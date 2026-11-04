"""万级账号多线程：绑机拿 RT + 每账号一个 sub2api JSON。

## 为什么「瞎开多线程」很差

1. **OpenAI 按 IP/设备限流** — 100 线程同打 → rate_limit / 503 / account 雪崩  
2. **代理 sticky 不够** — worker 数 > 可用 sid 时抢同一出口  
3. **Getatext 全局限流** — 文档 2 rps 租号；过多并发只会 400/429  
4. **整批等齐** — 1 个慢号拖死整批；应「完成一个立刻写文件、立刻补号」  
5. **OTP 会话绑定** — 必须同线程同 session 跑完，不能拆成乱序队列步骤  

## 推荐架构（本模块）

```
账号队列 ──► 固定 N 个 worker（默认 10）
               │  独占 1 条 US 代理
               │  MS 邮箱 OTP（直连/独立出口）
               │  Getatext 接码（直连 + 全局限流）
               │  成功 → 立刻写 out_dir/<email>.json
               └  失败 → results.jsonl + 可选重试队列
```

建议：**workers=12~20**，代理池 ≥ 2×workers，单号 timeout=150~200s。  
控制台默认 quiet（只打 OK/FAIL/进度）；全量步骤写 ``out_dir/run.log``。

用法见 ``python -m tokenrefresh.batch_bind --help``。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import traceback
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# package root on path when run as script
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tokenrefresh.api import bind_phone  # noqa: E402
from tokenrefresh.email_ import (  # noqa: E402
    _ms_refresh_access_token,
    register_ms_oauth_credentials,
)
from tokenrefresh.export_format import (  # noqa: E402
    account_row_for_export,
    export_sub2api,
)
from tokenrefresh.utils import log_line, set_log_file  # noqa: E402

# ── Getatext 全局限流（跨 worker 共享）────────────────────────
# 注意：租号 pacing 只应在真正 rent 时做（getatext 内部已 throttle），
# 不要在 process_one 开头卡住整号（会拖慢 MS/Web 登录并行度）。
_GETATEXT_RENT_LOCK = threading.Lock()
_GETATEXT_LAST_RENT = 0.0
_GETATEXT_RENT_MIN_INTERVAL = float(os.environ.get("BATCH_GETATEXT_RENT_INTERVAL", "0.50"))


def pace_getatext_rent() -> None:
    """Getatext 文档约 2 rps；所有 worker 共享间隔（仅租号前调用）。"""
    global _GETATEXT_LAST_RENT
    with _GETATEXT_RENT_LOCK:
        now = time.time()
        wait = _GETATEXT_RENT_MIN_INTERVAL - (now - _GETATEXT_LAST_RENT)
        if wait > 0:
            time.sleep(wait)
        _GETATEXT_LAST_RENT = time.time()


def _apply_batch_speed_env() -> None:
    """批量默认加速：关 humanize 预热、quiet 日志、接码 15s 丢号、邮箱 OTP 20s。"""
    os.environ.setdefault("TOKENREFRESH_QUIET", "1")
    os.environ.setdefault("TOKENREFRESH_LOG", "quiet")
    os.environ.setdefault("HUMANIZE_ENABLE", "0")
    os.environ.setdefault("HUMANIZE_WARM_REQUESTS", "0")
    os.environ.setdefault("BIND_PURE_FALLBACK", "0")
    os.environ.setdefault("MAIL_OTP_USE_DIRECT", "1")
    # 接码：默认 15 秒无短信验证码 → cancel + FAIL 丢号（别空等 2 分钟）
    os.environ.setdefault("GETATEXT_SMS_TIMEOUT", "15")
    os.environ.setdefault("GETATEXT_SMS_POLL_INTERVAL", "1.2")
    # 邮箱 OTP：批量别等 45s
    os.environ.setdefault("TOKENREFRESH_EMAIL_POLL_SECONDS", "20")


@dataclass
class AccountLine:
    email: str
    password: str = ""
    client_id: str = ""
    ms_rt: str = ""
    raw: str = ""

    @classmethod
    def parse(cls, line: str) -> "AccountLine | None":
        s = (line or "").strip()
        if not s or s.startswith("#"):
            return None
        # 支持:
        #   email----pass----client_id----ms_rt
        #   email--------pass----client_id----ms_rt  (中间空段，货源常见)
        # 按 ---- 切开后去掉空段再取字段
        chunks = [p.strip() for p in s.split("----") if p.strip()]
        if not chunks:
            return None
        email = chunks[0].lower()
        if "@" not in email:
            return None
        password = chunks[1] if len(chunks) > 1 else ""
        client_id = chunks[2] if len(chunks) > 2 else ""
        ms_rt = chunks[3] if len(chunks) > 3 else ""
        # ms_rt 偶尔被拆碎时：取最后一个以 M. 开头的长串
        if len(chunks) > 4:
            for c in reversed(chunks):
                if c.startswith("M.") or c.startswith("rt."):
                    ms_rt = c
                    break
        return cls(email=email, password=password, client_id=client_id, ms_rt=ms_rt, raw=s)


@dataclass
class BatchStats:
    total: int = 0
    ok: int = 0
    fail: int = 0
    skip: int = 0
    started: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_ok(self) -> None:
        with self.lock:
            self.ok += 1

    def add_fail(self) -> None:
        with self.lock:
            self.fail += 1

    def add_skip(self) -> None:
        with self.lock:
            self.skip += 1

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            elapsed = max(0.1, time.time() - self.started)
            done = self.ok + self.fail + self.skip
            return {
                "total": self.total,
                "ok": self.ok,
                "fail": self.fail,
                "skip": self.skip,
                "done": done,
                "pending": max(0, self.total - done),
                "elapsed_s": round(elapsed, 1),
                "ok_per_h": round(self.ok / elapsed * 3600, 1),
            }


def _safe_filename(email: str) -> str:
    return re.sub(r"[^\w.\-@]+", "_", email.replace("@", "_at_"))


def load_accounts(path: str | Path) -> list[AccountLine]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    out: list[AccountLine] = []
    seen: set[str] = set()
    for ln in text.splitlines():
        acc = AccountLine.parse(ln)
        if not acc or acc.email in seen:
            continue
        seen.add(acc.email)
        out.append(acc)
    return out


def load_done_emails(out_dir: Path) -> set[str]:
    """已成功导出的邮箱（resume）。"""
    done: set[str] = set()
    if not out_dir.is_dir():
        return done
    for p in out_dir.glob("*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        # sub2api envelope or plain tokens
        if isinstance(data, dict):
            if "accounts" in data and data["accounts"]:
                em = str(
                    (data["accounts"][0].get("credentials") or {}).get("email")
                    or data["accounts"][0].get("name")
                    or ""
                ).lower()
                if em:
                    done.add(em)
            em2 = str(data.get("email") or "").lower()
            if em2 and "@" in em2:
                done.add(em2)
        # filename heuristic
        name = p.stem.lower()
        if "_at_" in name:
            done.add(name.replace("_at_", "@").replace("_", "."))  # weak; prefer json body
    # also results ok lines
    res = out_dir / "results.jsonl"
    if res.is_file():
        for ln in res.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(ln)
            except Exception:
                continue
            if row.get("ok") and row.get("email"):
                done.add(str(row["email"]).lower())
    return done


def pick_proxy(pool: Any, email: str, sticky: bool = True) -> str:
    """Acquire one proxy (prefer free slot). sticky=False → random free exit."""
    if pool is None:
        return ""
    if hasattr(pool, "acquire"):
        for _ in range(40):
            try:
                # cliproxy.ProxyPool: acquire(exclude=None, *, random_pick=True)
                url = pool.acquire(random_pick=True)
            except Exception:
                url = ""
            if url:
                return str(url)
            time.sleep(0.15)
        return ""
    urls = list(getattr(pool, "_proxies", None) or [])
    if not urls:
        return ""
    if sticky:
        h = int(hashlib.sha256(email.encode()).hexdigest()[:8], 16)
        return urls[h % len(urls)]
    import random
    return random.choice(urls)


def release_proxy(pool: Any, proxy: str) -> None:
    if pool is not None and proxy and hasattr(pool, "release"):
        try:
            pool.release(proxy)
        except Exception:
            pass


def process_one(
    acc: AccountLine,
    *,
    proxy: str,
    out_dir: Path,
    timeout_s: float,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """单账号：MS 凭证 → bind_phone → 每号一文件。超时在外层 future 控制。"""
    t0 = time.time()
    email = acc.email
    row: dict[str, Any] = {
        "email": email,
        "ok": False,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    _log = log or (lambda _m: None)
    try:
        if acc.ms_rt:
            register_ms_oauth_credentials(email, acc.ms_rt, acc.client_id)
            if not _ms_refresh_access_token(email):
                row["error"] = "ms_rt_refresh_failed"
                return row
            mail_url = "msoauth://"
        else:
            mail_url = os.environ.get("BATCH_DEFAULT_MAIL_URL", "")

        # 不在此 pace Getatext：租号限流在 getatext.rent 内部；
        # 提前 pace 会串行化本可并行的 Web 登录。

        result = bind_phone(
            email,
            acc.password,
            mail_url=mail_url,
            proxy=proxy,
        )
        # 成功门槛：本 run 真绑机 + 有 RT（导出仍不写手机号/平台）
        phone_bound = bool(result.get("phone_bound"))
        row["phone_bound"] = phone_bound
        row["path_used"] = result.get("path") or ""
        if not result.get("ok") or not phone_bound or not result.get("refresh_token"):
            row["error"] = (
                result.get("error")
                or ("no_phone_bound" if not phone_bound else "bind_no_rt")
            )
            row["ok_flag"] = bool(result.get("ok"))
            # 未绑机拿到的 token 故意不落盘，避免“假成功”
            return row

        # 导出：仅白名单，一账号一文件
        out_path = out_dir / f"{_safe_filename(email)}.json"
        export_sub2api(
            [account_row_for_export({
                "email": email,
                "access_token": result["access_token"],
                "refresh_token": result["refresh_token"],
                "password": acc.password,
            })],
            str(out_path),
            at_only=False,
        )
        row["ok"] = True
        row["path"] = str(out_path)
        row["at_len"] = len(result.get("access_token") or "")
        row["rt_len"] = len(result.get("refresh_token") or "")
        # 故意不写 phone / provider
        return row
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"[:300]
        row["trace"] = traceback.format_exc()[-800:]
        return row
    finally:
        row["elapsed_s"] = round(time.time() - t0, 1)
        err = row.get("error") or ""
        if row.get("ok"):
            _log(f"OK  {email}  t={row.get('elapsed_s')}s  rt={row.get('rt_len')}")
        else:
            short = str(err).replace("\n", " ")[:120]
            _log(f"FAIL {email}  t={row.get('elapsed_s')}s  {short}")


def run_batch(
    accounts: list[AccountLine],
    *,
    out_dir: Path,
    workers: int = 15,
    proxy_file: str = "",
    proxy_region: str = "US",
    timeout_s: float = 180.0,
    resume: bool = True,
    start_interval: float = 0.0,
    max_accounts: int = 0,
    quiet: bool = True,
) -> BatchStats:
    _apply_batch_speed_env()
    if not quiet:
        os.environ["TOKENREFRESH_LOG"] = "verbose"
        os.environ["TOKENREFRESH_QUIET"] = "0"

    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"
    progress_path = out_dir / "progress.json"
    run_log = out_dir / "run.log"
    # 控制台 quiet，全量步骤仍进 run.log
    set_log_file(str(run_log))

    done = load_done_emails(out_dir) if resume else set()
    queue = [a for a in accounts if a.email not in done]
    if max_accounts > 0:
        queue = queue[:max_accounts]

    stats = BatchStats(total=len(queue) + (len(accounts) - len(queue) if resume else 0))
    stats.skip = len(accounts) - len(queue) if resume else 0
    stats.total = len(queue) + stats.skip

    # proxy pool
    pool = None
    try:
        from cliproxy import ProxyPool, load_proxy_urls

        urls: list[str] = []
        src = ""
        if proxy_file and Path(proxy_file).is_file():
            urls = load_proxy_urls(proxy_file)
            src = proxy_file
        else:
            k12 = _ROOT / "老版本k12" / "chatgpt-k12-tools" / "cli"
            candidates = [
                k12 / f"{proxy_region}.txt",
                k12 / f"{proxy_region.upper()}.txt",
                k12 / "US-30.txt",
                k12 / "us.txt",
                _ROOT / "cliproxy" / "regions" / f"{proxy_region.upper()}.txt",
            ]
            for p in candidates:
                if p.is_file():
                    urls = load_proxy_urls(p)
                    if urls:
                        src = str(p)
                        break
        if urls:
            pool = ProxyPool(urls, shuffle=True)
            log_line(f"proxy pool={len(urls)} src={src} workers={workers}", force=True)
        else:
            log_line("WARN: no proxy pool — OpenAI 直连极易限流", force=True)
    except Exception as exc:
        log_line(f"proxy pool load fail: {exc}", force=True)

    write_lock = threading.Lock()
    last_progress_log = [0.0]
    progress_every_s = float(os.environ.get("BATCH_PROGRESS_EVERY", "20") or 20)

    def append_result(row: dict) -> None:
        with write_lock:
            with results_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            progress_path.write_text(
                json.dumps(stats.snapshot(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

    def maybe_progress(force: bool = False) -> None:
        now = time.time()
        if not force and (now - last_progress_log[0]) < progress_every_s:
            return
        last_progress_log[0] = now
        snap = stats.snapshot()
        log_line(
            f"progress ok={snap['ok']} fail={snap['fail']} "
            f"done={snap['done']}/{snap['total']} "
            f"pending={snap['pending']} {snap['ok_per_h']}/h "
            f"elapsed={snap['elapsed_s']}s",
            force=True,
        )

    def worker_job(acc: AccountLine) -> dict:
        proxy = pick_proxy(pool, acc.email, sticky=True)
        try:
            return process_one(
                acc,
                proxy=proxy,
                out_dir=out_dir,
                timeout_s=timeout_s,
                log=lambda m: log_line(m, force=True),
            )
        finally:
            release_proxy(pool, proxy)

    log_line(
        f"batch start total_in={len(accounts)} queue={len(queue)} "
        f"skip={stats.skip} workers={workers} timeout={timeout_s}s "
        f"start_interval={start_interval}s out={out_dir}",
        force=True,
    )

    # 流式：完成一个立刻补下一个（不是整批 wait）
    inflight: dict[Future, AccountLine] = {}
    q_iter = iter(queue)
    # 硬顶 50；代理/接码不足时请自行降 workers
    workers = max(1, min(int(workers), 50))

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bind") as ex:
        def submit_next() -> bool:
            try:
                acc = next(q_iter)
            except StopIteration:
                return False
            # 仅在「补提交」时微间隔，初始灌满 workers 时尽量并行拉起
            if start_interval > 0 and inflight:
                time.sleep(start_interval)
            fut = ex.submit(worker_job, acc)
            inflight[fut] = acc
            return True

        # 初始并行灌满（不串行 sleep）
        for _ in range(workers):
            try:
                acc = next(q_iter)
            except StopIteration:
                break
            fut = ex.submit(worker_job, acc)
            inflight[fut] = acc

        while inflight:
            done_set, _ = wait(
                list(inflight.keys()), return_when=FIRST_COMPLETED, timeout=8.0,
            )
            if not done_set:
                maybe_progress(force=False)
                continue
            for fut in done_set:
                acc = inflight.pop(fut)
                try:
                    row = fut.result(timeout=1)
                except Exception as exc:
                    row = {
                        "email": acc.email,
                        "ok": False,
                        "error": f"future: {type(exc).__name__}: {exc}"[:300],
                        "ts": datetime.now(timezone.utc).isoformat(),
                    }
                    log_line(
                        f"FAIL {acc.email}  future:{type(exc).__name__}",
                        force=True,
                    )
                if row.get("ok"):
                    stats.add_ok()
                else:
                    stats.add_fail()
                append_result(row)
                submit_next()
            maybe_progress(force=False)

    final = stats.snapshot()
    log_line(
        f"batch done ok={final['ok']} fail={final['fail']} "
        f"done={final['done']}/{final['total']} "
        f"{final['ok_per_h']}/h elapsed={final['elapsed_s']}s",
        force=True,
    )
    progress_path.write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")
    set_log_file(None)
    return stats


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m tokenrefresh.batch_bind",
        description="多线程绑机导出：每账号一个 sub2api JSON（不含接码平台痕迹）",
    )
    p.add_argument("accounts", help="账号列表文件：email----pass----client_id----ms_rt 每行一条")
    p.add_argument("--out-dir", default="exports_batch", help="输出目录（每号一个 json）")
    p.add_argument(
        "--workers", type=int, default=15,
        help="并发 worker 数，建议 12~20（代理池够大可到 25；硬顶 50）",
    )
    p.add_argument("--timeout", type=float, default=180.0, help="单号目标耗时上限（秒，软）")
    p.add_argument("--proxy-file", default="", help="代理文件 host:port:user:pass")
    p.add_argument("--proxy-region", default="US", help="从 cliproxy/k12 cli 选区，默认 US")
    p.add_argument("--no-resume", action="store_true", help="不跳过已导出邮箱")
    p.add_argument(
        "--start-interval",
        type=float,
        default=0.05,
        help="补提交间隔秒（初始灌满 workers 不 sleep）；默认 0.05，限流时可 0.2~0.5",
    )
    p.add_argument("--limit", type=int, default=0, help="最多处理条数（调试用）")
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="控制台打全量步骤日志（默认 quiet，全量只写 out_dir/run.log）",
    )
    p.add_argument(
        "--retry-failed",
        action="store_true",
        help="只重试 out-dir/results.jsonl 里 ok=false 的邮箱（先失败后重试）",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=1,
        help="整批结束后对仍失败的账号再跑几轮（默认 1=不额外轮；设 2 表示最多再重试 1 轮）",
    )
    return p


def _failed_emails_from_results(out_dir: Path) -> set[str]:
    """results.jsonl 中最后状态为失败的邮箱。"""
    path = out_dir / "results.jsonl"
    last: dict[str, bool] = {}
    if not path.is_file():
        return set()
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(ln)
        except Exception:
            continue
        em = str(row.get("email") or "").strip().lower()
        if em:
            last[em] = bool(row.get("ok"))
    return {em for em, ok in last.items() if not ok}


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    _apply_batch_speed_env()
    if getattr(args, "verbose", False):
        os.environ["TOKENREFRESH_LOG"] = "verbose"
        os.environ["TOKENREFRESH_QUIET"] = "0"
    accounts = load_accounts(args.accounts)
    if not accounts:
        print("no accounts", file=sys.stderr)
        return 2
    if not os.environ.get("GETATEXT_API_KEY") and not os.environ.get("GETATEXT_API_KEYS"):
        log_line("WARN: GETATEXT_API_KEY not set — add_phone 会失败", force=True)

    out_dir = Path(args.out_dir)
    if args.retry_failed:
        failed = _failed_emails_from_results(out_dir)
        # 已有成功 json 的不算失败
        done = load_done_emails(out_dir)
        failed -= done
        accounts = [a for a in accounts if a.email in failed]
        log_line(f"retry-failed mode: {len(accounts)} accounts", force=True)
        if not accounts:
            print(json.dumps({"ok": 0, "fail": 0, "msg": "no failed to retry"}, indent=2))
            return 0

    rounds = max(1, int(args.retries or 1))
    last_snap: dict[str, Any] = {}
    for rnd in range(rounds):
        if rnd > 0:
            failed = _failed_emails_from_results(out_dir)
            done = load_done_emails(out_dir)
            failed -= done
            accounts = [a for a in load_accounts(args.accounts) if a.email in failed]
            if not accounts:
                log_line(f"retry round {rnd + 1}: nothing left", force=True)
                break
            log_line(f"retry round {rnd + 1}: {len(accounts)} accounts", force=True)
        stats = run_batch(
            accounts,
            out_dir=out_dir,
            workers=args.workers,
            proxy_file=args.proxy_file,
            proxy_region=args.proxy_region,
            timeout_s=args.timeout,
            # 重试轮/失败重试：不跳过「仅 results 失败」；成功 json 仍跳过
            resume=True if (args.retry_failed or rnd > 0) else (not args.no_resume),
            start_interval=args.start_interval,
            max_accounts=0 if (args.retry_failed or rnd > 0) else args.limit,
            quiet=not getattr(args, "verbose", False),
        )
        last_snap = stats.snapshot()
    print(json.dumps(last_snap, ensure_ascii=False, indent=2))
    return 0 if last_snap.get("fail", 1) == 0 or last_snap.get("ok", 0) > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
