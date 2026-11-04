"""Bridge: call Node JSDOM turnstile solver (dx+p → t).

Engine selection (TOKENREFRESH_T_ENGINE):
  auto  — try Node first if node + script available, else Python VM
  node  — require Node (raise if fail)
  python — force pure-Python VM (default legacy)

Node runtime lives in vendor/tokenrefresh/node_runtime/
  npm install   (jsdom)
  solve_turnstile.mjs
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

_RUNTIME_DIR = Path(__file__).resolve().parent / "node_runtime"
_SOLVE_JS = _RUNTIME_DIR / "solve_turnstile.mjs"

_node_bin: str | None = None
_node_checked = False


def node_runtime_dir() -> Path:
    return _RUNTIME_DIR


def find_node() -> str:
    global _node_bin, _node_checked
    if _node_checked:
        return _node_bin or ""
    _node_checked = True
    env = (os.environ.get("TOKENREFRESH_NODE_BIN") or "").strip()
    if env and Path(env).is_file():
        _node_bin = env
        return _node_bin
    which = shutil.which("node")
    _node_bin = which or ""
    return _node_bin


def node_solver_available() -> bool:
    if not _SOLVE_JS.is_file():
        return False
    return bool(find_node())


def t_engine() -> str:
    """auto | node | python"""
    raw = (
        os.environ.get("TOKENREFRESH_T_ENGINE")
        or os.environ.get("TOKENREFRESH_TURNSTILE_ENGINE")
        or "auto"
    ).strip().lower()
    if raw in ("node", "js", "jsdom", "nodejs"):
        return "node"
    if raw in ("python", "py", "vm"):
        return "python"
    return "auto"


def solve_turnstile_node(
    dx: str,
    p: str,
    *,
    profile: dict | None = None,
    timeout: float | None = None,
) -> str:
    """Run Node solver; raise RuntimeError on failure."""
    if not dx:
        return ""
    node = find_node()
    if not node:
        raise RuntimeError("node_not_found")
    if not _SOLVE_JS.is_file():
        raise RuntimeError(f"node_solver_missing: {_SOLVE_JS}")

    try:
        to = float(
            timeout
            if timeout is not None
            else (os.environ.get("TOKENREFRESH_NODE_T_TIMEOUT") or "25")
        )
    except Exception:
        to = 25.0

    payload: dict[str, Any] = {
        "dx": dx,
        "p": p,
        "profile": profile or {},
    }
    # Ensure plain JSON-serializable profile
    try:
        payload["profile"] = json.loads(json.dumps(payload["profile"], default=str))
    except Exception:
        payload["profile"] = {}

    env = os.environ.copy()
    env.setdefault("NODE_NO_WARNINGS", "1")
    # Prefer project-local node_modules
    nm = _RUNTIME_DIR / "node_modules"
    if nm.is_dir():
        env["NODE_PATH"] = str(nm) + os.pathsep + env.get("NODE_PATH", "")

    try:
        proc = subprocess.run(
            [node, str(_SOLVE_JS)],
            input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            capture_output=True,
            timeout=max(3.0, to),
            cwd=str(_RUNTIME_DIR),
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"node_turnstile_timeout:{to}s") from exc
    except OSError as exc:
        raise RuntimeError(f"node_turnstile_spawn_failed:{exc}") from exc

    out = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    if not out:
        raise RuntimeError(
            f"node_turnstile_empty_stdout rc={proc.returncode} stderr={err[:200]}"
        )
    try:
        # last JSON line (in case of noise)
        line = out.splitlines()[-1]
        data = json.loads(line)
    except Exception as exc:
        raise RuntimeError(
            f"node_turnstile_bad_json:{out[:180]} stderr={err[:120]}"
        ) from exc

    if not data.get("ok"):
        raise RuntimeError(
            f"node_turnstile_fail:{data.get('error') or err or 'unknown'}"
        )
    t = str(data.get("t") or "").strip()
    if not t:
        raise RuntimeError("node_turnstile_empty_t")
    if t in ("undefined", "dW5kZWZpbmVk"):
        raise RuntimeError("node_turnstile_undefined")
    return t


def solve_turnstile_prefer_node(
    dx: str,
    p: str,
    *,
    profile: dict | None = None,
    python_fallback=None,
) -> str:
    """Engine router used by turnstile.solve_turnstile / utils.

    python_fallback: callable(dx, p, profile=) -> str
    """
    eng = t_engine()
    if eng == "python":
        if python_fallback is None:
            raise RuntimeError("python_fallback_required")
        return python_fallback(dx, p, profile=profile)

    if eng == "node" or (eng == "auto" and node_solver_available()):
        try:
            t = solve_turnstile_node(dx, p, profile=profile)
            return t
        except Exception as exc:
            if eng == "node":
                raise
            # auto: fall through to python
            try:
                sys.stderr.write(f"[turnstile] node failed, python fallback: {exc}\n")
            except Exception:
                pass

    if python_fallback is None:
        raise RuntimeError("no_turnstile_solver")
    return python_fallback(dx, p, profile=profile)
