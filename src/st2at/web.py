"""Self-contained single-page interface. No CDN, no analytics, no storage."""

INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>st2at · ST 刷新 AT</title>
<style>
:root{
  --bg:#0b0d10;--panel:#12161b;--panel2:#171c23;--line:#252c36;
  --text:#e8edf4;--muted:#8d98a8;--lime:#b8f34a;--lime2:#8ddc16;
  --red:#ff6b6b;--blue:#74b9ff;
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;background:
  radial-gradient(900px 500px at 15% -10%,#1d2a15 0,transparent 55%),
  radial-gradient(700px 400px at 110% 20%,#13202c 0,transparent 60%),var(--bg);
  color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
.wrap{width:min(1040px,calc(100% - 32px));margin:0 auto;padding:44px 0 56px}
header{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:28px}
.brand{display:flex;align-items:center;gap:14px}
.logo{width:48px;height:48px;border:1px solid #40501e;border-radius:14px;background:#19220e;
  display:grid;place-items:center;color:var(--lime);font-weight:800;font-size:18px;box-shadow:0 0 40px #b8f34a12}
h1{font-size:24px;line-height:1.1;margin:0;letter-spacing:-.5px}
.sub{color:var(--muted);font-size:12px;margin-top:7px}
.pill{border:1px solid var(--line);background:#12171e;color:var(--muted);font-size:11px;
  padding:8px 11px;border-radius:999px;white-space:nowrap}
.grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:18px}
.card{border:1px solid var(--line);border-radius:18px;background:linear-gradient(180deg,#141920,#101419);
  box-shadow:0 20px 60px #0006;overflow:hidden}
.card-head{padding:18px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}
.card-head h2{font-size:13px;margin:0;letter-spacing:.4px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--lime);box-shadow:0 0 12px var(--lime)}
.card-body{padding:20px}
label{display:flex;align-items:center;justify-content:space-between;gap:12px;font-size:12px;color:#c8d1dd;margin:0 0 9px}
label span{color:var(--muted);font-size:11px;font-weight:400}
textarea,input{width:100%;border:1px solid #2b3440;background:#0b0f14;color:var(--text);
  border-radius:11px;padding:13px 14px;font:inherit;font-size:12px;line-height:1.6;outline:none;transition:.15s}
textarea{min-height:156px;resize:vertical}
textarea:focus,input:focus{border-color:#587a20;box-shadow:0 0 0 3px #b8f34a12}
.field{margin-bottom:17px}
.optional{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center}
button{border:0;border-radius:11px;font:inherit;font-weight:700;cursor:pointer;transition:.15s}
.primary{width:100%;padding:14px 18px;background:linear-gradient(180deg,var(--lime),#9ee62c);color:#131804;
  box-shadow:0 8px 30px #b8f34a20;font-size:13px}
.primary:hover{filter:brightness(1.06);transform:translateY(-1px)}
.primary:disabled{opacity:.55;cursor:wait;transform:none}
.ghost{padding:12px 14px;background:#1b222b;border:1px solid #303a48;color:#c9d3e0;font-size:12px}
.ghost:hover{background:#222b36}
.hint{font-size:11px;color:var(--muted);line-height:1.7;margin-top:12px}
.result{min-height:366px;display:flex;flex-direction:column}
.empty{flex:1;display:grid;place-items:center;text-align:center;color:#596474;padding:32px}
.empty b{display:block;color:#8793a4;font-size:13px;margin-bottom:8px}
.empty code{color:#6e7d91;font-size:11px}
.status{display:none;padding:12px 14px;border-radius:11px;margin-bottom:15px;font-size:12px;line-height:1.6;word-break:break-word}
.status.err{display:block;border:1px solid #6b2b32;background:#2b1418;color:#ffb3b3}
.status.ok{display:block;border:1px solid #38521d;background:#18230f;color:#c9f784}
.out{display:none}
.out.show{display:block}
.out-row{margin-bottom:13px}
.out-label{font-size:10px;color:var(--muted);letter-spacing:.8px;text-transform:uppercase;margin-bottom:7px;display:flex;justify-content:space-between}
.token-box{position:relative;border:1px solid #2a3440;background:#090d12;border-radius:10px;padding:11px 42px 11px 12px;
  font-size:10px;line-height:1.55;word-break:break-all;max-height:112px;overflow:auto;color:#cfe2ff}
.copy{position:absolute;right:7px;top:7px;padding:5px 7px;border:1px solid #354150;background:#151b23;color:#a8b5c6;border-radius:6px;font-size:10px}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px}
.meta div{border:1px solid var(--line);background:#0e1319;padding:10px 12px;border-radius:10px}
.meta small{display:block;color:var(--muted);font-size:9px;margin-bottom:5px;letter-spacing:.6px}
.meta strong{font-size:11px;font-weight:500;color:#d8e0ea;word-break:break-all}
footer{display:flex;justify-content:space-between;gap:20px;color:#596474;font-size:10px;margin-top:20px;line-height:1.7}
footer a{color:#7f8da1;text-decoration:none}
@media(max-width:820px){.grid{grid-template-columns:1fr}.wrap{padding-top:28px}header{flex-direction:column}.pill{align-self:flex-start}.result{min-height:280px}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="logo">S→A</div>
      <div>
        <h1>ST 刷新 AT</h1>
        <div class="sub">ChatGPT session token → access token · 只做这一件事</div>
      </div>
    </div>
    <div class="pill">no database · no storage · one request</div>
  </header>

  <div class="grid">
    <section class="card">
      <div class="card-head"><h2>01 / 输入 Session Token</h2><span class="dot"></span></div>
      <div class="card-body">
        <form id="refreshForm">
          <div class="field">
            <label for="st">SESSION TOKEN <span>支持裸 ST 或整段 Cookie</span></label>
            <textarea id="st" name="st" spellcheck="false" autocomplete="off"
              placeholder="__Secure-next-auth.session-token=eyJ...&#10;&#10;或直接粘贴 eyJ..."></textarea>
          </div>
          <div class="field">
            <label for="ws">WORKSPACE ID <span>可选 · 不填则使用账号默认空间</span></label>
            <input id="ws" name="ws" spellcheck="false" autocomplete="off" placeholder="e.g. 3f1c2d8e-....">
          </div>
          <button class="primary" id="submitBtn" type="submit">刷新 AT →</button>
          <div class="hint">请求直接发往 chatgpt.com；本服务不保存、不记录任何凭证，结果只在当前页面展示。</div>
        </form>
      </div>
    </section>

    <section class="card">
      <div class="card-head"><h2>02 / 结果</h2><span class="dot" style="background:#3d4a5c;box-shadow:none"></span></div>
      <div class="card-body result">
        <div class="empty" id="empty">
          <div><b>等待输入</b><code>POST /v1/refresh</code></div>
        </div>
        <div class="status" id="status"></div>
        <div class="out" id="out">
          <div class="out-row">
            <div class="out-label"><span>ACCESS TOKEN</span><span id="atLen"></span></div>
            <div class="token-box" id="at"><button class="copy" data-copy="at">COPY</button><span id="atText"></span></div>
          </div>
          <div class="out-row">
            <div class="out-label"><span>SESSION TOKEN (ROTATED)</span><span id="stState"></span></div>
            <div class="token-box" id="stOut"><button class="copy" data-copy="stOut">COPY</button><span id="stText"></span></div>
          </div>
          <div class="meta">
            <div><small>EMAIL</small><strong id="email">—</strong></div>
            <div><small>PLAN</small><strong id="plan">—</strong></div>
            <div><small>WORKSPACE</small><strong id="account">—</strong></div>
            <div><small>EXPIRES</small><strong id="expires">—</strong></div>
          </div>
        </div>
      </div>
    </section>
  </div>

  <footer>
    <div>ST2AT / v0.1.0<br>MIT License</div>
    <div>API: <a href="/docs">/docs</a> · <a href="/healthz">/healthz</a></div>
  </footer>
</div>

<script>
const $ = (id) => document.getElementById(id);
const form = $("refreshForm");
const btn = $("submitBtn");

function showError(message) {
  $("empty").style.display = "none";
  $("out").classList.remove("show");
  const box = $("status");
  box.className = "status err";
  box.textContent = message;
}

function text(id, value) {
  $(id).textContent = value || "—";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const session_token = $("st").value.trim();
  const workspace_id = $("ws").value.trim();
  if (!session_token) {
    showError("请先填入 Session Token。");
    return;
  }
  btn.disabled = true;
  btn.textContent = "请求中…";
  $("status").className = "status";
  try {
    const response = await fetch("/v1/refresh", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({session_token, workspace_id: workspace_id || null})
    });
    let data = {};
    try { data = await response.json(); } catch (_) {}
    if (!response.ok) {
      const detail = data && data.error ? data.error.message : "HTTP " + response.status;
      throw new Error(detail);
    }
    $("empty").style.display = "none";
    $("status").className = "status ok";
    $("status").textContent = "刷新成功 · HTTP " + response.status;
    $("out").classList.add("show");
    text("atText", data.access_token);
    $("atLen").textContent = (data.access_token || "").length + " CHARS";
    if (data.session_token) {
      text("stText", data.session_token);
      $("stState").textContent = "NEW · 请替换旧 ST";
    } else {
      text("stText", "未轮换，继续使用原 ST");
      $("stState").textContent = "UNCHANGED";
    }
    text("email", data.email);
    text("plan", data.plan_type);
    text("account", data.account_id);
    text("expires", data.expires_at ? new Date(data.expires_at).toLocaleString() : null);
  } catch (error) {
    showError(error.message || "请求失败");
  } finally {
    btn.disabled = false;
    btn.textContent = "刷新 AT →";
  }
});

document.querySelectorAll(".copy").forEach((button) => {
  button.addEventListener("click", async () => {
    const source = button.dataset.copy === "at" ? $("atText") : $("stText");
    const value = source.textContent.trim();
    if (!value || value === "未轮换，继续使用原 ST") return;
    try {
      await navigator.clipboard.writeText(value);
      const old = button.textContent;
      button.textContent = "OK";
      setTimeout(() => { button.textContent = old; }, 1000);
    } catch (_) {}
  });
});
</script>
</body>
</html>
"""
