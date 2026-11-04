<div align="center">

# st2at

**ChatGPT ST → AT，只做这一件事。**

把一个 `__Secure-next-auth.session-token` 换成新的 `accessToken`。
一条请求、一个接口、一个 CLI，没有数据库，没有账号体系，没有多余功能。

<sub>Python 3.10+ · FastAPI · curl_cffi · MIT</sub>

</div>

---

## 它是什么

`st2at` 是从 [team-manage-refresh](https://github.com/loLollipop/team-manage-refresh) 中抽出的最小独立实现，只保留它的 `refresh_access_token_with_session_token()` 能力：

```text
__Secure-next-auth.session-token  ──GET /api/auth/session──▶  accessToken
                                                              sessionToken（可能轮换）
                                                              idToken（可能返回）
```

它适合做：

- 命令行里快速把 ST 换成 AT
- 给脚本或其他服务提供一个只负责换 Token 的 HTTP 接口
- 作为一个可读、可测试的 ChatGPT Web 会话协议参考实现

它不包含：账号导入、Team 管理、RT 刷新、密码登录、数据库、定时任务、兑换码、代理池。

## 核心协议

真正关键的只有三段：

```http
GET https://chatgpt.com/api/auth/session HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Cookie: __Secure-next-auth.session-token=<ST>
Referer: https://chatgpt.com/
Connection: keep-alive
```

需要指定 workspace 时，URL 追加：

```text
?exchange_workspace_token=true&workspace_id=<WORKSPACE_ID>&reason=setCurrentAccount
```

成功响应的 JSON 顶层字段：

```json
{
  "accessToken": "eyJ...",
  "sessionToken": "eyJ...",
  "idToken": "eyJ..."
}
```

`sessionToken` 如果返回了，就是轮换后的新 ST，后续要替换旧值；没返回就继续用原 ST。`idToken` 可能不存在。

> 源项目通过 `curl_cffi` 的 `chrome110` 浏览器指纹发请求。直接用普通 `requests` 或 `httpx` 默认指纹，容易被 Cloudflare 挡在 `403`。这是整个方法里最容易漏掉的一层。

完整拆解见 [docs/protocol.md](docs/protocol.md)。

## 快速开始

### 1. 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. CLI：一条命令换 AT

推荐从 stdin 读，避免 token 留在 shell history：

```bash
printf '%s' "$ST" | st2at refresh --st-file -
```

也可以直接传：

```bash
st2at refresh --st 'eyJ...'
```

带 workspace：

```bash
printf '%s' "$ST" | st2at refresh --st-file - --workspace-id '3f1c2d8e-...'
```

输出 JSON：

```bash
printf '%s' "$ST" | st2at refresh --st-file - --json
```

结果示例：

```json
{
  "access_token": "eyJ...",
  "session_token": "eyJ...",
  "id_token": null,
  "token_type": "Bearer",
  "email": "user@example.com",
  "user_id": "user-...",
  "account_id": "workspace-...",
  "plan_type": "team",
  "expires_at": "2033-05-18T03:33:20+00:00"
}
```

`email`、`account_id`、`expires_at` 等字段来自对 AT 的 JWT payload 解码，仅用于展示。

### 3. HTTP 服务

```bash
uvicorn st2at.api:app --host 0.0.0.0 --port 8000
```

打开 <http://127.0.0.1:8000> 使用单页界面，API 文档在 <http://127.0.0.1:8000/docs>。

直接调接口：

```bash
curl -sS http://127.0.0.1:8000/v1/refresh \
  -H 'Content-Type: application/json' \
  -d '{
    "session_token": "eyJ...",
    "workspace_id": "3f1c2d8e-..."
  }'
```

响应：

```json
{
  "access_token": "eyJ...",
  "session_token": "eyJ...",
  "id_token": null,
  "token_type": "Bearer",
  "email": "user@example.com",
  "user_id": "user-...",
  "account_id": "workspace-...",
  "plan_type": "team",
  "expires_at": "2033-05-18T03:33:20+00:00"
}
```

`session_token` 为 `null` 表示上游没有轮换，继续使用原 ST。

### 4. Docker

```bash
docker build -t st2at .
docker run --rm -p 8000:8000 st2at
```

或：

```bash
docker compose up -d
```

## 作为库调用

```python
import asyncio
import os

from st2at import ST2ATClient


async def main() -> None:
    client = ST2ATClient(proxy=os.getenv("ST2AT_PROXY") or None)
    result = await client.refresh(os.environ["ST2AT_SESSION_TOKEN"])
    print(result.access_token)
    if result.session_token:
        print("rotated ST:", result.session_token)


asyncio.run(main())
```

完整示例见 [examples/refresh_once.py](examples/refresh_once.py)。

## API

### `POST /v1/refresh`

请求体：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `session_token` | string | 是 | 裸 ST、`Cookie:` 头或整段浏览器 Cookie |
| `workspace_id` | string \| null | 否 | 指定 workspace 时传入 |

成功：`200 OK`

```json
{
  "access_token": "eyJ...",
  "session_token": "eyJ...",
  "id_token": null,
  "token_type": "Bearer",
  "email": "user@example.com",
  "user_id": "user-...",
  "account_id": "workspace-...",
  "plan_type": "team",
  "expires_at": "2033-05-18T03:33:20+00:00"
}
```

错误：

```json
{
  "error": {
    "code": "session_rejected",
    "message": "ChatGPT rejected the session token (HTTP 403)"
  }
}
```

| HTTP | code | 含义 |
|---:|---|---|
| 400 | `invalid_session_token` | 输入为空、格式坏、Cookie 中没有 ST |
| 400 | `invalid_workspace` | `workspace_id` 含非法字符 |
| 401 | `session_rejected` | 上游返回 401/403，ST 被拒绝 |
| 429 | `upstream_rate_limited` | 上游返回 429 |
| 502 | `upstream_http_error` | 上游返回其他 4xx/5xx |
| 502 | `upstream_bad_response` | 200 但 JSON 坏或没有 `accessToken` |
| 502 | `upstream_transport_error` | DNS、连接、TLS、超时等传输失败 |

### `GET /healthz`

```json
{"status": "ok", "version": "0.1.0"}
```

## 配置

HTTP 服务的配置全部来自环境变量：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `ST2AT_HOST` | `0.0.0.0` | 监听地址 |
| `ST2AT_PORT` | `8000` | 监听端口 |
| `ST2AT_PROXY` | 空 | 显式代理，如 `http://user:pass@host:8080` 或 `socks5h://...` |
| `ST2AT_IMPERSONATE` | `chrome110` | curl_cffi 浏览器指纹 |
| `ST2AT_TIMEOUT` | `30` | 单次请求超时秒数 |
| `ST2AT_VERIFY_TLS` | `true` | 是否校验 TLS 证书 |

CLI 还支持 `--proxy`、`--impersonate`、`--timeout`、`--insecure`。

## 从源项目抽取了哪些代码

源项目：

- 仓库：`loLollipop/team-manage-refresh`
- 文件：`app/services/chatgpt.py`
- 方法：`ChatGPTService.refresh_access_token_with_session_token()`

抽取时保留的行为：

1. `GET https://chatgpt.com/api/auth/session`
2. `Cookie: __Secure-next-auth.session-token=<ST>`
3. 指定 `account_id` 时改用 `exchange_workspace_token=true&workspace_id=...&reason=setCurrentAccount`
4. 用 `curl_cffi` 的浏览器指纹发送，默认 `chrome110`
5. 解析 `accessToken`、`sessionToken`、`idToken`
6. 把返回的 `sessionToken` 视为轮换后的 ST

独立项目里删掉了：

- SQLAlchemy 模型与加密存储
- Team 账号、代理池、Free 号池
- RT 刷新和 OAuth 回调
- 定时预刷新
- 所有后台管理页面

差异：本项目默认开启 TLS 证书校验；源项目为兼容其代理链路使用了 `verify=False`。需要兼容抓包代理时，设 `ST2AT_VERIFY_TLS=false` 或 CLI 加 `--insecure`。

## 开发

```bash
PYTHONPATH=src pytest -q
```

测试全部离线，使用 fake session，不会访问真实 ChatGPT。

## License

MIT。抽取来源的版权声明见 [NOTICE](NOTICE)。
