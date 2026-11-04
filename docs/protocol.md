# ST → AT 协议拆解

本文记录从 `team-manage-refresh` 的 `app/services/chatgpt.py` 中抽出的 ST 换 AT 方法。目标是把行为写清楚，方便独立实现、测试和排障。

## 1. 前置条件

手里要有一个 ChatGPT Web 的会话 Cookie：

```text
__Secure-next-auth.session-token=<ST>
```

ST 通常是一个长 JWT。浏览器里可能以整段 Cookie 出现：

```text
__Host-next-auth.csrf-token=...; __Secure-next-auth.session-token=...; ...
```

本项目的 `normalize_session_token()` 接受三种输入：

1. 裸 ST
2. `Cookie: ...` 头
3. 整段浏览器 Cookie

它也支持 NextAuth 把超长 Cookie 分片成 `...session-token.0`、`...session-token.1` 的形式，按序号拼接。

## 2. 请求

### 2.1 默认空间

```http
GET /api/auth/session HTTP/1.1
Host: chatgpt.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Cookie: __Secure-next-auth.session-token=<ST>
Referer: https://chatgpt.com/
Connection: keep-alive
```

完整 URL：

```text
https://chatgpt.com/api/auth/session
```

### 2.2 指定 workspace

```text
https://chatgpt.com/api/auth/session?exchange_workspace_token=true&workspace_id=<WORKSPACE_ID>&reason=setCurrentAccount
```

`workspace_id` 用 URL 编码后放入查询串。源项目把它叫 `account_id`，有些导出文件里它也叫 `chatgpt_account_id`。

### 2.3 浏览器指纹

这是请求成功率的重点。源项目用 `curl_cffi.requests.AsyncSession`，它当时写的是 `chrome110`：

```python
AsyncSession(
    impersonate="chrome110",
    timeout=30,
    verify=False,       # 源项目为兼容其代理链路
    trust_env=False,
)
```

本项目要求 Chrome 146–150 区间，默认改为 `chrome150`，需要固定 146 时用 `chrome146`。`curl_cffi 0.16.3` 的精确 profile 只有 `chrome146` 与 `chrome150`，没有 `chrome147`、`chrome148`、`chrome149`。

如果改用普通 `requests`/`httpx` 默认 TLS 指纹，Cloudflare 可能直接返回 `403`，即使 Cookie 本身有效。

### 2.4 动态代理出口

BestGo / 711 裸格式：

```text
proxy.example.com:10000:demo-user-region-JP-session-demo123-sessTime-5:example-pass
```

本项目的处理顺序：

1. 解析 `host:port:user:pass`
2. 读取用户名里的 `-region-JP`、`-session-abc123`、`-sessTime-5`
3. 每次 `refresh()` 生成新的随机 session，替换旧 session
4. 保留 region 和 sessTime，拼回 `socks5h://user:pass@host:port`
5. 将该 URI 交给 `curl_cffi`

同一个 session 固定落到同一个出口 IP；换 session 就换出口。每次刷新换一次 session，保证不同请求不撞 IP。


## 3. 响应

成功时 HTTP 200，Content-Type 为 JSON：

```json
{
  "accessToken": "eyJ...",
  "sessionToken": "eyJ...",
  "idToken": "eyJ..."
}
```

字段说明：

| 字段 | 必填 | 用途 |
|---|---|---|
| `accessToken` | 是 | 新 AT，后续请求放在 `Authorization: Bearer <AT>` |
| `sessionToken` | 否 | 轮换后的 ST。返回时必须覆盖旧 ST |
| `idToken` | 否 | 部分场景需要；返回时一并保存 |

有时响应里只有 `accessToken`。这不代表失败，表示 ST 没有轮换。

### 响应示例

```json
{
  "accessToken": "<ACCESS_TOKEN>",
  "sessionToken": "<SESSION_TOKEN>",
  "idToken": "<ID_TOKEN>"
}
```

## 4. 失败状态

| 上游状态 | 含义 | 本项目错误 |
|---:|---|---|
| 401/403 | ST 无效、过期、被风控拒绝 | `session_rejected` |
| 429 | 速率限制 | `upstream_rate_limited` |
| 其他 4xx | 请求被拒绝 | `upstream_http_error` |
| 5xx | ChatGPT 侧异常 | `upstream_http_error` |
| 200 但没有 `accessToken` | 响应格式变化或登录态不完整 | `upstream_bad_response` |
| 连接/DNS/TLS/超时 | 传输失败 | `upstream_transport_error` |

不要把上游返回的整段 HTML 原样回给调用方。本项目只提取 JSON 中的 `detail` / `error`，并截断到 300 字符。

## 5. 最小实现

```python
from curl_cffi.requests import AsyncSession


async def st_to_at(st: str, workspace_id: str | None = None) -> dict:
    url = "https://chatgpt.com/api/auth/session"
    if workspace_id:
        url += (
            "?exchange_workspace_token=true"
            f"&workspace_id={workspace_id}"
            "&reason=setCurrentAccount"
        )

    headers = {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Cookie": f"__Secure-next-auth.session-token={st}",
        "Referer": "https://chatgpt.com/",
        "Connection": "keep-alive",
    }

    async with AsyncSession(
        impersonate="chrome150",
        timeout=30,
        verify=True,
        trust_env=False,
    ) as session:
        response = await session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

    if not data.get("accessToken"):
        raise RuntimeError("response has no accessToken")

    return {
        "access_token": data["accessToken"],
        "session_token": data.get("sessionToken"),
        "id_token": data.get("idToken"),
    }
```

注意：`AsyncSession` 的上下文管理语法随 curl_cffi 版本可能不同；本项目核心代码显式调用 `close()`，避免版本差异。

## 6. 验证清单

- [x] 请求路径是 `/api/auth/session`，不是 OAuth 的 `/oauth/token`
- [x] Cookie 名是 `__Secure-next-auth.session-token`
- [x] 带 `Referer: https://chatgpt.com/`
- [x] 指定 workspace 时三个查询参数齐全且顺序固定
- [x] 使用 `curl_cffi` 浏览器指纹
- [x] 200 后先检查 `accessToken`
- [x] `sessionToken` 存在时更新本地 ST
- [x] 401/403 与 5xx 分开处理
- [x] 不把 ST/AT 写日志、不落盘
