# Acunetix MCP — 协议说明

> 本文件记录 Acunetix API 协议细节（依据官方 Swagger 文档与公开接口行为分析），是 Server 实现的事实依据。

## 1. 认证机制（双通道）

### 方式一：官方 API Key（推荐）
- 生成位置：Acunetix UI → Profile 页 → API Key 段 → **Generate new API key**
- 认证方式：所有请求带 `X-Auth: <API_KEY>` 头（REST 与 GraphQL 通用）
- 官方依据：内置 Swagger 文档 `securityDefinitions.scanner_authorization`（apiKey, in: header）
- 优点：**无单会话约束、无 401 失效**，纯请求头认证

### 方式二：会话登录（回退）
- 登录端点：`POST /graphql/` + `mutation loginUser($data: UserLoginInput)`
- **密码必须先做 SHA-256 哈希**（服务端要求，客户端提交前预哈希）
- 响应：`{ status: SUCCESS, token: <128位hex> }`
- 会话传递：
  - GraphQL：`X-Auth: <token>` 头
  - REST：`ui_session` cookie + `x-auth: <token>` 头（**必须同一次登录的同一 token**）
- 实现说明（v1.1.3）：因 Python `http.cookiejar` 对无点主机名（`localhost`）的域匹配限制（该场景下 `domain="localhost"` 的 cookie 不会随请求发送，会导致 REST 通道 401），客户端在请求中**显式注入 `Cookie: ui_session=<token>` 头**以确保 cookie 正常发送（已端到端验证修复）
- 注意：**单会话约束**——并发登录会踢掉旧会话（401）

## 2. API 端点面

| 通道 | 端点 | 说明 |
|---|---|---|
| GraphQL | `/graphql/` | 主 UI 数据通道（introspection 已禁用） |
| GraphQL | `/apihub/graphql/` | API Hub（API 安全扫描） |
| REST | `/api/v1/*` | 业务数据（111 路径 / 161 操作，官方 Swagger） |

### REST 核心端点
```
GET  /api/v1/targets          # 目标列表
POST /api/v1/targets          # 新增目标 {address, description, criticality}
GET  /api/v1/scans            # 扫描列表
POST /api/v1/scans            # 启动扫描（响应头 Location 含 scan_id）
GET  /api/v1/vulnerabilities  # 漏洞列表
GET  /api/v1/reports          # 报告列表
GET  /api/v1/reports/download/{descriptor}  # 报告下载（PDF）
GET  /api/v1/scanning_profiles # 扫描配置
GET  /api/v1/me/stats         # 统计
```

## 3. 参数约束（实测）

- `criticality` 枚举：**Critical[30] / High[20] / Normal[10] / Low[0]**（YAML:4020）
- Full Scan profile_id 固定：`11111111-1111-1111-1111-111111111111`
- 批量删除 `/targets/delete`：body 传 `{"target_ids": [...]}`；空 body = 空操作

## 4. 错误处理（实测）

| 场景 | 响应 | 处理 |
|---|---|---|
| 限流 | HTTP 429 + `retry_after.delay_seconds` | 指数退避重试（最多 5 次） |
| 会话失效 | ① HTTP 401（任意通道）；② HTTP 200 + `errors[].message` 含 `401 Unauthorized`（GraphQL，被顶会话） | 两种形态均清理会话 token，提示重新登录 |
| 认证失败 | 400 "Invalid Authorization header" | 检查头格式（X-Auth vs x-auth） |
| GraphQL 错误 | 响应 `errors[]`（HTTP 200 或 4xx） | 逐条解析 message |
| 目标不存在 | 404 "Target not found" | 先 list 确认 ID |
| 参数非法 | 400 "Validation errors" + details | 按 details 修正 |

## 5. 接口与安全特性

- GraphQL introspection 禁用 → 必须使用已知操作（依据官方文档与运行行为）
- 登录限流 → 客户端必须退避
- 单会话约束 → 自动化与人工不可并发同一账号
- TOTP 2FA：`totp_required` 字段可探测；需传 `otpToken`
- SSO：`userSsoEnabled` 查询可检测

## 6. 已知上游偏差

- 未知 JSON-RPC 方法返回错误码 `-32602`（Invalid params），而非规范 `-32601`（Method not found）——此行为来自 mcp SDK 1.29.0 的分发层，非本项目代码。标准 MCP 客户端不依赖该错误码做分支，故不做 patch；每次升级 `mcp` 依赖后复验，上游修复后应返回 `-32601`。

## 7. Custom Cookies 登录态协议（v1.2.0）

针对 automatic 无法生效的站点（无标准表单 / 风控 / 加密提交），用浏览器登录后注入 Cookie 建立登录态。

**配置结构**（`PATCH /targets/{id}/configuration`）：

```json
{
  "login": {"kind": "none"},
  "custom_cookies": [
    {"cookie": "<完整 Cookie 串，≤4096 字符>", "url": "https://<站点域名>/"}
  ]
}
```

- `login.kind` 必须为 `none`（关闭 automatic，避免扫描器再次尝试自动登录）
- `custom_cookies` 数组最多 10 条；每条 `{cookie, url}`（url 为该 Cookie 的作用域）
- **必须回读验证**：PATCH 后 GET 同端点比对——历史上出现过"带 configuration 包装返回 200 但不落盘"的静默失效，故写入后一律 GET 确认（`acunetix_set_custom_cookies` 已内置该步骤）

**查询**：`GET /targets/{id}/configuration` 的 `custom_cookies` 字段

**注意**：
- Cookie 有效期由目标站点决定（如会话类 Cookie 常为 1 天~30 天），过期后需重新获取并再次写入
- Cookie 含登录凭证，工具返回仅给摘要（长度/域名），不回显完整值
