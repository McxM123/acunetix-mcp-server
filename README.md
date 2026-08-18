# Awvs MCP Server

**Model Context Protocol (MCP) server that lets any LLM (Claude, WorkBuddy, Cursor, etc.) directly operate an Acunetix / Invicti Web Vulnerability Scanner.**

**当前版本：v1.1.4**

基于官方内置 API 文档（Swagger 2.0，111 路径 / 161 操作）与公开接口行为分析，将 Acunetix 的完整 API 协议（GraphQL + REST 双通道）封装为 15 个 LLM 可调用工具。官方已确认该产品提供完整 REST API，本 Server 是其 MCP 化封装。

---

## Features

- **双通道 API 桥**：GraphQL（`/graphql/`，主 UI 通道）+ REST（`/api/v1/`，业务数据通道）
- **两种官方认证**：
  - 官方 API Key（Profile 页生成，`X-Auth` 头，纯认证无会话）— **推荐**
  - 会话登录（`loginUser` mutation，密码 SHA-256 预哈希）
- **15 个 MCP 工具**：认证 / GraphQL 通用执行器 / REST 通用执行器 / 目标 / 扫描 / 漏洞 / 报告 / 配置 / 统计 / 用户
- **健壮错误处理**：429 限流自动退避、401 会话失效识别、GraphQL errors 解析、TLS 自签名证书兼容
- **安全设计**：凭据经环境变量注入（不硬编码）、token 仅存内存、写操作工具显式标注

## Design Philosophy（设计原则）

**工具是被调用的能力层，不是决策层。**

- 工具只负责：接受 LLM 参数 → 执行对应系统操作 → 完整结构化返回结果
- 工具**不拦截** LLM 调用、**不自动替 LLM 做决定**、**不隐藏额外行为**（如自动重登/自动续期）
- 判断、规划、决策全部归 LLM；工具通过"信息完备 + 调用便利"支持决策
- 错误返回是"信息"（说明发生了什么 + 可选方向），不是"指令"（不强制 LLM 怎么做）
- 长时间阻塞类操作返回状态快照，由 LLM 决定是否轮询
- 辅助查询（如查重）做成独立工具，供 LLM 按需调用，而非内嵌自动执行

---

## Quick Start

> 💡 **首次使用？** 请先阅读 [examples/NEW_USER_GUIDE.md](examples/NEW_USER_GUIDE.md)（5 步完整上手：获取 API Key → 填到哪 → 验证 → 使用 → 故障排查）。配置模板见 [examples/.env.example](examples/.env.example) 与 [examples/mcp-config-absolute.example.json](examples/mcp-config-absolute.example.json)。

### 1. 安装

```bash
# 方式 A：源码运行（当前唯一方式，推荐）
pip install -r requirements.txt

```

### 2. 配置凭据（账号密码 / API Key 填这里）

凭据通过**环境变量**或 MCP 客户端的 **`environment` 字段**传入，不写进代码。

**Linux / macOS（bash）:**
```bash
# 方式一（推荐）：官方 API Key —— Acunetix 界面 → 你的用户名 → Profile → API Key → Generate new API key
export ACUNETIX_API_KEY="<your-api-key>"
# 方式二：账号密码（会话登录，有单会话约束）
export ACUNETIX_EMAIL="<your-email>"
export ACUNETIX_PASSWORD="<your-password>"
# 可选
export ACUNETIX_BASE_URL="https://localhost:3443"
export ACUNETIX_VERIFY_SSL="false"
```

**Windows（PowerShell）:**
```powershell
$env:ACUNETIX_API_KEY="<your-api-key>"
$env:ACUNETIX_BASE_URL="https://localhost:3443"
$env:ACUNETIX_VERIFY_SSL="false"
```

**Windows（CMD）:**
```cmd
set ACUNETIX_API_KEY=<your-api-key>
set ACUNETIX_BASE_URL=https://localhost:3443
```

> 💡 **通用建议**：在 MCP 客户端（如 Claude Desktop / WorkBuddy）的配置文件 `environment` 字段中设置凭据，即可**跨平台免环境变量**，各操作系统行为一致。

### 3. 验证配置（自检）

```bash
python -m acunetix_mcp --selftest
```

预期输出：`认证: 官方 API Key` → `REST me: <邮箱>` → `targets: <N> 个目标` → `自检通过`。

### 4. 启动 MCP Server（两种方式）

```bash
# 方式 A：命令行直接启动（stdio 模式）
python -m acunetix_mcp

# 方式 B：MCP 客户端配置中声明（推荐，示例见 examples/mcp-config-absolute.example.json）
#   用 __main__.py 的绝对路径，无需依赖 PYTHONPATH，最稳妥
```

```json
{
  "mcpServers": {
    "acunetix-mcp": {
      "type": "local",
      "command": "python",
      "args": ["-m", "acunetix_mcp"],
      "environment": {
        "ACUNETIX_BASE_URL": "https://localhost:3443",
        "ACUNETIX_API_KEY": "<your-api-key>"
      }
    }
  }
}
```

> **没有预置凭据也能用**：若客户端未配置 environment，可直接在对话中调用 `acunetix_use_api_key("<key>")` 或 `acunetix_login(email="...", password="...")` 传入。

---

## Available Tools (18)

| Tool | Type | Description |
|---|---|---|
| `acunetix_login` | auth | 会话登录（方式二，回退） |
| `acunetix_use_api_key` | auth | 官方 API Key 认证（方式一，推荐） |
| `acunetix_logout` | auth | 清理本地会话 |
| `acunetix_me` | query | 当前用户信息（GraphQL） |
| `acunetix_gql` | **generic** | 任意 GraphQL query/mutation（覆盖任意功能） |
| `acunetix_rest` | **generic** | 任意 REST 端点调用（GET/POST/PUT/DELETE） |
| `acunetix_list_targets` | business | 目标列表 |
| `acunetix_get_target` | business | 单目标详情 |
| `acunetix_list_scans` | business | 扫描列表 |
| `acunetix_list_vulnerabilities` | business | 漏洞列表 |
| `acunetix_list_reports` | business | 报告列表 |
| `acunetix_list_scan_profiles` | business | 扫描配置 |
| `acunetix_stats` | business | 用户统计（最易受攻击目标） |
| `acunetix_add_target` | **write** | 新增目标（criticality: 30/20/10/0） |
| `acunetix_start_scan` | **write** | 启动扫描 |
| `acunetix_set_custom_cookies` | **write** | 写入自定义 Cookie 建立登录态（回读验证落盘） |
| `acunetix_verify_custom_cookies` | query | 核查自定义 Cookie 配置状态 |
| `acunetix_clear_custom_cookies` | **write** | 清空自定义 Cookie（不自动改 login.kind） |

> 通用执行器（`acunetix_gql` / `acunetix_rest`）可覆盖官方 YAML 中全部 111 路径 / 161 操作。

---

## Typical Workflow (LLM 自主操作)

```
1. acunetix_use_api_key("<key>") 或 acunetix_login()
2. acunetix_list_targets()            # 查看目标 → 取 target_id
3. acunetix_list_scan_profiles()      # 查看配置 → 取 profile_id
4. acunetix_start_scan(target_id, profile_id)
5. acunetix_list_scans()              # 轮询扫描状态
6. acunetix_list_vulnerabilities()    # 获取漏洞
7. acunetix_gql(GetReport)            # 生成报告
8. acunetix_logout()
```

---

## Logged-in Scan（登录态扫描，可选）

部分站点使用非标准登录（无表单 / 风控 / 加密提交），`automatic` 自动登录无法生效。
此时可先在浏览器完成登录，将登录 Cookie 注入目标，使扫描器以登录态爬取受限区域：

```
1. （浏览器自动化，可选）打开登录页 → 完成登录 → 提取完整 Cookie 串
2. acunetix_set_custom_cookies(target_id, cookie_str)   # 写入 + 回读验证
3. acunetix_verify_custom_cookies(target_id)            # 核查已配置
4. acunetix_start_scan(target_id, profile_id)           # 以登录态扫描
5. acunetix_list_vulnerabilities()                      # 获取漏洞
```

- **可选配套工具**：若需浏览器自动化完成登录与 Cookie 提取，可接入第三方 MCP
  `js-reverse-mcp`（npm 一行安装，见 [docs/AUTH_WORKFLOW.md](docs/AUTH_WORKFLOW.md)）：
  ```json
  { "mcpServers": { "js-reverse": { "command": "npx", "args": ["js-reverse-mcp"] } } }
  ```
- Cookie 会过期（有效期取决于目标站点），过期后需重新获取并再次写入。

---

## Documentation

- [docs/PROTOCOL.md](docs/PROTOCOL.md) — 协议说明（认证机制、双通道、限流、单会话约束）
- [docs/SECURITY.md](docs/SECURITY.md) — 安全性考量
- [docs/AUTH_WORKFLOW.md](docs/AUTH_WORKFLOW.md) — 登录态重建工作流（Custom Cookies 全流程）

---

## Security Notes

- **凭据安全**：API Key / 密码仅通过环境变量传入，代码不落盘、不硬编码。
- **最小权限**：建议为自动化创建独立低权限账号（本仓库默认凭据为演示用途）。
- **写操作**：`acunetix_add_target` / `acunetix_start_scan` 为写操作，生产环境建议在 MCP 层加人工确认。
- **TLS**：本机自签名证书默认 `verify_ssl=False`，生产环境必须开启证书校验。

---

## License

MIT

---

## Disclaimer

本工具仅用于**授权环境**下的安全测试与自动化集成。使用前请确保你拥有目标系统的合法授权。Acunetix / Invicti 为相应公司的商标。
