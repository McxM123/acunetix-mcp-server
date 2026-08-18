# Acunetix MCP — 安全性考量

## 凭据管理

- **不硬编码**：API Key / 密码通过环境变量 `ACUNETIX_API_KEY` / `ACUNETIX_EMAIL` / `ACUNETIX_PASSWORD` 注入
- **不落盘**：会话 token 仅存内存，不写日志、不写文件
- 日志只输出 token / key 前 8-16 位预览

## 传输安全

- 本机 On-Premises 默认自签名证书：`ACUNETIX_VERIFY_SSL=false`（仅限本地环境）
- 生产环境必须 `true` 并配置受信证书链

## 最小权限

- 当前仓库演示账号为 Administrator（su:true）
- **生产建议**：为自动化创建独立低权限账号（仅扫描/查看权限）
- 写操作工具（`acunetix_add_target` / `acunetix_start_scan`）建议在 MCP 客户端层加人工确认钩子

## 审计

- 所有工具调用记录 `operation_name` 日志
- 系统侧操作绑定 token 所属用户身份

## 已知系统安全特性（自动化需适配）

| 特性 | 影响 |
|---|---|
| GraphQL introspection 禁用 | 需维护已知操作清单 |
| 登录限流 429 | 客户端必须退避 |
| 单会话约束 | 会话登录会互踢；**用 API Key 可避免该影响** |
| TOTP 2FA | 需传 otpToken 或先绑定 |
| SSO 配置 | 检测 userSsoEnabled |

## 负责任使用

本工具仅用于**授权环境**下的安全测试与自动化集成。使用者须自行确保拥有目标系统的合法授权，并遵守所在地法律法规。
