# 首次使用指南（New User Guide）

本指南面向**从未配置过** Acunetix MCP 的新用户，从零开始 5 步完成接入。

---

## 第 0 步：确认前置条件

| 条件 | 说明 |
|---|---|
| Acunetix 已安装运行 | 访问 `https://<主机>:3443` 能看到登录页 |
| Python 3.10+ | 运行 `python --version` 确认 |
| 一个 Acunetix 账号 | 管理员创建的用户即可（建议低权限账号） |

---

## 第 1 步：获取 API Key（推荐）或记住账号密码

**方式一（推荐）：API Key**
1. 浏览器打开 Acunetix，用你的账号登录
2. 点击**右上角你的用户名** → **Profile**
3. 向下滚动到 **API Key** 区域
4. 点击 **Generate new API key** → 点击 **Copy**
5. 复制得到的密钥（形如 `1986ad8c...` 的 64 位字符）

**方式二：账号密码**
- 使用你的登录邮箱和密码即可（注意：会话登录会踢掉其他在线会话）

---

## 第 2 步：把凭据填到"正确的位置"

凭据**不是填在代码里**，而是通过环境变量或 MCP 客户端的 `environment` 字段传入。三种常见场景：

### 场景 A：在 MCP 客户端（Claude Desktop / WorkBuddy / Cursor）中使用

打开 MCP 配置文件（各客户端位置不同，一般是 `claude_desktop_config.json` / WorkBuddy 连接器管理页），添加：

```json
{
  "mcpServers": {
    "acunetix-mcp": {
      "type": "local",
      "command": "python",
      "args": ["-m", "acunetix_mcp"],
      "environment": {
        "ACUNETIX_API_KEY": "粘贴你的API Key"
      }
    }
  }
}
```

### 场景 B：命令行直接运行

**Linux / macOS（bash）:**
```bash
export ACUNETIX_API_KEY="粘贴你的API Key"
python -m acunetix_mcp --selftest   # 验证配置
```
**Windows（PowerShell）:**
```powershell
$env:ACUNETIX_API_KEY="粘贴你的API Key"
python -m acunetix_mcp --selftest
```
**Windows（CMD）:**
```cmd
set ACUNETIX_API_KEY=粘贴你的API Key
python -m acunetix_mcp --selftest
```

### 场景 C：已在客户端运行、未预置凭据

无需重启——直接在对话中调用工具传入：
- `acunetix_use_api_key("<你的API Key>")`（推荐）
- 或 `acunetix_login(email="...", password="...")`

---

## 第 3 步：验证是否配置成功

```bash
python -m acunetix_mcp --selftest
```

预期输出：
```
认证: 官方 API Key
REST me: <你的邮箱>
targets: <N> 个目标
自检通过
```

---

## 第 4 步：开始使用

在支持 MCP 的 AI 客户端中，直接自然语言提问，例如：
- "列出所有扫描目标"
- "查看最近的漏洞"
- "对目标 X 启动一次扫描"
- "生成最新扫描报告"

---

## 故障排查

| 现象 | 原因 | 解决 |
|---|---|---|
| `缺少凭据` | 未配置环境变量 | 按第 2 步配置后重启，或调用 `acunetix_use_api_key` / `acunetix_login` |
| `认证失败 (401)` | API Key 错误/已失效 | 重新生成 API Key 并更新配置 |
| `连接失败（服务未启动?）` | Acunetix 未运行或地址错误 | 检查 `ACUNETIX_BASE_URL`，确认 3443 端口可访问 |
| `TLS 校验失败` | 自签名证书 | 设置 `ACUNETIX_VERIFY_SSL=false` |
| `429 限流` | 请求过快 | 客户端已自动退避，稍后重试即可 |
