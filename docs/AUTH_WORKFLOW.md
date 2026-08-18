# 登录态重建工作流（Custom Cookies）

> 适用场景：目标站点的登录机制无法被扫描器自动处理（无标准表单、风控验证、客户端加密提交、多步登录等），需要以"已登录"身份扫描受限区域。
> 版本：v1.2.0 起支持

---

## 一、前置条件：两个 MCP

| MCP | 必装？ | 安装 |
|---|---|---|
| `acunetix-mcp` | ✅ 必装 | 见仓库 README 主安装流程 |
| `js-reverse-mcp` | ⚠️ 可选（仅浏览器自动化取 Cookie 时需要） | npm 一行接入： |

```json
{
  "mcpServers": {
    "js-reverse": {
      "command": "npx",
      "args": ["js-reverse-mcp"]
    }
  }
}
```

> 说明：`js-reverse-mcp` 为第三方开源工具（GitHub: zhizhuodemao/js-reverse-mcp），用于浏览器自动化与 Cookie 提取。核心扫描能力不依赖它——你也可以用任何方式获取 Cookie（如手动从浏览器 DevTools 复制）。

---

## 二、职责分工

```
浏览器自动化（js-reverse / 手动）          acunetix-mcp
┌──────────────────────────┐      ┌────────────────────────────┐
│ ① 打开登录页              │      │ ④ set_custom_cookies        │
│ ② 完成登录（过风控）      │ ───▶ │ ⑤ verify_custom_cookies     │
│ ③ 提取完整 Cookie 串      │      │ ⑥ start_scan / 漏洞获取     │
└──────────────────────────┘      └────────────────────────────┘
        "拿到登录凭证"                     "使用凭证扫描"
```

---

## 三、完整步骤

### 步骤 1-3：浏览器登录并提取 Cookie

**方式 A：浏览器自动化（js-reverse）**

```
1. new_page("https://<站点>/login")           # 打开登录页
2. 填写凭据 → 完成登录（有风控时需真人交互）    # 登录成功标志：跳转登录页/出现登录后元素
3. evaluate_script → document.cookie          # 读非 HttpOnly Cookie
4. list_network_requests(cookieName="<登录token名>")  # 追踪 HttpOnly Cookie 的 Set-Cookie 源头
   → 用 reqid + outputPart="responseHeaders" 取完整值
5. 拼接为完整 Cookie 串："k1=v1; k2=v2; ..."
```

**方式 B：手动（任意浏览器）**

```
DevTools → Application → Cookies → 复制全部 Cookie 拼接为 "k1=v1; k2=v2" 串
```

**要点**：
- 完整 Cookie 串应包含**登录会话凭证**（如 `session`/`token`/`uid` 类 Cookie）——判断标准：未登录请求不会携带它
- 部分 HttpOnly Cookie（JS 读不到）需从浏览器网络面板的 Set-Cookie 响应头获取
- 截图/元素检查可辅助确认登录成功（出现"退出登录""我的""管理中心"等登录后元素）

### 步骤 4：注入 Cookie 到目标（acunetix-mcp）

```
acunetix_set_custom_cookies(target_id, cookie_str, url?)
→ {applied: true, verified: true, login_kind: "none", custom_cookies: [{url, cookie_len}]}
```

- `verified: true` 表示**已回读确认落盘**（工具内置验证，防止静默失效）
- 返回仅含摘要，不回显 Cookie 值

### 步骤 5：核查配置（可选）

```
acunetix_verify_custom_cookies(target_id)
→ {configured: true, has_token_hint: true, ...}
```

### 步骤 6：以登录态启动扫描

```
acunetix_start_scan(target_id, profile_id)   # 扫描器请求自动携带注入的 Cookie
acunetix_list_vulnerabilities()              # 获取结果
```

### 步骤 7：验证登录态是否生效（可选）

- 对比未登录与登录态扫描的**漏洞数与覆盖路径**（登录态应发现更多受限区域内容）
- 或检查扫描请求中登录后路径（如 `/user/`）是否仍被重定向到登录页

---

## 四、Cookie 过期与复用

- Cookie 有效期由目标站点决定（会话类常为 1 天~30 天）
- 过期后：重新走步骤 1-3 获取新 Cookie → 步骤 4 覆盖写入即可（幂等）
- 不再需要登录态时：`acunetix_clear_custom_cookies(target_id)` 清空
  （注意：清空不自动改 `login.kind`，恢复自动登录需显式配置）

---

## 五、常见问题

| 问题 | 处理 |
|---|---|
| 自动填表后无登录反应 | 站点有风控/JS 加密提交，需真人浏览器完成登录（自动化浏览器无法过行为风控） |
| Cookie 写入后 `verified: false` | 检查 url 是否与目标域名一致；检查 Cookie 串格式（`k=v` 分号分隔） |
| 扫描结果与未登录无差异 | 注入的 Cookie 不含登录凭证（会话 Cookie 才是关键）；确认已拿到登录后专属 Cookie |
| 登录后页面仍重定向到登录页 | Cookie 已过期或作用域不符；重新获取并确认 url 正确 |
| 站点登录后动态刷新 Cookie | 短扫描或扫描前手动刷新 Cookie；考虑配合扫描调度 |

---

## 六、安全提示

- Cookie 是登录凭证的等价物：**不要**将其写入日志、提交到仓库或回显到对话
- 工具已设计为只返回摘要（长度/域名）；调用方同样应避免打印完整 Cookie
- 建议使用专用测试账号，避免暴露真实账号会话
