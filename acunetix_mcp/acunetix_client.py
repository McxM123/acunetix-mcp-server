# -*- coding: utf-8 -*-
"""
acunetix_client.py — Acunetix (Invicti) 自动化客户端（GraphQL + REST 双通道）
======================================================================
基于官方 API 文档与协议行为构建：

【认证协议（官方文档 + 运行行为确认）】
  1. 登录：POST /graphql/ + mutation loginUser($data: UserLoginInput)
     - 密码必须先做 SHA-256 哈希（服务端要求）
     - 返回 { status: SUCCESS, token }，token 为 128 位十六进制会话标识
  2. 会话传递（两种通道，token 相同）：
     - GraphQL:  `X-Auth: <token>` 头（主 UI 数据通道）
     - REST:     `ui_session` cookie + `x-auth: <token>` 头（业务数据通道）
     - 注意：cookie 与 x-auth 必须来自【同一次登录】的同一个 token，否则 401
  3. 限流：HTTP 429 带 retry_after(delay_seconds)，需退避重试
  4. 会话失效：HTTP 401 → 清除本地 token；并发登录会踢掉旧会话（单会话约束）
  5. GraphQL introspection 被禁用 → 操作必须使用已知 query/mutation

【设计目标】把该系统 API 封装为大模型（LLM）可直接调用的工具层。
"""

import hashlib
import json
import logging
import re
import time
import urllib3
import requests
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("acunetix")


class AcunetixAuthError(Exception):
    """认证失败（凭据错误 / 账户锁定 / OTP / 会话失效）"""


class AcunetixRateLimited(Exception):
    """触发 429 限流且重试耗尽"""


class AcunetixAPIError(Exception):
    """GraphQL 错误 / HTTP 非 2xx / 网络错误"""


class AcunetixClient:
    """Acunetix 双通道客户端：登录、token 管理、限流退避、401 重登、错误解析。"""

    LOGIN_STATUS = {
        "ACCOUNT_LOCKED": "账户已锁定（含 retry_after）",
        "FAILED": "凭据错误",
        "OTP_NOT_SET": "未配置 OTP，需先绑定",
        "OTP_REQUIRED": "需要 OTP 二次验证",
        "PASSWORD_EXPIRED": "密码已过期",
        "SUCCESS": "成功",
    }

    def __init__(self, base_url="https://localhost:3443", verify_ssl=False,
                 timeout=30, max_retries=5, user_agent=None, api_key=None):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.token = None          # 会话 token（login 模式）
        self.api_key = None        # 官方 API Key（Profile 页生成，纯 X-Auth 认证）
        self.email = None
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
            ),
        })
        self.session.headers.setdefault("Origin", self.base_url)
        if api_key:
            self.use_api_key(api_key)

    # ------------------------------------------------------------------
    # 认证
    # ------------------------------------------------------------------
    def use_api_key(self, api_key):
        """
        【官方推荐认证】设置 API Key（Profile 页 → Generate new API key）。
        纯 X-Auth 头认证：REST 与 GraphQL 均可用，无需登录、无需 cookie、
        无单会话约束、无 401 会话失效问题。
        官方文档: /Acunetix-API-Documentation.yaml securityDefinitions
        """
        if not api_key or not isinstance(api_key, str):
            raise AcunetixAuthError("API Key 无效")
        self.api_key = api_key.strip()
        self.token = None
        logger.info("已启用官方 API Key 认证（%s...）", self.api_key[:8])

    def verify_api_key(self, api_key: str) -> dict:
        """用候选 Key 一次性探测 /me；失败抛异常，**不触碰**现有认证状态。

        用于"先校验、后提交"：调用方先 verify_api_key 确认有效，再 use_api_key 提交，
        避免无效 Key 覆盖当前可用凭据（BUG-2026-02）。
        """
        key = (api_key or "").strip()
        if not key:
            raise AcunetixAuthError("API Key 无效")
        url = f"{self.base_url}/api/v1/me"
        try:
            resp = self.session.get(url, headers={"X-Auth": key},
                                    verify=self.verify_ssl, timeout=self.timeout)
        except requests.exceptions.SSLError as exc:
            raise AcunetixAPIError(f"TLS 校验失败: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            raise AcunetixAPIError(f"连接失败（服务未启动?）: {exc}") from exc
        if resp.status_code == 429:
            raise AcunetixRateLimited("触发限流（429），请稍后重试")
        if resp.status_code == 401:
            raise AcunetixAuthError(
                "API Key 认证失败（401）—— key 无效、被删除或已重新生成，请在 Profile 页确认")
        if resp.status_code >= 400:
            raise AcunetixAPIError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError as exc:
            raise AcunetixAPIError(f"响应非 JSON: {resp.text[:200]}") from exc

    def login(self, email, password, otp_token=None, remember_me=True):
        pass_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        data = {"email": email, "password": pass_hash, "rememberMe": remember_me}
        if otp_token:
            data["otpToken"] = otp_token
        query = """mutation loginUser($data: UserLoginInput) {
  login(data: $data) { status token details }
}"""
        resp = self._raw_gql(query, {"data": data}, auth_required=False)
        login = resp.get("data", {}).get("login", {})
        status = login.get("status")
        if status != "SUCCESS":
            raise AcunetixAuthError(
                f"登录失败: {self.LOGIN_STATUS.get(status, status)} 详情={login.get('details')}")
        self.token = login.get("token")
        self.email = email
        # 保持 session cookie（REST 通道需要 ui_session 与 x-auth 同一 token）
        # cookie 域必须与实际访问 host 一致，否则 requests 不发送 cookie → REST 401
        host = urlparse(self.base_url).hostname or "localhost"
        self.session.cookies.set("ui_session", self.token, domain=host, path="/")
        logger.info("登录成功: %s", email)
        return {"status": status, "token": self.token}

    def logout(self):
        """清理本地认证（API Key 模式仅清理本地，不影响 key 本身）。"""
        if self.token:
            try:
                self._raw_gql("mutation logoutUser { logout }", {}, auth_required=True)
            except Exception as exc:
                logger.warning("登出请求失败（忽略）: %s", exc)
        self.token = None
        self.api_key = None
        self.email = None
        self.session.cookies.clear()

    @property
    def authenticated(self):
        return bool(self.token or self.api_key)

    # ------------------------------------------------------------------
    # 底层请求（含重试）
    # ------------------------------------------------------------------
    def _do(self, method, url, headers=None, json_body=None, params=None, _retry=0,
            _channel="graphql"):
        hdrs = {}
        # 官方 API Key 优先；无则用会话 token
        if self.api_key:
            hdrs["X-Auth"] = self.api_key
        elif self.token:
            hdrs["x-auth"] = self.token
            # 会话模式 REST 通道需 ui_session cookie；cookiejar 对无点主机名(localhost)
            # 存在域匹配缺陷（cookie 永远发不出去），故显式注入 Cookie 头绕开该缺陷
            hdrs["Cookie"] = f"ui_session={self.token}"
        if headers:
            hdrs.update(headers)
        try:
            resp = self.session.request(
                method, url, headers=hdrs, json=json_body, params=params,
                verify=self.verify_ssl, timeout=self.timeout)
        except requests.exceptions.SSLError as exc:
            raise AcunetixAPIError(f"TLS 校验失败: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            raise AcunetixAPIError(f"连接失败（服务未启动?）: {exc}") from exc

        if resp.status_code == 429:
            if _retry >= self.max_retries:
                raise AcunetixRateLimited(f"连续 {self.max_retries} 次触发限流（429）")
            try:
                delay = float(resp.json().get("details", {}).get("delay_seconds", 3))
            except Exception:
                delay = 3
            delay = max(1.0, delay)
            logger.warning("429 限流，等待 %.1fs 重试 (%d/%d)", delay, _retry + 1, self.max_retries)
            time.sleep(delay)
            return self._do(method, url, headers, json_body, params, _retry + 1, _channel)

        if resp.status_code == 401:
            if self.api_key:
                raise AcunetixAuthError(
                    "API Key 认证失败（401）—— key 无效、被删除或已重新生成，请在 Profile 页确认")
            if _channel == "rest":
                # REST 401 可能是 cookie 未发送的假阳性（无点主机名 localhost 域匹配缺陷），
                # 不连锁清空 token，交由调用方/LLM 决策（不做 GraphQL 通道有效性推断）
                raise AcunetixAuthError(
                    "REST 认证失败（401）。会话 token 已保留；若持续失败，请调用 acunetix_login 重建会话")
            # GraphQL 401：X-Auth 头被拒，token 真失效，清理会话
            self.token = None
            self.session.cookies.clear()
            raise AcunetixAuthError("会话已失效（401），请重新 login()")

        return resp

    def _raw_gql(self, query, variables=None, auth_required=True):
        if auth_required and not self.authenticated:
            raise AcunetixAuthError("未认证，请先调用 login() 或 use_api_key()")
        headers = {}
        if self.api_key:
            headers["X-Auth"] = self.api_key
        elif self.token:
            headers["X-Auth"] = self.token
        payload = {"query": query, "variables": variables or {}}
        resp = self._do("POST", f"{self.base_url}/graphql/",
                        headers=headers, json_body=payload)
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text[:500]
            # GraphQL 语法错误等形态：400 + errors[]，逐条解析 message（OBS-2026-01）
            if isinstance(detail, dict) and detail.get("errors"):
                msgs = [e.get("message", str(e)) for e in detail["errors"]]
                raise AcunetixAPIError(
                    f"GraphQL 错误(HTTP {resp.status_code}): " + " | ".join(msgs))
            raise AcunetixAPIError(f"HTTP {resp.status_code}: {detail}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise AcunetixAPIError(f"响应非 JSON: {resp.text[:300]}") from exc
        if body.get("errors"):
            msgs = [e.get("message", str(e)) for e in body["errors"]]
            joined = " | ".join(msgs)
            # 被顶会话形态：HTTP 200，401 内嵌于 errors[]（BUG-2026-01）
            if re.search(r"(?i)\b401\b", joined) and "unauthorized" in joined.lower():
                if self.api_key:
                    raise AcunetixAuthError(
                        "API Key 认证失败（GraphQL 内嵌 401）—— key 无效或已重新生成，请在 Profile 页确认")
                self.token = None
                self.session.cookies.clear()
                raise AcunetixAuthError(
                    "会话已失效（401 内嵌，可能被其他登录顶掉），请调用 acunetix_login 重新登录")
            raise AcunetixAPIError("GraphQL 错误: " + joined)
        return body

    def gql(self, operation_name, query, variables=None, auth_required=True):
        """通用 GraphQL 执行入口（LLM 主通道）。"""
        body = self._raw_gql(query, variables, auth_required=auth_required)
        result = body.get("data", {})
        logger.info("[%s] 返回: %s", operation_name,
                    list(result.keys()) if isinstance(result, dict) else type(result))
        return result

    def rest(self, method, path, params=None, json_body=None):
        """通用 REST 调用入口（/api/v1/...）。"""
        if not self.authenticated:
            raise AcunetixAuthError("未认证，请先调用 login() 或 use_api_key()")
        url = f"{self.base_url}/api/v1/{path.lstrip('/')}"
        resp = self._do(method, url, params=params, json_body=json_body, _channel="rest")
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text[:500]
            raise AcunetixAPIError(f"HTTP {resp.status_code}: {detail}")
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {"raw_bytes": len(resp.content), "content_type": resp.headers.get("Content-Type")}

    # ------------------------------------------------------------------
    # 业务封装（GraphQL）
    # ------------------------------------------------------------------
    def me(self):
        return self.gql("getUserData",
            "query getUserData { user { id accessRights firstName lastName lang roles { role { permissions } accessAllGroups } systemUser ownerId childAccount } }")

    def get_system_info(self):
        return self.gql("getSystemInfo",
            "query getSystemInfo { systemInfo { smtpConfigured canSendEmail acuMonitor buildNumber majorVersion minorVersion } }")

    def list_scan_profiles(self):
        return self.gql("scanProfiles", "query scanProfiles { scanProfiles { id name } }")

    # ------------------------------------------------------------------
    # 业务封装（REST —— 对应官方 REST 接口，已验证 200）
    # ------------------------------------------------------------------
    def rest_targets(self, limit=20):
        """目标列表（GET /api/v1/targets?l=N）"""
        return self.rest("GET", "targets", params={"l": limit})

    def rest_target(self, target_id):
        return self.rest("GET", f"targets/{target_id}")

    def rest_scans(self, limit=20):
        return self.rest("GET", "scans", params={"l": limit})

    def rest_vulnerabilities(self, limit=20):
        return self.rest("GET", "vulnerabilities", params={"l": limit})

    def rest_reports(self, limit=20):
        return self.rest("GET", "reports", params={"l": limit})

    def rest_scanning_profiles(self):
        return self.rest("GET", "scanning_profiles")

    def rest_me_stats(self):
        return self.rest("GET", "me/stats")

    def rest_users(self, limit=50):
        return self.rest("GET", "users", params={"l": limit})

    def rest_add_target(self, address, description="", criticality=10, group_id=None):
        """新增目标（POST /api/v1/targets）——高风险写操作，需 LLM 明确意图。
        官方枚举（官方文档）：
          criticality = Critical[30] / High[20] / Normal[10] / Low[0]
        传枚举外值（如 1/5）返回 400 Validation errors condition=enum。
        官方示例还含 type 字段（"default"），可省略（有默认值）。"""
        body = {"address": address, "description": description, "criticality": criticality}
        if group_id:
            body["group_id"] = group_id
        return self.rest("POST", "targets", json_body=body)

    def rest_start_scan(self, target_id, profile_id):
        """启动扫描（POST /api/v1/scans）——高风险写操作"""
        body = {"target_id": target_id, "profile_id": profile_id,
                "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
        return self.rest("POST", "scans", json_body=body)

    def set_custom_cookies(self, target_id, cookie_str, url=""):
        """写入 custom_cookies 并回读验证（防静默失效——PATCH 带 configuration 包装
        会返回 200 但不落盘，必须以 GET 回读比对确认）。

        流程：GET 当前配置 → PATCH login.kind=none + custom_cookies → GET 回读比对。
        返回结构化结果（只含摘要，不回显完整 cookie 值）。"""
        if not target_id or not cookie_str:
            raise ValueError("target_id 与 cookie_str 均为必填")
        cookie_str = cookie_str.strip()
        if not url:
            # 未传 url 时从目标 address 推断 origin（scheme://host）
            from urllib.parse import urlparse
            t = self.rest("GET", f"targets/{target_id}")
            addr = t.get("address", "")
            if addr:
                p = urlparse(addr if "://" in addr else "https://" + addr)
                url = f"{p.scheme}://{p.netloc}"
        if url and not url.startswith(("http://", "https://")):
            raise ValueError("url 必须以 http:// 或 https:// 开头")
        # 1) PATCH：关闭 automatic 登录 + 写入 custom_cookies
        self.rest("PATCH", f"targets/{target_id}/configuration", json_body={
            "login": {"kind": "none"},
            "custom_cookies": [{"cookie": cookie_str, "url": url}],
        })
        # 2) 回读验证
        after = self.rest("GET", f"targets/{target_id}/configuration")
        ck = after.get("custom_cookies", [])
        verified = bool(ck) and ck[0].get("cookie") == cookie_str
        login_kind = after.get("login", {}).get("kind")
        return {
            "applied": True,
            "verified": verified,
            "login_kind": login_kind,
            "custom_cookies": [{"url": c.get("url"),
                                "cookie_len": len(c.get("cookie", ""))} for c in ck],
            "note": "登录态已写入；cookie 会过期（取决于目标站点），建议尽快启动扫描",
        }

    def get_custom_cookies(self, target_id):
        """查询目标 custom_cookies 配置状态（只读，供登录态核查）。"""
        cfg = self.rest("GET", f"targets/{target_id}/configuration")
        ck = cfg.get("custom_cookies", [])
        login_kind = cfg.get("login", {}).get("kind")
        has_token_hint = any("=" in c.get("cookie", "") for c in ck)
        return {
            "configured": bool(ck),
            "login_kind": login_kind,
            "cookies": [{"url": c.get("url"),
                         "cookie_len": len(c.get("cookie", ""))} for c in ck],
            "has_token_hint": has_token_hint,
            "note": "cookie 有效期取决于目标站点；过期后需重新获取并调用 set_custom_cookies",
        }

    def clear_custom_cookies(self, target_id):
        """清空 custom_cookies（不自动修改 login.kind，恢复方式由调用方显式决定）。"""
        before = self.rest("GET", f"targets/{target_id}/configuration")
        prev_ck = before.get("custom_cookies", [])
        prev_login = before.get("login", {}).get("kind")
        self.rest("PATCH", f"targets/{target_id}/configuration", json_body={"custom_cookies": []})
        after = self.rest("GET", f"targets/{target_id}/configuration")
        cleared = not after.get("custom_cookies")
        return {
            "cleared": cleared,
            "previous_login_kind": prev_login,
            "previous_cookie_count": len(prev_ck),
            "note": "已清空 custom_cookies；login.kind 未改动（当前为 %s），如需恢复登录方式请显式调用" % prev_login,
        }

    def upload_login_sequence(self, target_id, file_path):
        """上传 .lsr 登录序列文件到目标（官方 LSR 流程，v1.3.0）。

        .lsr 文件由 Acunetix GUI 的 Login Sequence Recorder 录制生成（AI 无法代做录制，
        本方法只负责上传环节）：
        1) 读本地 .lsr → 2) POST FileUploadDescriptor{name,size} 拿 upload_url
        3) octet-stream 上传二进制 → 4) 返回上传状态。
        上传成功 ≠ 已应用；需再调 apply_login_sequence（login.kind=sequence）。"""
        import os
        if not os.path.isfile(file_path):
            raise ValueError(f"文件不存在: {file_path}")
        if not file_path.lower().endswith(".lsr"):
            raise ValueError("文件必须是 .lsr 格式（Login Sequence Recorder 录制产物）")
        size = os.path.getsize(file_path)
        name = os.path.basename(file_path)
        # 1) 申请临时上传 URL（实测返回相对路径 /uploads/xxx，需拼接 origin）
        resp = self.rest("POST", f"targets/{target_id}/configuration/login_sequence",
                         json_body={"name": name, "size": size})
        upload_url = resp.get("upload_url")
        if not upload_url:
            raise AcunetixAPIError(f"未获得上传 URL: {resp}")
        if upload_url.startswith("/"):
            from urllib.parse import urlparse
            p = urlparse(self.base_url)
            upload_url = f"{p.scheme}://{p.netloc}{upload_url}"
        # 2) octet-stream 上传 .lsr 二进制（临时 URL 无需认证头；
        #    实测需 Content-Range + Content-Disposition，服务端按分块上传协议校验）
        with open(file_path, "rb") as f:
            data = f.read()
        r = self.session.request("POST", upload_url, data=data,
                                 headers={"Content-Type": "application/octet-stream",
                                          "Content-Range": f"bytes 0-{len(data)-1}/{len(data)}",
                                          "Content-Disposition": f'attachment; filename="{name}"'},
                                 verify=self.verify_ssl, timeout=self.timeout)
        if r.status_code not in (200, 201, 204):
            raise AcunetixAPIError(
                f"LSR 上传失败: HTTP {r.status_code} {r.text[:200]}"
                + ("（服务端校验 LSR 格式失败——请确认文件来自 Login Sequence Recorder 录制）"
                   if r.status_code == 409 else ""))
        return {
            "uploaded": True,
            "name": name,
            "size": size,
            "note": "上传成功；还需调用 apply_login_sequence 应用（login.kind=sequence）",
        }

    def apply_login_sequence(self, target_id):
        """应用已上传的登录序列（PATCH login.kind=sequence）+ 回读确认。
        未上传 .lsr 时服务端返回 409 "Login sequence not found"——转为友好提示。"""
        try:
            self.rest("PATCH", f"targets/{target_id}/configuration",
                      json_body={"login": {"kind": "sequence"}})
        except AcunetixAPIError as exc:
            if "Login sequence not found" in str(exc):
                return {
                    "applied": False,
                    "login_kind": None,
                    "hint": "目标未上传登录序列（.lsr）——请先调用 upload_login_sequence 上传后再应用",
                }
            raise
        after = self.rest("GET", f"targets/{target_id}/configuration")
        kind = after.get("login", {}).get("kind")
        return {
            "applied": kind == "sequence",
            "login_kind": kind,
            "note": "登录序列已应用；扫描器将按 .lsr 重放登录",
        }

    def get_login_sequence(self, target_id):
        """查询目标当前登录序列（.lsr）状态（只读）。
        未配置时 GET 返回 404 → 视为 configured=False（正常状态）。"""
        try:
            resp = self.rest("GET", f"targets/{target_id}/configuration/login_sequence")
        except AcunetixAPIError as exc:
            if "404" in str(exc):
                return {"configured": False, "files": [], "note": "目标当前未配置登录序列"}
            raise
        if isinstance(resp, dict):
            files = resp.get("files")
            if isinstance(files, list) and files:
                return {"configured": True, "files": files}
            if resp.get("upload_id"):
                return {"configured": True, "files": [resp]}
        return {"configured": False, "files": []}

    def delete_login_sequence(self, target_id):
        """删除目标的登录序列（.lsr）；未配置时删除视为成功（幂等）。"""
        before = self.get_login_sequence(target_id)
        try:
            self.rest("DELETE", f"targets/{target_id}/configuration/login_sequence")
        except AcunetixAPIError as exc:
            if "404" not in str(exc):
                raise
        after = self.get_login_sequence(target_id)
        return {
            "deleted": not after.get("configured"),
            "previous": before,
            "note": "已删除登录序列；如需恢复登录方式请显式配置 login.kind",
        }

    def get_auth_config(self, target_id):
        """获取目标登录配置摘要（login.kind + custom_cookies + login_sequence）。
        供 LLM 在扫描前判断目标是否需要/已配置登录态（信息完备支持决策）。"""
        cfg = self.rest("GET", f"targets/{target_id}/configuration")
        ck = cfg.get("custom_cookies", [])
        ls = self.get_login_sequence(target_id)  # 内部已容错 404
        kind = cfg.get("login", {}).get("kind")
        return {
            "login_kind": kind,
            "custom_cookies_count": len(ck),
            "custom_cookies_urls": [c.get("url") for c in ck],
            "login_sequence_configured": ls.get("configured"),
            "auth_ready_hint": (
                "custom_cookies" if ck else
                "login_sequence" if ls.get("configured") else
                "none（目标未配置登录态：若站点需登录，扫描登录后区域前必须先配置）"),
        }

    def preflight_scan(self, target_id):
        """扫描前登录就绪检查：读取登录配置 + 评估覆盖风险（信息完备支持决策，不拦截扫描）。"""
        auth = self.get_auth_config(target_id)
        if auth["login_kind"] == "automatic":
            coverage_risk = "low（已启用 automatic 自动登录）"
        elif auth["custom_cookies_count"] > 0 or auth["login_sequence_configured"]:
            coverage_risk = "low（已配置登录态）"
        else:
            coverage_risk = "high（未配置登录态——若站点含登录后区域，扫描无法覆盖）"
        auth["coverage_risk"] = coverage_risk
        auth["guidance"] = (
            "扫描前建议：若目标需要登录，先配置登录态"
            "（automatic 已生效则直接扫；否则 acunetix_set_custom_cookies 或 "
            "acunetix_upload_login_sequence + apply）；确认后调用 acunetix_start_scan。"
            "若不确定目标是否需要登录，可询问用户。"
        )
        return auth


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    import os
    c = AcunetixClient()
    api_key = os.environ.get("ACUNETIX_API_KEY")
    email = os.environ.get("ACUNETIX_EMAIL")
    pwd = os.environ.get("ACUNETIX_PASSWORD")
    if api_key:
        c.use_api_key(api_key)
        print("== 认证（官方 API Key）==")
    elif email and pwd:
        print("== 登录 ==")
        c.login(email, pwd)
    else:
        print("缺少 ACUNETIX_API_KEY 或 ACUNETIX_EMAIL/PASSWORD 环境变量")
        raise SystemExit(1)
    print("== REST me ==")
    print(c.rest("GET", "me"))
    print("== REST targets(2) ==")
    t = c.rest_targets(limit=2)
    print("目标总数:", t.get("total_count", "?"))
    for tg in t.get("targets", [])[:2]:
        print(" -", tg["address"], tg["target_id"], "severity:", tg.get("severity_counts"))
    print("== REST scanning_profiles(3) ==")
    sp = c.rest_scanning_profiles()
    print("配置数:", sp.get("total_count", "?"))
    for p in sp.get("scanning_profiles", [])[:3]:
        print(" -", p.get("profile_id"), p.get("name"))
    print("== GraphQL me ==")
    print(c.me())
    print("== 登出 ==")
    c.logout()
    print("OK")
