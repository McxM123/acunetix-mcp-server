# -*- coding: utf-8 -*-
"""
acunetix_mcp_server.py — Acunetix MCP Server（大模型直连层）
=================================================================
把 Acunetix (Invicti) 系统 API 封装为 MCP 工具，使大模型（LLM）能：
  1. 使用凭据直接认证并操作该系统任意功能
  2. 接收所有接口的完整返回内容
  3. 通过 GraphQL 通用执行器 + REST 业务封装覆盖全部功能面
  4. 内置错误处理：401 自动重登提示、429 限流退避、GraphQL 错误解析

运行方式（stdio 模式）：
  python acunetix_mcp_server.py

配置（环境变量，不硬编码凭据）：
  ACUNETIX_BASE_URL   默认 https://localhost:3443
  ACUNETIX_API_KEY    官方推荐：Profile 页生成的 API Key（可选，二选一）
  ACUNETIX_EMAIL      Acunetix 登录账号（与 PASSWORD 搭配，二选一）
  ACUNETIX_PASSWORD   Acunetix 登录密码
  ACUNETIX_VERIFY_SSL 默认 false（本机自签名证书）
"""

import json
import logging
import os
import sys
import warnings
from typing import Any

# 抑制 pydantic-settings 的已知启动警告（pydantic-settings 2.15.0 + mcp 1.29.0 中
# lifespan 字段未完整定义所致，非本项目问题；上游修复后移除本过滤——BUG-2026-05）
warnings.filterwarnings(
    "ignore",
    message="Field 'lifespan' has an incomplete definition",
    category=UserWarning)

from mcp.server.fastmcp import FastMCP

from acunetix_client import (
    AcunetixClient,
    AcunetixAuthError,
    AcunetixRateLimited,
    AcunetixAPIError,
)

# 项目版本号（单一来源；__init__.py 的 __version__ 引用此值）
VERSION = "1.3.4"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("acunetix-mcp")

# ----------------------------------------------------------------------
# 全局客户端（单实例，token 会话由 login/logout 工具管理）
# ----------------------------------------------------------------------
_client: AcunetixClient | None = None


def get_client() -> AcunetixClient:
    global _client
    if _client is None:
        _client = AcunetixClient(
            base_url=os.environ.get("ACUNETIX_BASE_URL", "https://localhost:3443"),
            verify_ssl=os.environ.get("ACUNETIX_VERIFY_SSL", "false").lower() == "true",
        )
        # 官方推荐：若配置了 ACUNETIX_API_KEY，启动即启用 API Key 认证（无需登录）
        api_key = os.environ.get("ACUNETIX_API_KEY")
        if api_key:
            _client.use_api_key(api_key)
            logger.info("已通过环境变量启用官方 API Key 认证")
    return _client


def _suggested_action(exc: Exception) -> str:
    """根据异常类型与消息给出可执行的下一步建议（信息提示，不干预 LLM 决策）"""
    name = type(exc).__name__
    msg = str(exc)
    if name == "AcunetixAuthError":
        if "缺少凭据" in msg:
            return "请设置环境变量 ACUNETIX_EMAIL / ACUNETIX_PASSWORD，或调用 acunetix_use_api_key 传入 API Key"
        if "API Key" in msg:
            return "请在 Acunetix Profile 页重新生成 API Key，然后调用 acunetix_use_api_key 更新"
        if "锁定" in msg:
            return "账户已被锁定，请等待解锁或联系管理员"
        if "OTP" in msg:
            return "需要 OTP 二次验证，请传入 otp_token 重新登录"
        if "过期" in msg:
            return "密码已过期，请联系管理员重置密码"
        if "REST 认证失败" in msg:
            return "可先调用 acunetix_me 检查 GraphQL 通道是否有效；已失效则调用 acunetix_login 重新登录"
        if "会话" in msg:
            return "会话已失效，请调用 acunetix_login 重新登录"
        if "凭据" in msg or "密码" in msg:
            return "请检查账号密码是否正确，或改用 acunetix_use_api_key"
        return "请检查认证凭据"
    if name == "AcunetixRateLimited":
        return "系统限流，请稍后重试或降低调用频率"
    if name == "AcunetixAPIError":
        if "连接失败" in msg:
            return "请确认 Acunetix 服务已启动，并检查 ACUNETIX_BASE_URL 地址与端口"
        if "TLS" in msg:
            return "证书校验失败，可设置 ACUNETIX_VERIFY_SSL=false（自签名场景）"
        return "请根据错误信息检查请求参数与端点路径"
    return "请根据错误信息排查"


def _err(exc: Exception) -> dict:
    """把异常转成结构化 JSON 返回（LLM 可直接理解）"""
    return {"ok": False, "error": type(exc).__name__, "message": str(exc),
            "suggested_action": _suggested_action(exc)}


def _ok(data: Any) -> dict:
    return {"ok": True, "data": data}


mcp = FastMCP("acunetix")
# mcp 1.10.x 的 FastMCP 不暴露 version 参数（settings 无法注入），
# 直接设置底层 Server.version，使 initialize 的 serverInfo.version 显示项目版本
try:
    mcp._mcp_server.version = VERSION
except AttributeError:
    pass


# ======================================================================
# 认证工具
# ======================================================================
@mcp.tool()
def acunetix_login(email: str | None = None, password: str | None = None,
                   otp_token: str | None = None) -> dict:
    """
    【会话登录】登录 Acunetix 系统并建立会话（方式二）。
    - email/password 省略时使用环境变量 ACUNETIX_EMAIL / ACUNETIX_PASSWORD
    - 成功后 token 保存在内存中，后续工具自动携带认证
    - 注意：系统有单会话约束，会话登录会顶掉其他在线会话
    提示：官方推荐方式是 acunetix_use_api_key（无单会话约束）。

    【重要区分】本工具登录的是 **Acunetix 扫描系统**（本 MCP 的认证），
    **不等于目标网站的登录态**。目标网站需要登录时，需单独配置：
    automatic（目标配置已生效）/ custom_cookies（acunetix_set_custom_cookies）
    / LSR（acunetix_upload_login_sequence + apply）。判断目标登录态请用
    acunetix_preflight_scan。
    """
    try:
        c = get_client()
        if c.api_key:
            ignored = any(v is not None for v in (email, password, otp_token))
            current_email = ""
            me_error = None
            try:
                current_email = c.rest("GET", "me").get("email", "")
            except Exception as exc:
                me_error = f"{type(exc).__name__}: {exc}"
            payload = {"mode": "api_key",
                       "authenticated": not me_error,
                       "note": "已启用官方 API Key 认证，无需会话登录",
                       "current_email": current_email}
            if me_error:
                payload["current_email_error"] = me_error
            if ignored:
                payload["params_ignored"] = True
                payload["note"] += "；显式传入的 email/password/otp_token 已被忽略（如需验证账密请先 acunetix_logout）"
            return _ok(payload)
        email = email or os.environ.get("ACUNETIX_EMAIL")
        password = password or os.environ.get("ACUNETIX_PASSWORD")
        if not email or not password:
            return _err(AcunetixAuthError(
                "缺少凭据：请设置环境变量 ACUNETIX_EMAIL / ACUNETIX_PASSWORD，或使用 acunetix_use_api_key 传入 API Key"))
        r = c.login(email, password, otp_token=otp_token)
        return _ok({"mode": "session", "status": r["status"], "email": email,
                    "token_preview": r["token"][:16] + "..."})
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_use_api_key(api_key: str) -> dict:
    """
    【官方推荐认证】使用 Profile 页生成的 API Key 认证（方式一）。
    - api_key: Profile 页 → API Key → Generate new API key 生成的 64 位密钥
    - 纯 X-Auth 头认证：REST 与 GraphQL 均可用，无需登录、无单会话约束
    - 若在环境变量 ACUNETIX_API_KEY 中配置，MCP server 启动时已自动启用，无需调用本工具

    【重要区分】本工具认证的是 **Acunetix 扫描系统**，**不等于目标网站的登录态**。
    目标网站需登录时请单独配置（见 acunetix_preflight_scan 指引）。
    """
    try:
        c = get_client()
        me = c.verify_api_key(api_key)   # 1) 先校验，此时尚未改动任何状态
        c.use_api_key(api_key)           # 2) 校验成功后才提交
        return _ok({"verified": True, "email": me.get("email"),
                    "first_name": me.get("first_name"), "su": me.get("su")})
    except Exception as exc:
        return _err(exc)                 # 校验失败时客户端凭据状态原封未动


@mcp.tool()
def acunetix_logout() -> dict:
    """登出并清理本地会话。
    影响：登出后本 MCP 的 Acunetix 认证失效，后续调用工具会提示未认证——
    需重新 acunetix_use_api_key 或 acunetix_login。
    注意：这只会登出 Acunetix 扫描系统，不影响任何目标网站登录态。"""
    try:
        get_client().logout()
        return _ok({"logged_out": True})
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_me() -> dict:
    """获取当前登录用户信息（GraphQL）。
    返回 user 字段（id/email/firstName/lastName/su 等），用于确认当前认证身份。
    若返回未认证错误，先调用 acunetix_use_api_key 或 acunetix_login。"""
    try:
        return _ok(get_client().me())
    except Exception as exc:
        return _err(exc)


# ======================================================================
# GraphQL 通用执行器（覆盖任意功能）
# ======================================================================
@mcp.tool()
def acunetix_gql(operation_name: str, query: str,
                 variables: dict | None = None) -> dict:
    """
    【通用 GraphQL 执行器】—— 大模型自主操作的核心通道。
    向 /graphql/ 发送任意已确认可用的 query/mutation。
    - operation_name: 操作名（如 loginUser / getSharedUIData / getSystemInfo）
    - query: 完整 GraphQL 文本（依据官方文档与已知操作清单）
    - variables: 变量对象（可选）
    注意：本系统 introspection 已禁用，必须使用已知操作名与字段结构。
    返回结构随具体操作而异（data 或 errors[]）。"""
    try:
        return _ok(get_client().gql(operation_name, query, variables or {}))
    except Exception as exc:
        return _err(exc)


# ======================================================================
# REST 通用执行器（覆盖 /api/v1/* 业务数据）
# ======================================================================
@mcp.tool()
def acunetix_rest(method: str, path: str, params: dict | None = None,
                  body: dict | None = None) -> dict:
    """
    【通用 REST 调用器】访问 /api/v1/* 端点。
    - method: GET/POST/PUT/DELETE/PATCH
    - path: 端点路径，如 targets / scans / vulnerabilities / reports / me
    - params: 查询参数（可选）
    - body: JSON 请求体（POST/PUT 等写操作需要）
    高风险写操作请确保意图明确。
    提示：写操作（PATCH/POST）后建议 GET 回读确认落盘——部分端点存在
    "返回成功但未生效"的静默失效，回读是唯一可靠确认方式。"""
    try:
        return _ok(get_client().rest(method.upper(), path, params=params, json_body=body))
    except Exception as exc:
        return _err(exc)


# ======================================================================
# 高频业务封装（REST —— 常用业务操作）
# ======================================================================
@mcp.tool()
def acunetix_list_targets(limit: int = 20) -> dict:
    """列出扫描目标（GET /api/v1/targets?l=N），含地址/ID/漏洞计数。
    提示：目标登录配置摘要（auth_config）请用 acunetix_get_target 或
    acunetix_preflight_scan 查看（本列表不逐目标查询，避免慢查询）。"""
    try:
        return _ok(get_client().rest_targets(limit))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_get_target(target_id: str) -> dict:
    """获取单个目标详情（GET /api/v1/targets/{id}）。
    - target_id: 目标 ID（acunetix_list_targets 获取）
    返回目标详情，并附 auth_config 登录配置摘要（login.kind / custom_cookies /
    login_sequence），供判断该目标是否需要/已配置登录态。"""
    try:
        c = get_client()
        data = c.rest_target(target_id)
        # 附加登录配置摘要（信息完备支持决策：LLM 可据此判断是否需要登录态）
        data["auth_config"] = c.get_auth_config(target_id)
        return _ok(data)
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_preflight_scan(target_id: str) -> dict:
    """
    【只读】扫描前登录就绪检查：读取目标登录配置并评估登录后区域覆盖风险。
    - target_id: 目标 ID（acunetix_list_targets 获取）
    返回 login_kind / custom_cookies_count / login_sequence_configured /
    auth_ready_hint / coverage_risk / guidance。
    用途：启动扫描前判断是否需要先配置登录态。本工具只提供决策信息，
    **不拦截扫描**——是否配置登录态、是否询问用户，由 LLM 决定。
    """
    try:
        return _ok(get_client().preflight_scan(target_id))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_list_scans(limit: int = 20) -> dict:
    """列出扫描任务（GET /api/v1/scans?l=N）——【摘要级】。
    轮询单次扫描状态用 acunetix_rest（method=GET, path=scans/{scan_id}）。
    注意：progress 在扫描处理中恒为 0（完成才=100），判断进展用
    current_session.severity_counts / threat 是否变化，详见 PROTOCOL §9。"""
    try:
        return _ok(get_client().rest_scans(limit))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_list_vulnerabilities(limit: int = 20) -> dict:
    """列出漏洞（GET /api/v1/vulnerabilities?l=N）——【摘要级】。
    每条含：漏洞类型/URL/严重度(0-4)/置信度/CWE 标签/状态/vuln_id。
    需要完整证据时（复现请求+注入 payload/CVSS 评分/影响/修复建议/参考链接）：
    用返回的 vuln_id 调 acunetix_rest（method=GET, path=vulnerabilities/{vuln_id}）获取【详情级】数据。
    注意：详情含注入 payload 等敏感请求内容，仅用于授权报告，勿写入公开日志/聊天。"""
    try:
        return _ok(get_client().rest_vulnerabilities(limit))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_list_reports(limit: int = 20) -> dict:
    """列出已生成报告（GET /api/v1/reports?l=N）——【摘要级】。
    - limit: 返回条数（默认 20）
    返回报告列表（report_id/名称/格式/大小/状态等）。
    生成报告用 acunetix_gql（GetReport 操作）；获取报告详情/内容用
    acunetix_rest（GET reports/{report_id}）。"""
    try:
        return _ok(get_client().rest_reports(limit))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_list_scan_profiles() -> dict:
    """列出扫描配置（GET /api/v1/scanning_profiles），用于启动扫描时选 profile。"""
    try:
        return _ok(get_client().rest_scanning_profiles())
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_stats() -> dict:
    """当前用户统计（GET /api/v1/me/stats）：扫描/目标/漏洞汇总。"""
    try:
        return _ok(get_client().rest_me_stats())
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_add_target(address: str, description: str = "",
                        criticality: int = 10) -> dict:
    """
    【写操作】新增扫描目标（POST /api/v1/targets）。
    - address: 目标 URL/IP，如 http://example.com
    - criticality: 官方枚举 Critical[30]/High[20]/Normal[10]/Low[0]，默认 10；其他值报 400
    返回：target_id（后续配置登录态/启动扫描都需此 ID）。
    - 提示：新增后若站点需登录，可配置登录态（acunetix_set_custom_cookies /
      acunetix_upload_login_sequence）；扫描前用 acunetix_preflight_scan 检查登录就绪度。
    """
    try:
        return _ok(get_client().rest_add_target(address, description, criticality))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_start_scan(target_id: str, profile_id: str) -> dict:
    """
    【写操作】对目标启动扫描（POST /api/v1/scans）。
    - target_id: 目标 ID（acunetix_list_targets 获取）
    - profile_id: 扫描配置 ID（acunetix_list_scan_profiles 获取）

    【登录前置检查（重要）】若目标含登录后受限区域，启动扫描前应确认登录配置：
    1. 先调 acunetix_get_target 或 acunetix_preflight_scan 查看 auth_config / coverage_risk
    2. 若未配置登录态且目标可能需登录：
       - 询问用户是否需要登录后扫描
       - 需要则配置：custom_cookies（acunetix_set_custom_cookies）或
         LSR（acunetix_upload_login_sequence + apply）或确认 automatic 已生效
    3. 未配置登录态直接扫描 = 只能覆盖匿名可见内容，登录后区域不可达。
    """
    try:
        return _ok(get_client().rest_start_scan(target_id, profile_id))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_set_custom_cookies(target_id: str, cookie_str: str, url: str = "") -> dict:
    """
    【写操作】为目标写入自定义 Cookie（Custom Cookies）以建立登录态，并回读验证落盘。
    适用于 automatic 自动登录无法生效的站点（无标准表单 / 风控 / 加密提交等）——
    由浏览器完成登录后提取 Cookie 串传入，扫描器直接以登录态请求。
    - target_id: 目标 ID（acunetix_list_targets 获取）
    - cookie_str: 完整 Cookie 串（如 "session=xxx; uid=yyy"），需包含登录会话凭证
    - url: Cookie 作用域 URL（可选，默认取目标 address 的 origin）
    返回 applied/verified 状态与摘要；不回显 cookie 完整值（敏感信息）。
    前置判断：先用 acunetix_preflight_scan 确认目标登录态需求；写入后用
    acunetix_verify_custom_cookies 核查，再 acunetix_start_scan。
    """
    try:
        return _ok(get_client().set_custom_cookies(target_id, cookie_str, url))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_verify_custom_cookies(target_id: str) -> dict:
    """
    【只读】查询目标自定义 Cookie 配置状态，供核查登录态是否已配置。
    - target_id: 目标 ID
    返回 configured / login_kind / cookies 摘要 / has_token_hint；cookie 值不回显。
    """
    try:
        return _ok(get_client().get_custom_cookies(target_id))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_clear_custom_cookies(target_id: str) -> dict:
    """
    【写操作】清空目标的自定义 Cookie。
    注意：不自动修改 login.kind，恢复登录方式（如 automatic）由调用方显式决定——
    可用 acunetix_rest（method=PATCH, path=targets/{target_id}/configuration,
    body={"login":{"kind":"automatic"}}）恢复。
    - target_id: 目标 ID
    返回 cleared 状态与清理前摘要。
    """
    try:
        return _ok(get_client().clear_custom_cookies(target_id))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_upload_login_sequence(target_id: str, file_path: str) -> dict:
    """
    【写操作】上传 .lsr 登录序列文件到目标（官方 LSR 流程）。
    .lsr 文件由 Acunetix GUI 的 Login Sequence Recorder 录制生成（AI 无法代做录制，
    本工具只负责上传环节）；上传后需调 acunetix_apply_login_sequence 应用。
    - target_id: 目标 ID
    - file_path: 本地 .lsr 文件绝对路径
    返回 uploaded/name/size 摘要。
    """
    try:
        return _ok(get_client().upload_login_sequence(target_id, file_path))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_apply_login_sequence(target_id: str) -> dict:
    """
    【写操作】应用已上传的登录序列（PATCH login.kind=sequence）+ 回读确认。
    应用后扫描器将按 .lsr 录制内容重放登录。
    前置：需先调 acunetix_upload_login_sequence 上传 .lsr；未上传时服务端返回 409
    "Login sequence not found"（工具会转友好提示）。
    - target_id: 目标 ID
    返回 applied/login_kind 状态。
    """
    try:
        return _ok(get_client().apply_login_sequence(target_id))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_get_login_sequence(target_id: str) -> dict:
    """
    【只读】查询目标当前登录序列（.lsr）配置状态。
    - target_id: 目标 ID
    返回 configured 与文件摘要（upload_id/name/size）。
    """
    try:
        return _ok(get_client().get_login_sequence(target_id))
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def acunetix_delete_login_sequence(target_id: str) -> dict:
    """
    【写操作】删除目标的登录序列（.lsr）。
    注意：删除后不自动修改 login.kind，恢复登录方式由调用方显式决定——
    可用 acunetix_rest（method=PATCH, path=targets/{target_id}/configuration,
    body={"login":{"kind":"automatic"}}）恢复。
    - target_id: 目标 ID
    返回 deleted 状态与删除前摘要。
    """
    try:
        return _ok(get_client().delete_login_sequence(target_id))
    except Exception as exc:
        return _err(exc)


if __name__ == "__main__":
    # 支持 --selftest 参数做端到端验证（只读操作）
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        c = get_client()
        api_key = os.environ.get("ACUNETIX_API_KEY")
        if api_key:
            c.use_api_key(api_key)
            print("认证: 官方 API Key", flush=True)
        else:
            email = os.environ.get("ACUNETIX_EMAIL")
            pwd = os.environ.get("ACUNETIX_PASSWORD")
            if not email or not pwd:
                print("自检失败: 缺少 ACUNETIX_API_KEY 或 ACUNETIX_EMAIL/PASSWORD 环境变量", flush=True)
                sys.exit(1)
            print("认证: 会话登录 →", c.login(email, pwd)["status"], flush=True)
        print("REST me:", c.rest("GET", "me").get("email"), flush=True)
        print("REST targets:", len(c.rest_targets(5).get("targets", [])), "个目标", flush=True)
        print("REST profiles:", len(c.rest_scanning_profiles().get("scanning_profiles", [])), "个配置", flush=True)
        print("GraphQL me:", c.me().get("user", {}).get("firstName"), flush=True)
        print("自检通过", flush=True)
        sys.exit(0)
    mcp.run()
