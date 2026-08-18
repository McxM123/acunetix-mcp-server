# -*- coding: utf-8 -*-
"""回归测试：验证缺陷修复（离线，不依赖真实 Acunetix 服务）

- BUG-01：rest() 必须把 params 透传给 requests.request（limit 分页语义）
- BUG-02/A-1：会话模式 Cookie 头必须显式注入（cookiejar 对无点主机名 localhost
  有域匹配缺陷，cookie 永远发不出去）；cookie 域必须等于 base_url 的 host
- B-1：REST 401 不得连锁清空 token；GraphQL 401（X-Auth 头被拒）才清空 token
- BUG-2026-01（U1）：HTTP 200 + errors[] 内嵌 401（被顶会话）→ 抛 AuthError + 清 token
- BUG-2026-02（U2）：verify_api_key 失败不触碰现有凭据
- BUG-2026-03（U3）：API Key 模式下 login 显式参数 → params_ignored:true
- OBS-2026-01（U4）：GraphQL 400 + errors[] 逐条解析
- OBS-2026-02（U5）：REST 401 文案中性 + 建议一致
- BUG-2026-05（U6）：启动 stderr 无 IncompleteFieldDefinitionWarning

运行：python tests/test_regressions.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import urlparse
from acunetix_mcp.acunetix_client import AcunetixClient


def _fake_ok_response(payload):
    class _R:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        content = b"{}"

        def json(self):
            return payload

    return _R()


class _R401:
    status_code = 401
    headers = {}
    content = b"{}"

    def json(self):
        return {}


def _mock_login(client, token="a" * 32):
    """mock login 的 GraphQL 响应为 SUCCESS"""
    client._raw_gql = lambda *a, **k: {
        "data": {"login": {"status": "SUCCESS", "token": token, "details": ""}}}


def test_rest_params_transparent():
    """BUG-01：rest(params=...) 必须把查询串传给 requests.request"""
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)  # 走 API Key 认证，避免未认证拦截
    captured = {}

    def fake_request(method, url, **kwargs):
        captured["params"] = kwargs.get("params")
        captured["url"] = url
        return _fake_ok_response({"targets": []})

    c.session.request = fake_request
    c.rest("GET", "targets", params={"l": 3})

    assert captured["params"] == {"l": 3}, f"params 未透传: {captured}"
    print("  PASS: rest(params) 已透传到 requests.request")


def test_rest_targets_limit():
    """BUG-01：rest_targets(limit=N) 应通过 params 传 l=N"""
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)
    captured = {}

    def fake_request(method, url, **kwargs):
        captured["params"] = kwargs.get("params")
        return _fake_ok_response({"targets": []})

    c.session.request = fake_request
    c.rest_targets(limit=5)
    assert captured["params"] == {"l": 5}, f"limit 未转为 l 参数: {captured}"
    print("  PASS: rest_targets(limit=5) 传递 params={l:5}")


def test_cookie_domain_dynamic():
    """BUG-02：login() 的 cookie 域必须等于 base_url 的 host（jar 属性层）"""
    for base in ["https://127.0.0.1:13443", "https://acunetix.example.com:3443",
                 "https://localhost:3443"]:
        c = AcunetixClient(base_url=base)
        _mock_login(c)
        c.login("u@example.com", "pw")

        expected = urlparse(base).hostname
        domains = {ck.domain for ck in c.session.cookies if ck.name == "ui_session"}
        assert expected in domains, f"cookie 域错误: {domains} 应含 {expected}"
        print(f"  PASS: cookie 域动态化 {base} → {expected}")


def test_cookie_header_explicitly_injected():
    """BUG-02/A-1：会话模式 Cookie 头必须显式注入到请求中（发送层断言，
    覆盖 localhost 无点主机名——cookiejar 对该场景永远不发 cookie）"""
    for base in ["https://localhost:3443", "https://127.0.0.1:13443",
                 "https://acunetix.example.com:3443"]:
        c = AcunetixClient(base_url=base)
        _mock_login(c)
        c.login("u@example.com", "pw")
        captured = {}

        def fake_request(method, url, **kwargs):
            captured["headers"] = kwargs.get("headers", {})
            return _fake_ok_response({"x": 1})

        c.session.request = fake_request
        c.rest("GET", "me/stats")
        cookie_hdr = captured["headers"].get("Cookie", "")
        assert "ui_session=" in cookie_hdr, \
            f"{base}: Cookie 头未显式注入: {captured['headers']}"
        print(f"  PASS: {base} Cookie 头显式注入（发送层确认）")


def test_rest_401_no_cascade():
    """B-1：REST 401 不得连锁清空会话 token（GraphQL 通道可能仍有效）"""
    c = AcunetixClient(base_url="https://localhost:3443")
    _mock_login(c)
    c.login("u@example.com", "pw")
    token_before = c.token

    c.session.request = lambda *a, **k: _R401()
    try:
        c.rest("GET", "me/stats")
        raise AssertionError("应抛出 AcunetixAuthError")
    except Exception as exc:
        assert c.token == token_before, f"REST 401 误清 token: {c.token}"
        assert "REST 认证失败" in str(exc), f"错误信息未区分通道: {exc}"
        print("  PASS: REST 401 未连锁清空 token，GraphQL 通道保留")


def test_graphql_401_clears_session():
    """B-1：GraphQL 401（X-Auth 头被拒）才清空 token（真失效）"""
    c = AcunetixClient(base_url="https://localhost:3443")
    c.token = "d" * 32  # 直接设 token，走真实 _raw_gql → _do(graphql 通道)
    c.session.request = lambda *a, **k: _R401()
    try:
        c._raw_gql("query { x }")
        raise AssertionError("应抛出 AcunetixAuthError")
    except Exception:
        assert c.token is None, f"GraphQL 401 未清空 token: {c.token}"
        print("  PASS: GraphQL 401 已清空 token（真失效）")


def test_embedded_401_clears_session():
    """U1 / BUG-2026-01：HTTP 200 + errors[] 内嵌 401（被顶会话）→ AuthError + 清 token"""
    from acunetix_mcp.acunetix_client import AcunetixAuthError
    # 会话模式：应清 token
    c = AcunetixClient(base_url="https://localhost:3443")
    c.token = "a" * 32
    c.session.request = lambda *a, **k: _fake_ok_response(
        {"errors": [{"message": "HTTP-RESPONSE: 401 Unauthorized ..."}]})
    try:
        c._raw_gql("query { x }")
        raise AssertionError("应抛出 AcunetixAuthError")
    except AcunetixAuthError:
        assert c.token is None, f"内嵌 401 未清 token: {c.token}"
        print("  PASS: 会话模式内嵌 401 → AuthError + token 清理")
    # API Key 模式：抛 AuthError 但保留 key
    c2 = AcunetixClient(base_url="https://localhost:3443")
    c2.api_key = "b" * 32
    c2.session.request = lambda *a, **k: _fake_ok_response(
        {"errors": [{"message": "HTTP-RESPONSE: 401 Unauthorized ..."}]})
    try:
        c2._raw_gql("query { x }")
        raise AssertionError("应抛出 AcunetixAuthError")
    except AcunetixAuthError:
        assert c2.api_key == "b" * 32, "API Key 模式不应清除 key"
        print("  PASS: API Key 模式内嵌 401 → AuthError + key 保留")


def test_use_api_key_verify_before_commit():
    """U2 / BUG-2026-02：verify_api_key 失败不触碰现有凭据"""
    from acunetix_mcp.acunetix_client import AcunetixAuthError
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("good" * 16)  # 模拟已有有效 key
    class _R401Me:
        status_code = 401
        text = "Unauthorized"
    c.session.get = lambda *a, **k: _R401Me()
    try:
        c.verify_api_key("bad" * 16)
        raise AssertionError("应抛出 AcunetixAuthError")
    except AcunetixAuthError:
        assert c.api_key == "good" * 16, f"verify 失败却误改 key: {c.api_key}"
        print("  PASS: verify_api_key 失败不触碰现有 key")


def test_login_params_ignored_flag():
    """U3 / BUG-2026-03：API Key 模式下 login 显式参数 → params_ignored:true"""
    import acunetix_mcp.acunetix_mcp_server as srv
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("k" * 32)
    c.rest = lambda *a, **k: {"email": "test@local.com"}  # mock /me
    srv._client = c
    r = srv.acunetix_login(email="u@example.com", password="wrong")
    assert r.get("ok") is True, f"应返回 ok: {r}"
    assert r["data"].get("params_ignored") is True, f"缺 params_ignored: {r}"
    print("  PASS: login 显式参数被忽略时返回 params_ignored:true")


def test_graphql_400_errors_parsed():
    """U4 / OBS-2026-01：HTTP 400 + errors[] 应逐条解析，而非整体字符串化"""
    from acunetix_mcp.acunetix_client import AcunetixAPIError
    c = AcunetixClient(base_url="https://localhost:3443")
    c.api_key = "k" * 32
    class _R400:
        status_code = 400
        def json(self):
            return {"errors": [{"message": "Cannot query field 'nope'"}]}
    c.session.request = lambda *a, **k: _R400()
    try:
        c._raw_gql("query { nope }")
        raise AssertionError("应抛出 AcunetixAPIError")
    except AcunetixAPIError as exc:
        assert str(exc).startswith("GraphQL 错误(HTTP 400):"), f"未解析 errors: {exc}"
        print("  PASS: GraphQL 400 + errors 已逐条解析")


def test_rest_401_neutral_wording():
    """U5 / OBS-2026-02：REST 401 文案不做通道推断；建议与消息一致"""
    from acunetix_mcp.acunetix_client import AcunetixAuthError
    from acunetix_mcp.acunetix_mcp_server import _suggested_action
    c = AcunetixClient(base_url="https://localhost:3443")
    c.token = "a" * 32
    c.session.request = lambda *a, **k: _R401()
    try:
        c.rest("GET", "me/stats")
        raise AssertionError("应抛出 AcunetixAuthError")
    except AcunetixAuthError as exc:
        msg = str(exc)
        assert "可能仍有效" not in msg, f"仍含通道推断: {msg}"
        action = _suggested_action(exc)
        assert "acunetix_me" in action, f"建议未引导检查 GraphQL: {action}"
        print("  PASS: REST 401 文案中性 + 建议一致")


def test_startup_no_warning():
    """U6 / BUG-2026-05：启动 stderr 无 IncompleteFieldDefinitionWarning"""
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env.setdefault("ACUNETIX_API_KEY", "x" * 64)
    proc = subprocess.Popen(
        [sys.executable, "-c", "import acunetix_mcp.acunetix_mcp_server"],
        cwd=root, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        text=True, encoding="utf-8")
    _, err = proc.communicate(timeout=30)
    assert "IncompleteFieldDefinitionWarning" not in err, \
        f"stderr 含警告: {err[:200]}"
    print("  PASS: 启动 stderr 无 IncompleteFieldDefinitionWarning")


def test_set_custom_cookies_verified():
    """v1.2.0：set_custom_cookies 写入后必须回读验证落盘（防静默失效），且摘要返回不回显 cookie 值"""
    import json as _json
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)
    calls = []

    def fake_rest(method, path, params=None, json_body=None):
        calls.append((method, path, json_body))
        if method == "PATCH":
            return None  # 204
        return {"login": {"kind": "none"},
                "custom_cookies": [{"cookie": "session=abc; uid=1", "url": "https://example.com/"}]}

    c.rest = fake_rest
    r = c.set_custom_cookies("t1", "session=abc; uid=1", "https://example.com/")
    assert r["applied"] is True
    assert r["verified"] is True, f"回读验证失败: {r}"
    assert r["login_kind"] == "none"
    assert r["custom_cookies"][0]["cookie_len"] == len("session=abc; uid=1")  # 只给长度摘要
    assert "session=abc" not in _json.dumps(r), "返回中泄露了完整 cookie 值"
    print("  PASS: set_custom_cookies 写入+回读验证，摘要返回无泄漏")


def test_get_custom_cookies_summary():
    """v1.2.0：get_custom_cookies 返回状态摘要与 has_token_hint（不回显完整值）"""
    import json as _json
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)
    c.rest = lambda *a, **k: {"login": {"kind": "none"},
                              "custom_cookies": [{"cookie": "session=abc", "url": "https://example.com/"}]}
    r = c.get_custom_cookies("t1")
    assert r["configured"] is True
    assert r["has_token_hint"] is True
    assert "session=abc" not in _json.dumps(r)
    print("  PASS: get_custom_cookies 摘要 + has_token_hint")


def test_clear_custom_cookies_no_login_change():
    """v1.2.0：clear 清空 cookie 但不自动修改 login.kind（由调用方显式决定）"""
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)
    state = {"login": {"kind": "automatic"},
             "custom_cookies": [{"cookie": "s=1", "url": "https://example.com/"}]}

    def fake_rest(method, path, params=None, json_body=None):
        if method == "PATCH":
            state["custom_cookies"] = []
            return None
        return state

    c.rest = fake_rest
    r = c.clear_custom_cookies("t1")
    assert r["cleared"] is True
    assert r["previous_login_kind"] == "automatic"
    assert state["login"]["kind"] == "automatic", "clear 不应改动 login.kind"
    print("  PASS: clear 清空 cookie，login.kind 保持不变")


def test_upload_login_sequence_flow():
    """v1.3.0：upload_login_sequence 构造 FileUploadDescriptor 并 octet-stream 上传"""
    import tempfile
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)
    rest_calls = []

    def fake_rest(method, path, params=None, json_body=None):
        rest_calls.append((method, path, json_body))
        return {"upload_url": "https://upload.local/tmp/x"}

    c.rest = fake_rest
    up = {}

    def fake_sess_req(method, url, **kwargs):
        up["url"] = url
        up["ct"] = kwargs.get("headers", {}).get("Content-Type")
        up["data"] = kwargs.get("data")
        class _R:
            status_code = 200
            text = "ok"
        return _R()

    c.session.request = fake_sess_req
    with tempfile.NamedTemporaryFile(suffix=".lsr", delete=False) as f:
        f.write(b"LSR-SEQ-DEMO")
        path = f.name
    try:
        r = c.upload_login_sequence("t1", path)
        assert r["uploaded"] is True
        assert r["size"] == len(b"LSR-SEQ-DEMO")
        assert rest_calls[0][1] == "targets/t1/configuration/login_sequence"
        assert rest_calls[0][2] == {"name": path.split("\\")[-1].split("/")[-1],
                                    "size": len(b"LSR-SEQ-DEMO")}
        assert up["url"] == "https://upload.local/tmp/x"
        assert up["ct"] == "application/octet-stream"
        assert up["data"] == b"LSR-SEQ-DEMO"
        print("  PASS: upload_login_sequence 构造 descriptor + octet-stream 上传")
    finally:
        import os as _os
        _os.unlink(path)


def test_apply_login_sequence_verified():
    """v1.3.0：apply_login_sequence PATCH kind=sequence + 回读确认"""
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)

    def fake_rest(method, path, params=None, json_body=None):
        if method == "PATCH":
            assert json_body == {"login": {"kind": "sequence"}}, f"PATCH body 错误: {json_body}"
            return None
        return {"login": {"kind": "sequence"}}

    c.rest = fake_rest
    r = c.apply_login_sequence("t1")
    assert r["applied"] is True
    assert r["login_kind"] == "sequence"
    print("  PASS: apply_login_sequence PATCH + 回读")


def test_get_login_sequence_state():
    """v1.3.0：get_login_sequence 解析 UploadedFile（files / upload_id 两种形态）"""
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)
    c.rest = lambda *a, **k: {"files": [{"upload_id": "u1", "name": "a.lsr", "size": 10}]}
    assert c.get_login_sequence("t1")["configured"] is True
    c.rest = lambda *a, **k: {"upload_id": "u2", "name": "b.lsr", "size": 5}
    assert c.get_login_sequence("t1")["configured"] is True
    c.rest = lambda *a, **k: {}
    assert c.get_login_sequence("t1")["configured"] is False
    print("  PASS: get_login_sequence 三种响应形态解析")


def test_delete_login_sequence():
    """v1.3.0：delete_login_sequence 删除后 configured=False"""
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)
    state = {"present": True}

    def fake_rest(method, path, params=None, json_body=None):
        if method == "DELETE":
            state["present"] = False
            return None
        return {"files": [{"upload_id": "u1"}]} if state["present"] else {}

    c.rest = fake_rest
    r = c.delete_login_sequence("t1")
    assert r["deleted"] is True
    assert r["previous"]["configured"] is True
    print("  PASS: delete_login_sequence 删除 + 前状态摘要")


def test_preflight_scan_risk_levels():
    """v1.3.1：preflight_scan 按登录配置输出正确的覆盖风险评估"""
    c = AcunetixClient(base_url="https://localhost:3443")
    c.use_api_key("x" * 64)
    # 场景1：custom_cookies 已配置 → 覆盖风险 low
    c.get_auth_config = lambda tid: {
        "login_kind": "none", "custom_cookies_count": 1,
        "custom_cookies_urls": ["https://example.com/"],
        "login_sequence_configured": False, "auth_ready_hint": "custom_cookies"}
    r1 = c.preflight_scan("t1")
    assert "low" in r1["coverage_risk"], f"场景1 应为 low: {r1}"
    # 场景2：未配置任何登录态 → 覆盖风险 high
    c.get_auth_config = lambda tid: {
        "login_kind": "none", "custom_cookies_count": 0,
        "custom_cookies_urls": [], "login_sequence_configured": False,
        "auth_ready_hint": "none（目标未配置登录态）"}
    r2 = c.preflight_scan("t1")
    assert "high" in r2["coverage_risk"], f"场景2 应为 high: {r2}"
    # 场景3：automatic → 覆盖风险 low
    c.get_auth_config = lambda tid: {
        "login_kind": "automatic", "custom_cookies_count": 0,
        "custom_cookies_urls": [], "login_sequence_configured": False,
        "auth_ready_hint": "automatic"}
    r3 = c.preflight_scan("t1")
    assert "low" in r3["coverage_risk"], f"场景3 应为 low: {r3}"
    assert "guidance" in r3 and "acunetix_start_scan" in r3["guidance"]
    print("  PASS: preflight_scan 三种登录配置的风险评估")


if __name__ == "__main__":
    test_rest_params_transparent()
    test_rest_targets_limit()
    test_cookie_domain_dynamic()
    test_cookie_header_explicitly_injected()
    test_rest_401_no_cascade()
    test_graphql_401_clears_session()
    test_embedded_401_clears_session()
    test_use_api_key_verify_before_commit()
    test_login_params_ignored_flag()
    test_graphql_400_errors_parsed()
    test_rest_401_neutral_wording()
    test_startup_no_warning()
    test_set_custom_cookies_verified()
    test_get_custom_cookies_summary()
    test_clear_custom_cookies_no_login_change()
    test_upload_login_sequence_flow()
    test_apply_login_sequence_verified()
    test_get_login_sequence_state()
    test_delete_login_sequence()
    test_preflight_scan_risk_levels()
    print("\n=== 回归测试全部通过 ===")
