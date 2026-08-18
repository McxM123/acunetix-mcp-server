# -*- coding: utf-8 -*-
"""
全能力核验脚本：启动 acunetix-mcp 并逐一真实调用全部工具，输出每项结果。
安全策略：读操作全部实调；写操作（add_target/start_scan）只验证参数校验与错误处理，
不真正创建/启动，避免污染系统数据。
"""
import json
import os
import subprocess
import sys
import time

_PY = sys.executable
_SERVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "acunetix_mcp", "acunetix_mcp_server.py")
print("== 配置核对 ==")
print("  server:", _SERVER)
print("  server 存在:", os.path.isfile(_SERVER))
print("  凭据来源: ACUNETIX_API_KEY=%s / ACUNETIX_EMAIL=%s" % (
    os.environ.get("ACUNETIX_API_KEY", "(未设置)")[:8] + "...",
    os.environ.get("ACUNETIX_EMAIL", "(未设置)")))

env = dict(os.environ)
proc = subprocess.Popen([_PY, _SERVER], env=env,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1)
time.sleep(1.5)


def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()
    deadline = time.time() + 25
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            return json.loads(line)
        time.sleep(0.1)
    return None


def call(name, args=None):
    r = send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": name, "arguments": args or {}}})
    if not r or "result" not in r:
        return {"ok": False, "error": "MCP 层错误: " + json.dumps(r)[:200]}
    txt = "".join(c.get("text", "") for c in r["result"].get("content", []))
    try:
        return json.loads(txt)
    except Exception:
        return {"ok": False, "raw": txt[:300]}


results = []


def record(name, fn):
    try:
        r = fn()
        ok = r.get("ok", False)
        summary = json.dumps(r, ensure_ascii=False)[:220]
        results.append((name, ok, summary))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {summary}")
    except Exception as e:
        results.append((name, False, str(e)))
        print(f"[FAIL] {name}: EXC {e}")
    time.sleep(0.6)  # 避免触发 429 限流


# ---- 握手 ----
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "verify", "version": "1.0"}}})
proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
proc.stdin.flush()
time.sleep(0.3)

# ---- 认证 ----
record("acunetix_login (环境变量凭据)", lambda: call("acunetix_login"))
record("acunetix_me (GraphQL 用户)", lambda: call("acunetix_me"))

# ---- 读操作 ----
record("acunetix_stats", lambda: call("acunetix_stats"))
record("acunetix_list_targets(3)", lambda: call("acunetix_list_targets", {"limit": 3}))
record("acunetix_list_scan_profiles", lambda: call("acunetix_list_scan_profiles"))
record("acunetix_list_scans(3)", lambda: call("acunetix_list_scans", {"limit": 3}))
record("acunetix_list_vulnerabilities(3)", lambda: call("acunetix_list_vulnerabilities", {"limit": 3}))
record("acunetix_list_reports(3)", lambda: call("acunetix_list_reports", {"limit": 3}))

# ---- 通用执行器 ----
record("acunetix_gql (getSystemInfo)", lambda: call("acunetix_gql", {
    "operation_name": "getSystemInfo",
    "query": "query getSystemInfo { systemInfo { buildNumber majorVersion minorVersion } }"}))
record("acunetix_rest (GET me)", lambda: call("acunetix_rest", {"method": "GET", "path": "me"}))

# ---- 单目标详情（从列表取真实 ID）----
def get_target_detail():
    lst = call("acunetix_list_targets", {"limit": 1})
    tg = lst.get("data", {}).get("targets", [])
    if not tg:
        return {"ok": False, "error": "无目标可取"}
    return call("acunetix_get_target", {"target_id": tg[0]["target_id"]})
record("acunetix_get_target(真实ID)", get_target_detail)

# ---- 写操作：仅验证参数校验/错误路径（不真正执行）----
record("acunetix_add_target (非法地址→错误路径)", lambda: call("acunetix_add_target", {
    "address": "", "description": "test", "criticality": 10}))
record("acunetix_start_scan (无效ID→错误路径)", lambda: call("acunetix_start_scan", {
    "target_id": "00000000-0000-0000-0000-000000000000",
    "profile_id": "11111111-1111-1111-1111-111111111111"}))

# ---- 登出 ----
record("acunetix_logout", lambda: call("acunetix_logout"))

proc.kill()

print("\n== 汇总 ==")
passed = sum(1 for _, ok, _ in results if ok)
print(f"通过 {passed}/{len(results)}")
for name, ok, _ in results:
    print(f"  {'✓' if ok else '✗'} {name}")
