# -*- coding: utf-8 -*-
"""写操作闭环验证：添加测试目标 → 确认存在 → 删除 → 确认已删（不污染数据）"""
import json
import os
import subprocess
import sys
import time

_PY = sys.executable
_SERVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "acunetix_mcp", "acunetix_mcp_server.py")
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
    txt = "".join(c.get("text", "") for c in r["result"].get("content", []))
    return json.loads(txt)


send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "write-test", "version": "1.0"}}})
proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
proc.stdin.flush()
time.sleep(0.3)

TEST_ADDR = "http://127.0.0.1:9/acunetix-mcp-write-test"

print("== 1. 登录/认证 ==")
r = call("acunetix_login")
d = r.get("data", {})
if r.get("ok"):
    # API Key 模式返回 note；会话模式返回 status
    print("   ok:", r["ok"], "|", d.get("status") or d.get("note", "已认证"))

print("== 2. 添加测试目标（写操作）==")
r = call("acunetix_add_target", {"address": TEST_ADDR, "description": "MCP 写操作闭环验证，测后即删", "criticality": 10})
print("   raw:", json.dumps(r, ensure_ascii=False)[:400])
target_id = None
data = r.get("data")
if isinstance(data, dict):
    target_id = data.get("target_id") or data.get("id")
    if not target_id and isinstance(data.get("target"), dict):
        target_id = data["target"].get("target_id")
print("   新目标 ID:", target_id)

if target_id:
    print("== 3. 确认存在（list 中检索）==")
    r = call("acunetix_list_targets", {"limit": 50})
    found = [t for t in r["data"]["targets"] if t["target_id"] == target_id]
    print("   列表命中:", len(found) == 1, "| 地址:", found[0]["address"] if found else "-")

    print("== 4. 删除测试目标（REST DELETE）==")
    r = call("acunetix_rest", {"method": "DELETE", "path": f"targets/{target_id}"})
    print("   raw:", json.dumps(r, ensure_ascii=False)[:300])

    time.sleep(1)
    print("== 5. 确认已删除 ==")
    r = call("acunetix_list_targets", {"limit": 50})
    found = [t for t in r["data"]["targets"] if t["target_id"] == target_id]
    print("   残留命中:", len(found), "（应为 0）")

    time.sleep(1)
    print("== 6. 删除验证（再次 DELETE，预期 404）==")
    r = call("acunetix_rest", {"method": "DELETE", "path": f"targets/{target_id}"})
    print("   raw:", json.dumps(r, ensure_ascii=False)[:200])

print("== 7. 登出 ==")
r = call("acunetix_logout")
print("   ok:", r["ok"])

proc.kill()
print("\n== 写操作闭环验证完成 ==")
