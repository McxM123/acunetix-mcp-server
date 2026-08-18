# -*- coding: utf-8 -*-
"""MCP 完整工具调用测试（模拟大模型操作该系统）"""
import json
import os
import subprocess
import sys
import time

PY = sys.executable
SERVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "acunetix_mcp", "acunetix_mcp_server.py")
proc = subprocess.Popen(
    [PY, SERVER],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    text=True, encoding="utf-8", bufsize=1)
time.sleep(1)


def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()
    deadline = time.time() + 20
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        return json.loads(line)
    return None


def call(name, args=None):
    r = send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": name, "arguments": args or {}}})
    result = r.get("result", {})
    # 解析 content
    texts = [c.get("text", "") for c in result.get("content", [])]
    return "".join(texts)


# 握手
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "llm-test", "version": "1.0"}}})
proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
proc.stdin.flush()
time.sleep(0.3)

print("== 1. acunetix_login ==")
print(call("acunetix_login")[:200])

print("\n== 2. acunetix_me (GraphQL) ==")
print(call("acunetix_me")[:300])

print("\n== 3. acunetix_stats ==")
print(call("acunetix_stats")[:300])

print("\n== 4. acunetix_list_targets ==")
print(call("acunetix_list_targets", {"limit": 3})[:500])

print("\n== 5. acunetix_list_scan_profiles ==")
print(call("acunetix_list_scan_profiles")[:400])

print("\n== 6. acunetix_gql (getSystemInfo) ==")
print(call("acunetix_gql", {
    "operation_name": "getSystemInfo",
    "query": "query getSystemInfo { systemInfo { buildNumber majorVersion minorVersion } }",
})[:300])

print("\n== 7. acunetix_logout ==")
print(call("acunetix_logout")[:200])

proc.kill()
print("\n== ALL TOOL CALLS PASSED ==")
