# -*- coding: utf-8 -*-
"""Acunetix MCP Server 启动入口（包模式）"""
import sys
import os

# 确保可 import 同包模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from acunetix_mcp_server import mcp, get_client, VERSION  # noqa: E402
from acunetix_client import AcunetixClient  # noqa: E402

__version__ = VERSION

GUIDE = """
====================================================================
 Acunetix MCP Server - 首次使用引导
====================================================================
 检测到尚未配置连接凭据。首次使用请按以下步骤操作：

 【方式一：官方 API Key（推荐，最简单）】
   1. 登录 Acunetix Web 界面（默认 https://<主机>:3443）
   2. 点击右上角你的用户名 → Profile
   3. 向下滚动到 "API Key" 区域 → 点击 "Generate new API key"
   4. 点击 "Copy" 复制生成的密钥
   5. 把密钥配置为环境变量：
        export ACUNETIX_API_KEY="<你复制的密钥>"
   或在 MCP 客户端的 environment 字段中配置：
        "environment": { "ACUNETIX_API_KEY": "<你复制的密钥>" }

 【方式二：账号密码（会话登录）】
   在 MCP 客户端 environment 中配置：
        "environment": {
          "ACUNETIX_EMAIL": "<你的登录邮箱>",
          "ACUNETIX_PASSWORD": "<你的登录密码>"
        }
   注意：会话登录有单会话约束，会踢掉其他在线会话，推荐方式一。

 【其他可选配置】
   ACUNETIX_BASE_URL    系统地址，默认 https://localhost:3443
   ACUNETIX_VERIFY_SSL  自签名证书需设为 false（默认）

 【验证是否配置成功】
   重新启动本服务，或执行：python -m acunetix_mcp --selftest
====================================================================
"""


def _check_env() -> bool:
    """检查环境变量是否已配置认证凭据；未配置时打印引导。"""
    api_key = os.environ.get("ACUNETIX_API_KEY")
    email = os.environ.get("ACUNETIX_EMAIL")
    pwd = os.environ.get("ACUNETIX_PASSWORD")
    if api_key or (email and pwd):
        return True
    print(GUIDE, file=sys.stderr, flush=True)
    return False


def main():
    """CLI 入口：--selftest 自检 / --help 帮助 / 默认启动 MCP stdio"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(GUIDE)
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        import logging
        logging.basicConfig(level=logging.ERROR)
        if not _check_env():
            sys.exit(1)
        try:
            c = get_client()
            api_key = os.environ.get("ACUNETIX_API_KEY")
            if api_key:
                c.use_api_key(api_key)
                print("认证: 官方 API Key", flush=True)
            else:
                email = os.environ.get("ACUNETIX_EMAIL")
                pwd = os.environ.get("ACUNETIX_PASSWORD")
                print("认证: 会话登录 →", c.login(email, pwd)["status"], flush=True)
            me = c.rest("GET", "me")
            print("REST me:", me.get("email"), flush=True)
            print("targets:", len(c.rest_targets(5).get("targets", [])), flush=True)
            print("自检通过", flush=True)
        except Exception as exc:
            print("\n自检失败:", str(exc), file=sys.stderr, flush=True)
            print("诊断建议:", file=sys.stderr, flush=True)
            msg = str(exc)
            if "连接失败" in msg:
                print("  1. 确认 Acunetix 服务已启动（访问 ACUNETIX_BASE_URL 看能否打开登录页）", file=sys.stderr, flush=True)
                print("  2. 检查 ACUNETIX_BASE_URL 地址与端口是否正确", file=sys.stderr, flush=True)
            elif "401" in msg or "认证失败" in msg:
                print("  1. 检查 ACUNETIX_API_KEY 是否过期或被删除（Profile 页重新生成）", file=sys.stderr, flush=True)
            elif "缺少凭据" in msg:
                print("  1. 按上面引导配置 ACUNETIX_API_KEY 或 ACUNETIX_EMAIL/PASSWORD", file=sys.stderr, flush=True)
            else:
                print("  请根据上方错误信息检查配置（详见 examples/NEW_USER_GUIDE.md 故障排查）", file=sys.stderr, flush=True)
            sys.exit(1)

    # 默认启动 MCP stdio；未配置凭据时打印引导（不阻塞启动，客户端可在对话中调用
    # acunetix_use_api_key / acunetix_login 传入凭据）
    _check_env()
    mcp.run()


if __name__ == "__main__":
    main()
