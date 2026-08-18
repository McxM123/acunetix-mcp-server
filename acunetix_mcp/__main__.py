# -*- coding: utf-8 -*-
"""支持 `python -m acunetix_mcp` 与 `python acunetix_mcp/__main__.py` 两种运行方式"""
import os
import sys

# 直接以脚本运行（如 MCP 客户端配置指向本文件绝对路径）时，
# sys.path[0] 为包目录，需把仓库根目录加入 path 以便 import 包
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from acunetix_mcp import main  # noqa: E402

if __name__ == "__main__":
    main()
