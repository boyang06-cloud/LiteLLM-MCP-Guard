#!/usr/bin/env python3
"""Guarded entrypoint that installs MCP-Guard hooks before starting LiteLLM Proxy."""
import os
import sys

# Ensure /app/defense is on sys.path
DEFENSE_DIR = os.path.dirname(os.path.abspath(__file__))
if DEFENSE_DIR not in sys.path:
    sys.path.insert(0, DEFENSE_DIR)

import mcp_guard  # noqa: E402

mcp_guard.install()

from litellm.proxy.proxy_cli import run_server  # noqa: E402

if __name__ == "__main__":
    run_server()
