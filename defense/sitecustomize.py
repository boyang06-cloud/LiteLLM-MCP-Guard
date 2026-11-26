"""Auto-activate MCP-Guard inside LiteLLM worker processes when enabled."""
import os

if os.getenv("MCP_GUARD_ENABLE") == "1":
    import mcp_guard
    mcp_guard.install()
