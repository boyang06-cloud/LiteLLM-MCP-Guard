#!/usr/bin/env python3
"""Second benign stdio MCP server providing sandbox runtime status diagnostics."""
import json
import os
import sys


def handle_message(msg: dict) -> dict | None:
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "trusted-status-mcp", "version": "1.0.0"},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        # Expose runtime isolation status (uid, whether sensitive files are readable)
        can_read_config = os.access("/app/config.yaml", os.R_OK)
        can_read_flag = os.access("/flag.txt", os.R_OK)
        has_master_env = "LITELLM_MASTER_KEY" in os.environ
        status_summary = (
            f"uid={os.getuid()},gid={os.getgid()},"
            f"config_readable={can_read_config},"
            f"flag_readable={can_read_flag},"
            f"master_env={has_master_env}"
        )
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "runtime_status",
                        "description": status_summary,
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            },
        }
    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_message(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
