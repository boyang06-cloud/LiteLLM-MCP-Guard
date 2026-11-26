"""
MCP-Guard: Three-Layer Defense-in-Depth Framework for LiteLLM Proxy MCP stdio Endpoints.

Modes (controlled via MCP_GUARD_MODE environment variable):
  - baseline_open    : Simulates pre-allowlist LiteLLM (1.74.2 - 1.83.x) without command restriction.
  - baseline_default : Unmodified LiteLLM 1.83.6 default allowlist behavior (control group).
  - mcp_guard        : Full three-layer defense:
                       Layer 1 - Control-plane access & Host header integrity check
                       Layer 2 - Semantic command/arg/script-hash & env sanitization engine
                       Layer 3 - OS-level unprivileged sandbox execution (nobody + no_new_privs + rlimit)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, TextIO, Tuple

logger = logging.getLogger("mcp_guard")

# ---------------------------------------------------------------------------
# Security Policy Definitions (Layer 1 & Layer 2)
# ---------------------------------------------------------------------------
TRUSTED_BIN_DIRS: Tuple[str, ...] = ("/usr/local/bin", "/usr/bin", "/bin")
TRUSTED_SCRIPT_DIR: str = os.getenv(
    "MCP_GUARD_TRUSTED_DIR", "/app/defense/trusted_mcp_servers"
)
SANDBOX_LAUNCHER: str = "/app/defense/sandbox_exec.py"

ALLOWED_HOSTS: Set[str] = set(
    h.strip().lower()
    for h in os.getenv(
        "MCP_GUARD_ALLOWED_HOSTS", "localhost,127.0.0.1,litellm-victim,0.0.0.0"
    ).split(",")
    if h.strip()
)

# Interpreters allowed ONLY when paired with a registered & hash-verified MCP script
ALLOWED_INTERPRETERS: Set[str] = {"python", "python3"}

# Interpreter flags capable of inline/arbitrary code execution or module hijacking
FORBIDDEN_INTERPRETER_FLAGS: Set[str] = {
    "-c",
    "-e",
    "--eval",
    "-i",
    "-m",
    "-",
    "-r",
    "--require",
    "--import",
    "--loader",
    "--inspect",
    "--inspect-brk",
    "--print",
    "-p",
    "--exec",
    "-x",
}

# Environment variables known to enable code/library injection or execution hijacking
FORBIDDEN_ENV_KEYS: Set[str] = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONEXECUTABLE",
    "PYTHONCOERCECLOCALE",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "GLOBIGNORE",
    "SHELLOPTS",
    "PS4",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "GCONV_PATH",
    "IFS",
    "PATH",
    "HOME",
    "SHELL",
}

SAFE_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_./:@=+-]{1,256}$")


class PolicyViolation(Exception):
    """Structured security policy rejection."""

    def __init__(self, code: str, message: str, status_code: int = 403):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_trusted_manifest(trusted_dir: str) -> Dict[str, str]:
    """Build SHA-256 integrity manifest for registered MCP server scripts at startup."""
    manifest: Dict[str, str] = {}
    base = Path(trusted_dir)
    if not base.is_dir():
        return manifest
    for entry in sorted(base.iterdir()):
        if entry.is_file() and entry.suffix == ".py":
            real_path = os.path.realpath(str(entry))
            manifest[real_path] = compute_sha256(real_path)
    return manifest


class SemanticPolicyEngine:
    """Layer-2 validator for MCP stdio command, arguments, script integrity, and env."""

    def __init__(self, trusted_dir: str = TRUSTED_SCRIPT_DIR):
        self.trusted_dir = os.path.realpath(trusted_dir)
        self.manifest = build_trusted_manifest(self.trusted_dir)

    def validate_host(self, raw_headers: Optional[Dict[str, str]]) -> None:
        if not raw_headers:
            return
        lower_headers = {k.lower(): v for k, v in raw_headers.items()}
        host_val = lower_headers.get("host", "").strip()
        if not host_val:
            return
        # Strip port if present (IPv4/hostname)
        host_only = host_val.split(":")[0].lower()
        if host_only not in ALLOWED_HOSTS:
            raise PolicyViolation(
                "E_UNTRUSTED_HOST",
                f"Host header '{host_val}' is not in MCP-Guard allowed hosts.",
                status_code=403,
            )

    def validate_stdio_config(
        self,
        command: Optional[str],
        args: Optional[List[str]],
        env: Optional[Dict[str, str]],
    ) -> Tuple[str, List[str], Dict[str, str]]:
        # 1. Command canonicalization & trusted binary directory check
        if not command or not isinstance(command, str):
            raise PolicyViolation("E_MISSING_COMMAND", "MCP stdio command is required.")

        base_name = os.path.basename(command)
        if base_name not in ALLOWED_INTERPRETERS:
            raise PolicyViolation(
                "E_UNTRUSTED_CMD",
                f"Command '{command}' is blocked by MCP-Guard (only registered interpreter entrypoints allowed).",
            )

        # Resolve absolute executable path and prevent basename spoofing (e.g. /tmp/python)
        if os.path.isabs(command) or "/" in command:
            resolved_bin = os.path.realpath(command)
        else:
            located = shutil.which(command)
            if not located:
                raise PolicyViolation(
                    "E_CMD_NOT_FOUND", f"Command '{command}' not found in trusted PATH."
                )
            resolved_bin = os.path.realpath(located)

        if not any(
            resolved_bin.startswith(d + os.sep) for d in TRUSTED_BIN_DIRS
        ) or not os.path.isfile(resolved_bin):
            raise PolicyViolation(
                "E_UNTRUSTED_BIN_PATH",
                f"Resolved binary path '{resolved_bin}' is outside trusted system directories.",
            )

        # 2. Argument semantic validation & trusted script integrity check
        arg_list = list(args or [])
        if not arg_list:
            raise PolicyViolation(
                "E_MISSING_ARGS",
                "MCP stdio interpreter requires a registered MCP server script path.",
            )

        # Block any inline execution flags or shell metacharacters
        for token in arg_list:
            if not isinstance(token, str):
                raise PolicyViolation("E_INVALID_ARG_TYPE", "Argument must be a string.")
            stripped = token.strip()
            flag_prefix = stripped.split("=")[0]
            if stripped in FORBIDDEN_INTERPRETER_FLAGS or flag_prefix in FORBIDDEN_INTERPRETER_FLAGS:
                raise PolicyViolation(
                    "E_DISALLOWED_FLAG",
                    f"Interpreter flag '{token}' is forbidden by MCP-Guard.",
                )
            # Detect compact short flags like -cimport or -ecmd
            if stripped.startswith("-") and len(stripped) > 2 and stripped[:2] in {"-c", "-e", "-m", "-i", "-r", "-p"}:
                raise PolicyViolation(
                    "E_DISALLOWED_FLAG",
                    f"Compact interpreter flag '{token}' is forbidden by MCP-Guard.",
                )

        # First argument must be a registered script inside TRUSTED_SCRIPT_DIR
        script_arg = arg_list[0]
        if script_arg.startswith("-"):
            raise PolicyViolation(
                "E_DISALLOWED_FLAG",
                f"Leading option '{script_arg}' before script path is not permitted.",
            )

        resolved_script = os.path.realpath(script_arg)
        if not resolved_script.startswith(self.trusted_dir + os.sep):
            raise PolicyViolation(
                "E_UNTRUSTED_SCRIPT",
                f"Script '{script_arg}' resolves outside trusted MCP directory.",
            )
        if resolved_script not in self.manifest:
            raise PolicyViolation(
                "E_UNREGISTERED_SCRIPT",
                f"Script '{resolved_script}' is not in the MCP-Guard signed manifest.",
            )

        actual_hash = compute_sha256(resolved_script)
        if actual_hash != self.manifest[resolved_script]:
            raise PolicyViolation(
                "E_HASH_MISMATCH",
                f"Integrity check failed for '{resolved_script}' (SHA-256 mismatch).",
            )

        # Validate remaining script CLI arguments
        for extra in arg_list[1:]:
            if not SAFE_ARG_RE.match(extra):
                raise PolicyViolation(
                    "E_UNSAFE_ARG",
                    f"Argument '{extra}' contains disallowed characters.",
                )

        # 3. Environment variable sanitization
        sanitized_env: Dict[str, str] = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        for key, val in (env or {}).items():
            upper_key = str(key).upper()
            if upper_key in FORBIDDEN_ENV_KEYS or upper_key.startswith(
                ("LD_", "PYTHON", "NODE_", "BASH_", "PERL", "RUBY")
            ):
                raise PolicyViolation(
                    "E_DANGEROUS_ENV",
                    f"Environment variable '{key}' is blocked by MCP-Guard.",
                )
            if not SAFE_ENV_KEY_RE.match(str(key)):
                raise PolicyViolation(
                    "E_INVALID_ENV_KEY",
                    f"Environment variable name '{key}' violates naming policy.",
                )
            if not isinstance(val, str) or "\x00" in val or val.startswith("()"):
                raise PolicyViolation(
                    "E_INVALID_ENV_VALUE",
                    f"Environment variable value for '{key}' is invalid.",
                )
            sanitized_env[str(key)] = val

        return resolved_bin, [resolved_script, *arg_list[1:]], sanitized_env


def _audit_log(event: Dict[str, Any]) -> None:
    record = {"ts": round(time.time(), 4), **event}
    try:
        with open("/tmp/mcp_guard_audit.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Runtime Installation Hooks for the 3 Experimental Modes
# ---------------------------------------------------------------------------
_INSTALLED = False


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True

    mode = os.getenv("MCP_GUARD_MODE", "baseline_default").strip().lower()
    sys.stderr.write(f"[MCP-Guard] Initializing defense hooks in mode='{mode}'\n")

    if mode == "baseline_default":
        # Unmodified LiteLLM 1.83.6 default behavior
        return

    if mode == "baseline_open":
        _install_baseline_open()
        return

    if mode == "mcp_guard":
        _install_mcp_guard()
        return

    sys.stderr.write(f"[MCP-Guard] Unknown MCP_GUARD_MODE='{mode}', falling back to default.\n")


def _install_baseline_open() -> None:
    """
    Simulate pre-allowlist LiteLLM (1.74.2 - 1.83.x) by disabling only the
    MCP_STDIO_ALLOWED_COMMANDS membership check for controlled comparison.
    """
    try:
        import litellm.constants as lconst
        import litellm.proxy._types as ltypes
        import litellm.proxy._experimental.mcp_server.mcp_server_manager as mgr

        class _AllowAllSet:
            def __contains__(self, _item: object) -> bool:
                return True

            def __iter__(self):
                return iter(())

        open_set = _AllowAllSet()
        lconst.MCP_STDIO_ALLOWED_COMMANDS = open_set  # type: ignore[assignment]
        ltypes.MCP_STDIO_ALLOWED_COMMANDS = open_set  # type: ignore[assignment]
        mgr.MCP_STDIO_ALLOWED_COMMANDS = open_set  # type: ignore[assignment]
        sys.stderr.write("[MCP-Guard] Mode 'baseline_open' active (unrestricted stdio commands).\n")
    except Exception as exc:
        sys.stderr.write(f"[MCP-Guard] Failed to apply baseline_open: {exc}\n")


def _install_mcp_guard() -> None:
    """Install all three defense layers onto LiteLLM 1.83.6 without modifying upstream wheel files."""
    from fastapi import HTTPException
    import anyio
    import mcp.client.stdio as mcs
    import litellm.proxy._experimental.mcp_server.mcp_server_manager as mgr
    from litellm.proxy._types import MCPTransport

    engine = SemanticPolicyEngine(TRUSTED_SCRIPT_DIR)
    sys.stderr.write(
        f"[MCP-Guard] Loaded {len(engine.manifest)} signed MCP scripts from {engine.trusted_dir}\n"
    )

    # --- Hook 1 & 2: Intercept _build_stdio_env and _create_mcp_client ---
    orig_build_env = mgr.MCPServerManager._build_stdio_env
    orig_create_client = mgr.MCPServerManager._create_mcp_client

    def guarded_build_stdio_env(self, server, raw_headers=None):
        if server.transport == MCPTransport.stdio:
            try:
                engine.validate_host(raw_headers)
            except PolicyViolation as pv:
                _audit_log({"action": "BLOCK", "layer": "L1_HOST", "code": pv.code, "detail": pv.message})
                raise HTTPException(
                    status_code=pv.status_code,
                    detail={"mcp_guard_blocked": True, "code": pv.code, "error": pv.message},
                )
        return orig_build_env(self, server, raw_headers)

    async def guarded_create_mcp_client(
        self,
        server,
        mcp_auth_header=None,
        extra_headers=None,
        stdio_env=None,
    ):
        transport = server.transport or MCPTransport.sse
        if transport == MCPTransport.stdio:
            raw_env = stdio_env if stdio_env is not None else dict(server.env or {})
            try:
                safe_bin, safe_args, safe_env = engine.validate_stdio_config(
                    command=server.command,
                    args=server.args,
                    env=raw_env,
                )
            except PolicyViolation as pv:
                _audit_log(
                    {
                        "action": "BLOCK",
                        "layer": "L2_POLICY",
                        "code": pv.code,
                        "command": server.command,
                        "args": server.args,
                        "detail": pv.message,
                    }
                )
                raise HTTPException(
                    status_code=pv.status_code,
                    detail={"mcp_guard_blocked": True, "code": pv.code, "error": pv.message},
                )

            _audit_log(
                {
                    "action": "ALLOW",
                    "layer": "L2_POLICY",
                    "command": safe_bin,
                    "args": safe_args,
                }
            )
            # Keep validated command name for upstream allowlist compatibility;
            # Layer-3 sandbox re-resolves canonical realpath right before execv.
            server.args = safe_args
            stdio_env = safe_env

        return await orig_create_client(
            self,
            server=server,
            mcp_auth_header=mcp_auth_header,
            extra_headers=extra_headers,
            stdio_env=stdio_env,
        )

    mgr.MCPServerManager._build_stdio_env = guarded_build_stdio_env  # type: ignore[method-assign]
    mgr.MCPServerManager._create_mcp_client = guarded_create_mcp_client  # type: ignore[method-assign]

    # --- Hook 2b: Re-propagate HTTPException out of _execute_with_mcp_client ---
    # Note: In LiteLLM 1.83.6 rest_endpoints.py, _execute_with_mcp_client catches BaseException
    # and masks errors into a generic 200 JSON dict. Wrapping MCPClient.__init__ or letting
    # rest_endpoints return a clear blocked JSON is even cleaner; we patch FastAPI route handler
    # response transparency via middleware if needed, OR let HTTPException pass through!
    # We also patch mcp.client.stdio._create_platform_compatible_process for Layer 3!

    # --- Hook 3: OS-level Lightweight Process Sandbox ---
    async def sandboxed_create_process(
        command: str,
        args: list[str],
        env: dict[str, str] | None = None,
        errlog: TextIO = sys.stderr,
        cwd: Path | str | None = None,
    ):
        # Defense-in-depth re-validation right at the process spawn sink
        safe_bin, safe_args, safe_env = engine.validate_stdio_config(
            command=command,
            args=args,
            env=None,  # ignore default inherited env, enforce minimal clean env
        )
        # Merge only already-validated safe business keys from env
        if env:
            for k, v in env.items():
                uk = k.upper()
                if uk not in FORBIDDEN_ENV_KEYS and not uk.startswith(
                    ("LD_", "PYTHON", "NODE_", "BASH_", "PERL", "RUBY", "LITELLM_", "OPENAI_", "ANTHROPIC_")
                ) and SAFE_ENV_KEY_RE.match(k):
                    safe_env[k] = v

        sandbox_cmd = [sys.executable, SANDBOX_LAUNCHER, safe_bin, *safe_args]
        _audit_log(
            {
                "action": "SANDBOX_SPAWN",
                "layer": "L3_SANDBOX",
                "target": safe_bin,
                "args": safe_args,
            }
        )
        return await anyio.open_process(
            sandbox_cmd,
            env=safe_env,
            stderr=errlog,
            cwd="/tmp",
            start_new_session=True,
        )

    mcs._create_platform_compatible_process = sandboxed_create_process  # type: ignore[assignment]

    # --- Hook 1b: Transparent HTTP 403 for MCP-Guard rejections on FastAPI app ---
    # Also intercept Starlette/FastAPI HTTP layer on /mcp-rest/test/* so Layer 1 + Layer 2
    # return explicit HTTP 403 JSON instead of being swallowed by _execute_with_mcp_client's
    # broad `except BaseException`.
    try:
        from litellm.proxy.proxy_server import app as litellm_app
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse

        class MCPGuardMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                if request.url.path.startswith("/mcp-rest/test/"):
                    try:
                        engine.validate_host(dict(request.headers))
                    except PolicyViolation as pv:
                        _audit_log(
                            {"action": "BLOCK", "layer": "L1_MIDDLEWARE", "code": pv.code, "detail": pv.message}
                        )
                        return JSONResponse(
                            status_code=pv.status_code,
                            content={"status": "blocked", "mcp_guard_blocked": True, "code": pv.code, "error": pv.message},
                        )

                    # Pre-validate JSON payload for stdio transport before handler swallows exceptions
                    if request.method == "POST":
                        body = await request.body()
                        try:
                            data = json.loads(body.decode("utf-8")) if body else {}
                        except Exception:
                            data = {}
                        if isinstance(data, dict) and str(data.get("transport", "")).lower() == "stdio":
                            # Only enforce semantic policy after verifying request carries auth header
                            # (unauthenticated requests still hit LiteLLM's own 401 auth handler)
                            if request.headers.get("authorization") or request.headers.get("x-litellm-api-key"):
                                try:
                                    engine.validate_stdio_config(
                                        command=data.get("command"),
                                        args=data.get("args"),
                                        env=data.get("env"),
                                    )
                                except PolicyViolation as pv:
                                    _audit_log(
                                        {
                                            "action": "BLOCK",
                                            "layer": "L2_MIDDLEWARE",
                                            "code": pv.code,
                                            "command": data.get("command"),
                                            "detail": pv.message,
                                        }
                                    )
                                    return JSONResponse(
                                        status_code=pv.status_code,
                                        content={
                                            "status": "blocked",
                                            "mcp_guard_blocked": True,
                                            "code": pv.code,
                                            "error": pv.message,
                                        },
                                    )
                return await call_next(request)

        litellm_app.add_middleware(MCPGuardMiddleware)
        sys.stderr.write("[MCP-Guard] FastAPI MCPGuardMiddleware registered.\n")
    except Exception as exc:
        sys.stderr.write(f"[MCP-Guard] Middleware registration note: {exc}\n")

    sys.stderr.write("[MCP-Guard] All 3 defense layers active.\n")
