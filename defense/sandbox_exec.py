#!/usr/bin/env python3
"""
Layer-3 OS-level lightweight sandbox trampoline for MCP stdio subprocesses.

Applies Linux privilege dropping, PR_SET_NO_NEW_PRIVS, POSIX resource limits,
restricted working directory, and then execs the validated target command.
"""
import ctypes
import os
import pwd
import resource
import sys

PR_SET_NO_NEW_PRIVS = 38


def _apply_no_new_privs() -> None:
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        res = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if res != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
    except Exception as exc:
        sys.stderr.write(f"[MCP-Guard Sandbox] Warning: prctl failed: {exc}\n")


def _apply_rlimits() -> None:
    limits = [
        (resource.RLIMIT_CPU, (10, 10)),                  # max 10s CPU time
        (resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024)),  # 512 MB virtual mem
        (resource.RLIMIT_FSIZE, (1 * 1024 * 1024, 1 * 1024 * 1024)),   # 1 MB max file write
        (resource.RLIMIT_CORE, (0, 0)),                   # disable core dumps
        (resource.RLIMIT_NOFILE, (64, 64)),               # max 64 open FDs
    ]
    for lim, val in limits:
        try:
            resource.setrlimit(lim, val)
        except (ValueError, OSError):
            pass


def _drop_privileges(username: str = "nobody") -> None:
    if os.geteuid() != 0:
        return
    pw = pwd.getpwnam(username)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("[MCP-Guard Sandbox] Missing target command\n")
        sys.exit(2)

    target_cmd = sys.argv[1]
    target_args = sys.argv[1:]

    os.umask(0o077)
    sandbox_cwd = "/tmp/mcp_sandbox_cwd"
    os.makedirs(sandbox_cwd, mode=0o555, exist_ok=True)
    os.chdir(sandbox_cwd)

    _apply_rlimits()
    _drop_privileges("nobody")
    _apply_no_new_privs()

    os.execv(target_cmd, target_args)


if __name__ == "__main__":
    main()
