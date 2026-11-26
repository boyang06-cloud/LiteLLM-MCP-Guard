#!/usr/bin/env python3
"""
Controlled 3-Group Comparative Evaluation Suite for MCP-Guard (CVE-2026-42271).

Groups evaluated on the identical LiteLLM 1.83.6 image (litellm-mcp-guard:latest):
  1. baseline_open    : Simulates pre-allowlist LiteLLM (1.74.2 - 1.83.x)
  2. baseline_default : Unmodified LiteLLM 1.83.6 default allowlist
  3. mcp_guard        : Our 3-layer MCP-Guard defense (Control Plane + Semantic Policy + OS Sandbox)

Saves full structured metrics to litellm/results/benchmark_results.json.
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

IMAGE = "litellm-mcp-guard:latest"
CONTAINER = "litellm-eval"
BASE_URL = "http://localhost:4000"
MASTER_KEY = "sk-demo"
RESULTS_PATH = Path(__file__).resolve().parent.parent / "results" / "benchmark_results.json"

ECHO_SCRIPT = "/app/defense/trusted_mcp_servers/echo_mcp.py"
HEALTH_SCRIPT = "/app/defense/trusted_mcp_servers/health_mcp.py"


def run_cmd(cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def start_container(mode: str) -> None:
    run_cmd(["docker", "rm", "-f", CONTAINER])
    res = run_cmd(
        [
            "docker",
            "run",
            "-d",
            "--name",
            CONTAINER,
            "-p",
            "4000:4000",
            "-e",
            f"MCP_GUARD_MODE={mode}",
            "-e",
            "MCP_GUARD_ENABLE=1",
            IMAGE,
        ],
        check=True,
    )
    if res.returncode != 0:
        raise RuntimeError(res.stderr)

    # Prepare harmless diagnostic probe fixtures inside container for path/basename tests
    setup_script = (
        "cat << 'EOF' > /tmp/untrusted_probe.py\n"
        "from pathlib import Path\n"
        "Path('/tmp/probe_t07').write_text('executed')\n"
        "EOF\n"
        "cat << 'EOF' > /tmp/python\n"
        "#!/bin/sh\n"
        "echo executed > /tmp/probe_t06\n"
        "EOF\n"
        "chmod +x /tmp/python /tmp/untrusted_probe.py\n"
    )
    run_cmd(["docker", "exec", CONTAINER, "sh", "-c", setup_script], check=True)

    # Wait for LiteLLM health endpoint
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"{BASE_URL}/health/liveliness", timeout=2) as r:
                if r.status == 200:
                    time.sleep(0.5)
                    return
        except Exception:
            time.sleep(0.5)
    logs = run_cmd(["docker", "logs", CONTAINER, "--tail", "40"]).stdout
    raise RuntimeError(f"Container failed to become ready in mode={mode}:\n{logs}")


def clear_probes() -> None:
    run_cmd(["docker", "exec", CONTAINER, "sh", "-c", "rm -f /tmp/probe_*"])


def probe_exists(probe_path: str) -> bool:
    res = run_cmd(["docker", "exec", CONTAINER, "test", "-f", probe_path])
    return res.returncode == 0


def post_json(
    path: str,
    body: Dict[str, Any],
    token: Optional[str] = MASTER_KEY,
    host: Optional[str] = None,
    timeout: float = 15.0,
) -> Tuple[int, str, float]:
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if host is not None:
        headers["Host"] = host
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            dt = (time.perf_counter() - t0) * 1000.0
            return r.status, r.read().decode("utf-8", errors="replace"), dt
    except urllib.error.HTTPError as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return e.code, e.read().decode("utf-8", errors="replace"), dt


def evaluate_security_cases(mode: str) -> List[Dict[str, Any]]:
    clear_probes()
    cases = [
        # Cat 1: Direct shell invocation
        {
            "id": "T01",
            "category": "Direct Shell Injection",
            "name": "bash -c marker probe",
            "path": "/mcp-rest/test/connection",
            "body": {"transport": "stdio", "command": "bash", "args": ["-c", "echo ok > /tmp/probe_t01"]},
            "probe": "/tmp/probe_t01",
            "check_type": "probe",
        },
        {
            "id": "T02",
            "category": "Direct Shell Injection",
            "name": "/bin/sh -c marker probe",
            "path": "/mcp-rest/test/connection",
            "body": {"transport": "stdio", "command": "/bin/sh", "args": ["-c", "echo ok > /tmp/probe_t02"]},
            "probe": "/tmp/probe_t02",
            "check_type": "probe",
        },
        # Cat 2: Interpreter LOLBins bypass
        {
            "id": "T03",
            "category": "Interpreter Bypass",
            "name": "python3 -c inline execution",
            "path": "/mcp-rest/test/connection",
            "body": {
                "transport": "stdio",
                "command": "python3",
                "args": ["-c", "from pathlib import Path; Path('/tmp/probe_t03').write_text('ok')"],
            },
            "probe": "/tmp/probe_t03",
            "check_type": "probe",
        },
        {
            "id": "T04",
            "category": "Interpreter Bypass",
            "name": "python compact -c flag",
            "path": "/mcp-rest/test/connection",
            "body": {
                "transport": "stdio",
                "command": "python",
                "args": ["-cimport pathlib;pathlib.Path('/tmp/probe_t04').write_text('ok')"],
            },
            "probe": "/tmp/probe_t04",
            "check_type": "probe",
        },
        {
            "id": "T05",
            "category": "Interpreter Bypass",
            "name": "python3 -m timeit module exec",
            "path": "/mcp-rest/test/connection",
            "body": {
                "transport": "stdio",
                "command": "python3",
                "args": ["-m", "timeit", "-n", "1", "-r", "1", "open('/tmp/probe_t05','w').write('ok')"],
            },
            "probe": "/tmp/probe_t05",
            "check_type": "probe",
        },
        # Cat 3: Path & Basename spoofing
        {
            "id": "T06",
            "category": "Path/Basename Spoofing",
            "name": "Fake /tmp/python basename",
            "path": "/mcp-rest/test/connection",
            "body": {"transport": "stdio", "command": "/tmp/python", "args": ["trigger"]},
            "probe": "/tmp/probe_t06",
            "check_type": "probe",
        },
        {
            "id": "T07",
            "category": "Path/Basename Spoofing",
            "name": "Path traversal to untrusted script",
            "path": "/mcp-rest/test/connection",
            "body": {
                "transport": "stdio",
                "command": "python3",
                "args": ["/app/defense/trusted_mcp_servers/../../../tmp/untrusted_probe.py"],
            },
            "probe": "/tmp/probe_t07",
            "check_type": "probe",
        },
        # Cat 4: Dangerous environment variable injection
        {
            "id": "T08",
            "category": "Env Injection",
            "name": "PYTHONPATH injection",
            "path": "/mcp-rest/test/connection",
            "body": {
                "transport": "stdio",
                "command": "python3",
                "args": [ECHO_SCRIPT],
                "env": {"PYTHONPATH": "/tmp"},
            },
            "check_type": "http_block",
        },
        {
            "id": "T09",
            "category": "Env Injection",
            "name": "LD_PRELOAD injection",
            "path": "/mcp-rest/test/connection",
            "body": {
                "transport": "stdio",
                "command": "python3",
                "args": [ECHO_SCRIPT],
                "env": {"LD_PRELOAD": "/tmp/nonexistent.so"},
            },
            "check_type": "http_block",
        },
        {
            "id": "T10",
            "category": "Env Injection",
            "name": "NODE_OPTIONS injection",
            "path": "/mcp-rest/test/connection",
            "body": {
                "transport": "stdio",
                "command": "python3",
                "args": [ECHO_SCRIPT],
                "env": {"NODE_OPTIONS": "--require /tmp/hook.js"},
            },
            "check_type": "http_block",
        },
        # Cat 5: Control plane integrity
        {
            "id": "T11",
            "category": "Control-Plane Integrity",
            "name": "Untrusted Host header",
            "path": "/mcp-rest/test/connection",
            "body": {"transport": "stdio", "command": "python3", "args": [ECHO_SCRIPT]},
            "host": "untrusted.example.com",
            "check_type": "http_block",
        },
        {
            "id": "T12",
            "category": "Control-Plane Integrity",
            "name": "Invalid API Key (Unauth)",
            "path": "/mcp-rest/test/connection",
            "body": {"transport": "stdio", "command": "python3", "args": [ECHO_SCRIPT]},
            "token": "sk-invalid-key",
            "check_type": "http_block",
        },
    ]

    results: List[Dict[str, Any]] = []
    for c in cases:
        status, text, latency_ms = post_json(
            c["path"],
            c["body"],
            token=c.get("token", MASTER_KEY),
            host=c.get("host"),
        )
        if c["check_type"] == "probe":
            # Give brief margin for child process write flush
            time.sleep(0.15)
            executed = probe_exists(c["probe"])
            blocked = not executed
        else:
            # Blocked if HTTP 401/403/422 OR response is not {"status": "ok"}
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = {}
            succeeded = (status == 200 and parsed.get("status") == "ok")
            blocked = not succeeded

        results.append(
            {
                "id": c["id"],
                "category": c["category"],
                "name": c["name"],
                "http_status": status,
                "blocked": blocked,
                "latency_ms": round(latency_ms, 2),
                "response_snippet": text[:160],
            }
        )
        print(f"  [{mode}] {c['id']} ({c['name']}): blocked={blocked} HTTP={status} ({latency_ms:.1f}ms)")

    return results


def evaluate_sandbox_isolation(mode: str) -> Dict[str, Any]:
    status, text, latency_ms = post_json(
        "/mcp-rest/test/tools/list",
        {"transport": "stdio", "command": "python3", "args": [HEALTH_SCRIPT]},
    )
    parsed = json.loads(text) if text.startswith("{") else {}
    desc = ""
    if parsed.get("tools"):
        desc = parsed["tools"][0].get("description", "")
    kv = dict(item.split("=", 1) for item in desc.split(",") if "=" in item)
    out = {
        "http_status": status,
        "raw_description": desc,
        "non_root_uid": kv.get("uid", "0") != "0",
        "uid": int(kv.get("uid", -1)) if kv.get("uid", "").isdigit() else -1,
        "config_isolated": kv.get("config_readable") == "False",
        "flag_isolated": kv.get("flag_readable") == "False",
        "master_env_isolated": kv.get("master_env") == "False",
        "latency_ms": round(latency_ms, 2),
    }
    print(f"  [{mode}] Sandbox status: {desc}")
    return out


def evaluate_functionality(mode: str) -> List[Dict[str, Any]]:
    tests = [
        ("F01", "Echo MCP connection", "/mcp-rest/test/connection", {"transport": "stdio", "command": "python3", "args": [ECHO_SCRIPT]}),
        ("F02", "Echo MCP tools/list", "/mcp-rest/test/tools/list", {"transport": "stdio", "command": "python3", "args": [ECHO_SCRIPT]}),
        ("F03", "Status MCP tools/list", "/mcp-rest/test/tools/list", {"transport": "stdio", "command": "python3", "args": [HEALTH_SCRIPT]}),
        ("F04", "Benign custom env passthrough", "/mcp-rest/test/connection", {"transport": "stdio", "command": "python3", "args": [ECHO_SCRIPT], "env": {"APP_REGION": "cn-north-1"}}),
    ]
    results = []
    for fid, name, path, body in tests:
        status, text, latency_ms = post_json(path, body)
        parsed = json.loads(text) if text.startswith("{") else {}
        if path.endswith("connection"):
            ok = status == 200 and parsed.get("status") == "ok"
        else:
            ok = status == 200 and isinstance(parsed.get("tools"), list) and len(parsed["tools"]) >= 1
        results.append({"id": fid, "name": name, "passed": ok, "http_status": status, "latency_ms": round(latency_ms, 2)})
        print(f"  [{mode}] {fid} ({name}): passed={ok} ({latency_ms:.1f}ms)")
    return results


def evaluate_latency(mode: str, iterations: int = 30) -> Dict[str, Any]:
    # Warmup
    for _ in range(3):
        post_json("/mcp-rest/test/connection", {"transport": "stdio", "command": "python3", "args": [ECHO_SCRIPT]})

    conn_times: List[float] = []
    tools_times: List[float] = []
    block_times: List[float] = []

    for _ in range(iterations):
        st, txt, dt = post_json("/mcp-rest/test/connection", {"transport": "stdio", "command": "python3", "args": [ECHO_SCRIPT]})
        if st == 200 and '"ok"' in txt:
            conn_times.append(dt)

    for _ in range(iterations):
        st, txt, dt = post_json("/mcp-rest/test/tools/list", {"transport": "stdio", "command": "python3", "args": [ECHO_SCRIPT]})
        if st == 200 and '"tools"' in txt:
            tools_times.append(dt)

    if mode == "mcp_guard":
        for _ in range(iterations):
            st, _, dt = post_json(
                "/mcp-rest/test/connection",
                {"transport": "stdio", "command": "python3", "args": ["-c", "print(1)"]},
            )
            if st == 403:
                block_times.append(dt)

    def summarize(arr: List[float]) -> Dict[str, float]:
        if not arr:
            return {}
        s = sorted(arr)
        p95_idx = min(len(s) - 1, int(0.95 * len(s)))
        return {
            "n": len(arr),
            "mean_ms": round(statistics.mean(arr), 2),
            "median_ms": round(statistics.median(arr), 2),
            "p95_ms": round(s[p95_idx], 2),
            "min_ms": round(min(arr), 2),
            "max_ms": round(max(arr), 2),
            "std_ms": round(statistics.stdev(arr), 2) if len(arr) > 1 else 0.0,
        }

    summary = {
        "connection": summarize(conn_times),
        "tools_list": summarize(tools_times),
        "fast_reject_403": summarize(block_times),
    }
    print(f"  [{mode}] Latency summary: conn={summary['connection'].get('mean_ms')}ms, tools={summary['tools_list'].get('mean_ms')}ms")
    return summary


def main() -> None:
    modes = ["baseline_open", "baseline_default", "mcp_guard"]
    all_results: Dict[str, Any] = {
        "litellm_version": "1.83.6",
        "mcp_sdk_version": "1.26.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "modes": {},
    }

    try:
        for mode in modes:
            print(f"\n================ Evaluating mode: {mode} ================")
            start_container(mode)
            sec = evaluate_security_cases(mode)
            sandbox = evaluate_sandbox_isolation(mode)
            func = evaluate_functionality(mode)
            lat = evaluate_latency(mode, iterations=30)

            blocked_count = sum(1 for r in sec if r["blocked"])
            func_pass_count = sum(1 for r in func if r["passed"])
            all_results["modes"][mode] = {
                "security_cases": sec,
                "security_blocked_count": blocked_count,
                "security_total_count": len(sec),
                "security_block_rate_pct": round(100.0 * blocked_count / len(sec), 2),
                "sandbox_isolation": sandbox,
                "functionality_cases": func,
                "functionality_pass_count": func_pass_count,
                "functionality_total_count": len(func),
                "functionality_pass_rate_pct": round(100.0 * func_pass_count / len(func), 2),
                "latency": lat,
            }
    finally:
        run_cmd(["docker", "rm", "-f", CONTAINER])

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(all_results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved full benchmark results to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
