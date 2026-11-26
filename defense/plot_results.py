#!/usr/bin/env python3
"""
Generate publication-grade quantitative figures from benchmark_results.json
following ccf-visual-composer & Chinese Journal of Computers (计算机学报) typography standards.
Outputs both vector PDF (for XeLaTeX inclusion) and 300-DPI PNG (for visual QA).
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_PATH = ROOT / "litellm" / "results" / "benchmark_results.json"
OUT_DIR = (
    ROOT
    / "信息安全前沿技术期末作业"
    / "计算机学报模板_Chinese_Journal_of_Computer_Template"
    / "figures"
)

plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.sans-serif": ["Microsoft YaHei", "SimHei", "SimSun", "DejaVu Sans"],
        "axes.unicode_minus": False,
        "axes.linewidth": 0.9,
        "xtick.major.width": 0.8,
        "ytick.major.width": 0.8,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)

COLORS = {
    "baseline_open": ("#F5B7B1", "#B03A2E"),
    "baseline_default": ("#AED6F1", "#2471A3"),
    "mcp_guard": ("#A3E4D7", "#117A65"),
    "fast_reject": ("#D7BDE2", "#6C3483"),
}

MODE_LABELS = {
    "baseline_open": "无白名单基线",
    "baseline_default": "LiteLLM 1.83.6 默认",
    "mcp_guard": "MCP-Guard (本文)",
}


def load_data() -> dict:
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def plot_security_comparison(data: dict) -> None:
    modes = ["baseline_open", "baseline_default", "mcp_guard"]
    cat_map = [
        ("Direct Shell Injection", "直接Shell\n注入"),
        ("Interpreter Bypass", "解释器\n绕过"),
        ("Path/Basename Spoofing", "路径/名称\n伪造"),
        ("Env Injection", "环境变量\n注入"),
        ("Control-Plane Integrity", "控制面\n完整性"),
    ]

    rates = {m: [] for m in modes}
    for m in modes:
        cases = data["modes"][m]["security_cases"]
        for cat_en, _ in cat_map:
            sub = [c for c in cases if c["category"] == cat_en]
            pct = 100.0 * sum(1 for c in sub if c["blocked"]) / len(sub)
            rates[m].append(pct)
        rates[m].append(data["modes"][m]["security_block_rate_pct"])

    x_labels = [zh for _, zh in cat_map] + ["总体\n拦截率"]
    x = np.arange(len(x_labels))
    width = 0.25

    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(7.4, 3.45), gridspec_kw={"width_ratios": [1.28, 1.0]}
    )

    # --- Panel (a): Category block rate bar chart ---
    offsets = [-width, 0.0, width]
    hatches = ["///", "...", ""]
    for idx, m in enumerate(modes):
        fill, edge = COLORS[m]
        bars = ax1.bar(
            x + offsets[idx],
            rates[m],
            width=width * 0.90,
            color=fill,
            edgecolor=edge,
            linewidth=1.05,
            hatch=hatches[idx],
            label=MODE_LABELS[m],
            zorder=3,
        )
        for j, (b, val) in enumerate(zip(bars, rates[m])):
            y_pos = val + 2.2
            lbl = f"{val:.0f}" if abs(val - round(val)) < 1e-6 else f"{val:.1f}"
            x_shift = 0.0
            if j == 0 and idx == 1:
                x_shift = -0.05
            elif j == 0 and idx == 2:
                x_shift = 0.06
            ax1.text(
                b.get_x() + b.get_width() / 2.0 + x_shift,
                y_pos,
                lbl,
                ha="center",
                va="bottom",
                fontsize=6.0,
                fontweight="bold",
                color=edge,
            )

    ax1.set_ylim(0, 114)
    ax1.set_xticks(x)
    ax1.set_xticklabels(x_labels, fontsize=7.4, fontweight="bold")
    ax1.set_ylabel("风险拦截率 (%)", fontsize=8.5, fontweight="bold")
    ax1.set_title("(a) 各类攻击向量拦截率对比", fontsize=9.0, fontweight="bold", pad=22)
    ax1.grid(axis="y", linestyle="--", alpha=0.4, zorder=0)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)
    ax1.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 1.11),
        frameon=False,
        fontsize=7.0,
        ncol=3,
        columnspacing=0.9,
        handletextpad=0.4,
    )

    # --- Panel (b): Per-case & Sandbox Isolation Matrix ---
    row_items = [
        ("T01", "bash -c"),
        ("T02", "/bin/sh -c"),
        ("T03", "python3 -c"),
        ("T04", "python -c紧缩"),
        ("T05", "python3 -m"),
        ("T06", "伪造/tmp/python"),
        ("T07", "路径穿越脚本"),
        ("T08", "PYTHONPATH"),
        ("T09", "LD_PRELOAD"),
        ("T10", "NODE_OPTIONS"),
        ("T11", "伪造Host头"),
        ("T12", "无效API Key"),
        ("S01", "非root降权"),
        ("S02", "配置文件隔离"),
        ("S03", "flag文件隔离"),
    ]

    mat = np.zeros((len(row_items), 3), dtype=int)
    for col_idx, m in enumerate(modes):
        sec_by_id = {c["id"]: c["blocked"] for c in data["modes"][m]["security_cases"]}
        sb = data["modes"][m]["sandbox_isolation"]
        for row_idx, (rid, _) in enumerate(row_items):
            if rid.startswith("T"):
                mat[row_idx, col_idx] = 1 if sec_by_id[rid] else 0
            elif rid == "S01":
                mat[row_idx, col_idx] = 1 if sb["non_root_uid"] else 0
            elif rid == "S02":
                mat[row_idx, col_idx] = 1 if sb["config_isolated"] else 0
            elif rid == "S03":
                mat[row_idx, col_idx] = 1 if sb["flag_isolated"] else 0

    for r in range(len(row_items)):
        for c in range(3):
            passed = mat[r, c] == 1
            fc = "#D1F2EB" if passed else "#FADBD8"
            ec = "#117A65" if passed else "#B03A2E"
            rect = mpatches.FancyBboxPatch(
                (c + 0.06, r + 0.09),
                0.88,
                0.82,
                boxstyle="round,pad=0.02,rounding_size=0.08",
                facecolor=fc,
                edgecolor=ec,
                linewidth=0.8,
            )
            ax2.add_patch(rect)
            # Use DejaVu Sans explicitly for crisp checkmark / ballot-x glyphs
            sym = "✓" if passed else "✗"
            ax2.text(
                c + 0.5,
                r + 0.5,
                sym,
                ha="center",
                va="center",
                fontsize=8.2,
                fontweight="bold",
                fontfamily="DejaVu Sans",
                color=ec,
            )

    ax2.axhline(12.0, color="#333333", linestyle="--", linewidth=1.0)
    ax2.set_xlim(0, 3)
    ax2.set_ylim(len(row_items), 0)
    ax2.set_xticks([0.5, 1.5, 2.5])
    ax2.set_xticklabels(
        ["无白名单\n基线", "1.83.6\n默认", "MCP-Guard\n(本文)"],
        fontsize=7.3,
        fontweight="bold",
    )
    ax2.set_yticks([i + 0.5 for i in range(len(row_items))])
    ax2.set_yticklabels(
        [f"{rid} {lbl}" for rid, lbl in row_items], fontsize=6.6, fontweight="bold"
    )
    ax2.set_title("(b) 单项用例拦截与沙箱隔离矩阵", fontsize=9.0, fontweight="bold", pad=14)
    for spine in ax2.spines.values():
        spine.set_visible(False)
    ax2.tick_params(length=0)

    p_ok = mpatches.Patch(facecolor="#D1F2EB", edgecolor="#117A65", label="绿色(✓): 已拦截/已隔离")
    p_fail = mpatches.Patch(facecolor="#FADBD8", edgecolor="#B03A2E", label="红色(✗): 被绕过/未隔离")
    # Avoid missing glyph in legend by using plain Chinese labels cleanly
    p_ok = mpatches.Patch(facecolor="#D1F2EB", edgecolor="#117A65", label="已拦截 / 已隔离")
    p_fail = mpatches.Patch(facecolor="#FADBD8", edgecolor="#B03A2E", label="被绕过 / 未隔离")
    ax2.legend(
        handles=[p_ok, p_fail],
        loc="upper center",
        bbox_to_anchor=(0.5, -0.13),
        ncol=2,
        frameon=False,
        fontsize=6.9,
    )

    fig.tight_layout(w_pad=1.7)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_DIR / "fig2_security_comparison.pdf", bbox_inches="tight")
    fig.savefig(OUT_DIR / "fig2_security_comparison.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("Saved fig2_security_comparison.{pdf,png}")


def plot_latency_overhead(data: dict) -> None:
    modes = ["baseline_open", "baseline_default", "mcp_guard"]
    endpoints = [("connection", "/test/connection"), ("tools_list", "/test/tools/list")]

    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(7.4, 3.15), gridspec_kw={"width_ratios": [1.18, 1.0]}
    )

    # --- Panel (a): Benign MCP latency (Mean ± SD + P95 marker) ---
    x = np.arange(len(endpoints))
    width = 0.24
    offsets = [-width, 0.0, width]
    hatches = ["///", "...", ""]

    for idx, m in enumerate(modes):
        means = [data["modes"][m]["latency"][ep]["mean_ms"] for ep, _ in endpoints]
        stds = [data["modes"][m]["latency"][ep]["std_ms"] for ep, _ in endpoints]
        p95s = [data["modes"][m]["latency"][ep]["p95_ms"] for ep, _ in endpoints]
        fill, edge = COLORS[m]

        bars = ax1.bar(
            x + offsets[idx],
            means,
            width=width * 0.88,
            yerr=stds,
            capsize=3,
            color=fill,
            edgecolor=edge,
            linewidth=1.05,
            hatch=hatches[idx],
            error_kw={"ecolor": edge, "elinewidth": 1.0, "capthick": 1.0},
            label=MODE_LABELS[m],
            zorder=3,
        )
        ax1.scatter(
            x + offsets[idx],
            p95s,
            marker="D",
            s=22,
            color=edge,
            edgecolor="white",
            linewidth=0.6,
            zorder=5,
            label="P95 延迟" if idx == 2 else None,
        )
        for b, mean_v, p95_v in zip(bars, means, p95s):
            ax1.text(
                b.get_x() + b.get_width() / 2.0,
                p95_v + 1.5,
                f"{mean_v:.1f}",
                ha="center",
                va="bottom",
                fontsize=6.8,
                fontweight="bold",
                color=edge,
            )

    conn_delta = (
        data["modes"]["mcp_guard"]["latency"]["connection"]["mean_ms"]
        - data["modes"]["baseline_default"]["latency"]["connection"]["mean_ms"]
    )
    tools_delta = (
        data["modes"]["mcp_guard"]["latency"]["tools_list"]["mean_ms"]
        - data["modes"]["baseline_default"]["latency"]["tools_list"]["mean_ms"]
    )
    ax1.text(
        0 + width,
        54.5,
        f"(+{conn_delta:.2f} ms)",
        ha="center",
        va="bottom",
        fontsize=6.6,
        fontweight="bold",
        color="#117A65",
        bbox={"boxstyle": "round,pad=0.18", "facecolor": "#E8F8F5", "edgecolor": "#117A65", "lw": 0.7},
    )
    ax1.text(
        1 + width,
        54.5,
        f"(+{tools_delta:.2f} ms)",
        ha="center",
        va="bottom",
        fontsize=6.6,
        fontweight="bold",
        color="#117A65",
        bbox={"boxstyle": "round,pad=0.18", "facecolor": "#E8F8F5", "edgecolor": "#117A65", "lw": 0.7},
    )

    ax1.set_ylim(0, 64)
    ax1.set_xticks(x)
    ax1.set_xticklabels([lbl for _, lbl in endpoints], fontsize=8.0, fontweight="bold")
    ax1.set_ylabel("端到端响应延迟 (ms)", fontsize=8.5, fontweight="bold")
    ax1.set_title("(a) 合法 MCP 测试请求延迟对比 (n=30, 均值±标准差)", fontsize=8.5, fontweight="bold", pad=26)
    ax1.grid(axis="y", linestyle="--", alpha=0.4, zorder=0)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)
    ax1.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 1.15),
        frameon=False,
        fontsize=6.6,
        ncol=2,
        columnspacing=1.0,
        handletextpad=0.4,
    )

    # --- Panel (b): Fast-Reject vs Subprocess Execution Latency ---
    fast_mean = data["modes"]["mcp_guard"]["latency"]["fast_reject_403"]["mean_ms"]
    fast_std = data["modes"]["mcp_guard"]["latency"]["fast_reject_403"]["std_ms"]
    def_bypass_lats = [
        c["latency_ms"]
        for c in data["modes"]["baseline_default"]["security_cases"]
        if c["id"] in {"T03", "T04", "T05", "T06", "T07"}
    ]
    def_bypass_mean = float(np.mean(def_bypass_lats))
    def_bypass_std = float(np.std(def_bypass_lats, ddof=1))
    def_benign_mean = data["modes"]["baseline_default"]["latency"]["connection"]["mean_ms"]
    def_benign_std = data["modes"]["baseline_default"]["latency"]["connection"]["std_ms"]
    guard_benign_mean = data["modes"]["mcp_guard"]["latency"]["connection"]["mean_ms"]
    guard_benign_std = data["modes"]["mcp_guard"]["latency"]["connection"]["std_ms"]

    y_labels = [
        "MCP-Guard\n策略快拒(403)",
        "1.83.6 默认\n合法连接",
        "1.83.6 默认\n绕过子进程执行",
        "MCP-Guard\n合法沙箱执行",
    ]
    vals = [fast_mean, def_benign_mean, def_bypass_mean, guard_benign_mean]
    errs = [fast_std, def_benign_std, def_bypass_std, guard_benign_std]
    bar_colors = [
        COLORS["fast_reject"],
        COLORS["baseline_default"],
        COLORS["baseline_open"],
        COLORS["mcp_guard"],
    ]

    y = np.arange(len(y_labels))
    for i in range(len(y_labels)):
        fc, ec = bar_colors[i]
        ax2.barh(
            y[i],
            vals[i],
            height=0.55,
            xerr=errs[i],
            capsize=3,
            color=fc,
            edgecolor=ec,
            linewidth=1.05,
            error_kw={"ecolor": ec, "elinewidth": 1.0, "capthick": 1.0},
            zorder=3,
        )
        ax2.text(
            vals[i] + errs[i] + 1.1,
            y[i],
            f"{vals[i]:.2f} ms",
            va="center",
            ha="left",
            fontsize=7.2,
            fontweight="bold",
            color=ec,
        )

    savings_pct = (1.0 - fast_mean / def_bypass_mean) * 100.0
    # Place callout cleanly to the right of "3.20 ms" label with arrow starting from left of box
    ax2.annotate(
        f"零子进程启动\n耗时降低 {savings_pct:.1f}%",
        xy=(19.2, 0.0),
        xytext=(27.5, 0.0),
        va="center",
        ha="left",
        fontsize=6.7,
        fontweight="bold",
        color="#6C3483",
        bbox={"boxstyle": "round,pad=0.25", "facecolor": "#F5EEF8", "edgecolor": "#6C3483", "lw": 0.8},
        arrowprops={"arrowstyle": "->", "color": "#6C3483", "lw": 0.9},
    )

    ax2.set_xlim(0, 56)
    ax2.set_yticks(y)
    ax2.set_yticklabels(y_labels, fontsize=7.2, fontweight="bold")
    ax2.invert_yaxis()
    ax2.set_xlabel("平均响应延迟 (ms)", fontsize=8.5, fontweight="bold")
    ax2.set_title("(b) 恶意请求快拒与子进程执行耗时对比", fontsize=8.5, fontweight="bold", pad=14)
    ax2.grid(axis="x", linestyle="--", alpha=0.4, zorder=0)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    fig.tight_layout(w_pad=1.6)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_DIR / "fig3_latency_overhead.pdf", bbox_inches="tight")
    fig.savefig(OUT_DIR / "fig3_latency_overhead.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("Saved fig3_latency_overhead.{pdf,png}")


if __name__ == "__main__":
    d = load_data()
    plot_security_comparison(d)
    plot_latency_overhead(d)
