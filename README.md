# LiteLLM CVE-2026-42271 漏洞复现与 MCP-Guard 三层纵深修复实验仓库

本项目基于 `LiteLLM Proxy 1.83.6`（`mcp==1.26.0`），针对 MCP `stdio` 后台测试接口（`/mcp-rest/test/connection`、`/mcp-rest/test/tools/list`）的命令注入、解释器参数绕过、路径伪造及环境变量劫持风险，设计并实现了低侵入三层纵深防御框架 **MCP-Guard**，并提供完整的自动化三组对照评测与图表生成脚本。

## 目录结构

- `victim/`：原始漏洞靶机环境（`Dockerfile`、`config.yaml`、`entrypoint.sh`、`flag.txt`）
- `exploit/`：基础连接测试脚本（`exploit.py`）
- `defense/`：本文自研三层修复模块与评测代码
  - `mcp_guard.py`：核心防御框架（控制面 Host/权限校验 + 语义策略引擎 + 进程沙箱钩子）
  - `sandbox_exec.py`：OS 级轻量沙箱启动跳板（`nobody` 降权 + `PR_SET_NO_NEW_PRIVS` + `rlimit`）
  - `trusted_mcp_servers/`：注册良性 `stdio` MCP 测试服务（`echo_mcp.py`、`health_mcp.py`）
  - `run_guarded_proxy.py`、`sitecustomize.py`、`Dockerfile.guard`：非侵入式加载与容器化部署配置
  - `evaluate_benchmark.py`：三组对照（`baseline_open` / `baseline_default` / `mcp_guard`）自动化评测脚本
  - `plot_results.py`：论文矢量图表生成脚本
- `results/`：自动化评测原始输出（`benchmark_results.json`）

## 快速运行

### 1. 构建并启动 MCP-Guard 加固环境

```bash
docker build -f defense/Dockerfile.guard -t litellm-mcp-guard:latest .
docker compose -f docker-compose.guard.yml up -d
```

可通过环境变量 `MCP_GUARD_MODE` 在同一镜像内切换三组实验模式：`baseline_open`、`baseline_default`、`mcp_guard`。

### 2. 运行三组对照评测并生成论文图表

```bash
python defense/evaluate_benchmark.py
python defense/plot_results.py
```
