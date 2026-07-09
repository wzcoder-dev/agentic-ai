# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> 本文件只管 `security-guardian/` 子项目。仓库根 `agentic-ai/CLAUDE.md` 是课程总览，与本文件并存。

## 这个项目是什么

第 20 节《企业级数字员工的安全审计与生产治理》配套项目：一个面向**云端 OpenClaw** 的**上线前安全自审计控制台**。它位于 OpenClaw 与 Claude Code 之间——只读采集 OpenClaw 的真实运行证据、脱敏后放进受控工作区，调用 **Claude Code（`claude -p`）**做一次性安全判断，再把风险、告警、治理建议和 go/no-go 复检结论整理成报告。**只做审计，不改生产。**

**智能在 Claude Code 的 agent 循环里，不在脚本里。** `openclaw_security_console/app.py` 是单文件、纯 Python 标准库的 HTTP 服务（无第三方依赖，`pip install` 无对象），只负责采集/脱敏/建工作区/调 Claude/整理报告/兜底。

（本项目是课程仓库 DjangoPeng/agentic-ai 内的正本实现，无独立仓库；部署即克隆 agentic-ai 后进入 `security-guardian/` 子目录。）

## 铁律（不可违背）

1. **单向只读。** 审计链路只读取 OpenClaw，绝不写回、不改配置、不执行修复命令。检测可自动化，处置由人确认——**检测与治理解耦**。
2. **脱敏先行。** 写入 `evidence/` 的文本在复制时全文脱敏（`redact_sensitive`），`manifest.json` 标 `redacted: true`；文档/报告里出现密钥只能是占位符或脱敏片段（如 `sk-<REDACTED>`），绝不出现真实明文。敏感路径（`.ssh`/`.aws`/`identity`/`accounts`/`*.pem`/`*credential*`/`*secret*`/`*token*`）默认跳过，不进 evidence。
3. **诚实失败。** Claude 调用失败时显式标 `CC-CALL-FAILED`，`overallRisk=HIGH`，**禁止给出“安全通过”结论**。一份假的审计报告比没有报告更危险。
4. **Claude 只从 stdout 返回 JSON，报告由 Security Guardian 写入。** Claude 不写文件、不联网、不越界读工作区外路径；`report.json` / `report.md` 由 SG 依 stdout 落盘。
5. **建议已生成 ≠ 生产已治理。** 页面一排绿勾只代表“产物/建议已生成”。只有真实整改并留下 `verification` 证据才算闭环。
6. **审计工具自己也要最小权限。** 工作区从风险反推、限额抽样（默认 30 文件 / 每目录 6 / 每文件 20KB），不递归全量、不把真实密钥塞给 Claude——给多了会把审计工具自己变成新的攻击目标。

## 架构 / 数据流

```text
OpenClaw 真实文件(OPENCLAW_ROOT)
  → 只读采集 + 限额抽样 + 敏感路径跳过   collect_real_openclaw_evidence()
  → 复制到 evidence/ 时全文脱敏          copy_evidence_file() / redact_sensitive()
  → 建 run 工作区 runtime/audit_runs/<run_id>/  create_audit_run_workspace()
        manifest.json + evidence/ + audit_request.md
  → claude -p，cwd=run 目录，只读检索证据、stdout 返回 JSON   run_claude_code_audit()
  → SG 依 stdout 写 report.json / report.md            write_audit_artifacts()
  → 告警/治理建议(Claude 针对性优先，固定清单兜底) + go/no-go 复检
```

- **单向只读 + 一次性调用（one-shot）**：每次检测独立生成 `run_id`，Claude 从头读本次证据；不是把所有内容塞进一个超长 prompt，而是给一个受控证据箱。
- 状态存 `openclaw_security_console/state/state.json`（`load_state`/`save_state`，`STATE_LOCK` 保护）；`analyze-cloud` 用 `AUDIT_LOCK` 防并发（并发时返回 409 `audit already running`）。

## 调用契约（HTTP 接口）

| 方法 · 路径 | 作用 |
|---|---|
| `GET /` · `/dashboard.html` | 控制台页面 |
| `GET /api/status` | 全量状态（`public_status`，已清 rawOutput/脱敏 error） |
| `POST /api/reset` | 重置检测状态 |
| `POST /claude-code/analyze-cloud` | **核心**：采集→脱敏→建工作区→调 Claude→写报告（AUDIT_LOCK 串行） |
| `POST /claude-code/enable-monitoring` | 把 high/critical finding 转成告警规则建议 |
| `POST /guardian/seal-control-plane` | 控制面建议（关联 CC-001） |
| `POST /guardian/isolate-skill` | Skill 建议（关联 CC-003/004/005） |
| `POST /guardian/rotate-secrets` | 密钥建议（关联 CC-002） |
| `POST /guardian/apply-governance` | denyList/Token 熔断/审计建议（关联 CC-006/007/008） |
| `POST /guardian/final-audit` | 最终复检 + go/no-go 上线判决 |

**Claude 调用**：默认 `claude --permission-mode acceptEdits -p <prompt>`；`cwd` 为本次 run 目录。可用 `CLAUDE_CODE_COMMAND` 覆盖（含 `{prompt}` 时替换，否则追加为末位参数）。

**环境变量**：`OPENCLAW_ROOT`（审计对象根，默认探测 `/root/.openclaw` 等）、`CLAUDE_CODE_TIMEOUT`(300)、`CLAUDE_CODE_COMMAND`、`OPENCLAW_AUDIT_PATHS`（`;`/`,`/换行分隔补充目录）、`OPENCLAW_INCLUDE_DEFAULT_PATHS`(1)、`OPENCLAW_MAX_AUDIT_FILES`(30)、`OPENCLAW_MAX_FILES_PER_ROOT`(6)、`OPENCLAW_MAX_FILE_BYTES`(20000)、`GUARDIAN_HOST`(0.0.0.0)、`GUARDIAN_PORT`(8511)。

## 数据契约

**Claude 返回 / `report.json` 的 finding**（8 件事）：`id` / `severity`(critical|high|medium|low) / `location` / `evidence`(脱敏) / `risk` / `recommendation` / `remediationSteps[]` / `verification[]`；`summary.overallRisk` ∈ `CRITICAL|HIGH|REVIEW|CLEAN`。`normalize_finding` 会补默认值并再次脱敏 evidence。

**上线判决（`guardian_final_audit`，规则化、可解释）**：未执行检测→禁止判断；有 `critical`/`high`→暂缓上线；仅 `medium`→转人工复核；无 `OPENCLAW_ROOT` 或扫描文件数 0→审计范围不足；否则最好结果也只是“可进入受控上线前人工复核”。**永不替人签字。**

**生成产物**（均 gitignored）：`runtime/audit_runs/<run_id>/{manifest.json, evidence/, audit_request.md, report.json, report.md}`、`state/state.json`。

## 运行 / 验证

```bash
cd security-guardian
chmod +x run_dashboard.sh
OPENCLAW_ROOT=/root/.openclaw CLAUDE_CODE_TIMEOUT=300 ./run_dashboard.sh   # 0.0.0.0:8511
curl -X POST http://127.0.0.1:8511/claude-code/analyze-cloud
curl -X POST http://127.0.0.1:8511/guardian/final-audit
```

本地验证不需要真实 OpenClaw：造一个合成 `OPENCLAW_ROOT`（logs/配置/skills，埋公网监听、日志明文 Token、未签名 Skill、外传命令），点一遍端点即可。想脱离真实 `claude` 做确定性验证，把 `CLAUDE_CODE_COMMAND` 指向一个读 cwd 里 `manifest.json`、往 stdout 吐 findings JSON 的桩脚本；想验证诚实失败，把它指向一个非零退出的命令，应得到 `CC-CALL-FAILED` 且复检拒绝放行。

## 失败处理 / 已知坑

- `CC-CALL-FAILED`：Claude CLI 不可用/超时/stdout 无 JSON。**先修调用链路再重跑**，别绕过去硬解释审计结论；检查 `claude -p "只回复 ok"`、`CLAUDE_CODE_COMMAND`、登录状态。
- 扫描文件数为 0：多半 `OPENCLAW_ROOT` 指错或指到空目录。
- `audit already running`（409）：已有检测在跑（AUDIT_LOCK），等完成再触发。
- 端口证据只在 Linux 有：`collect_open_ports` 读 `/proc/net/tcp[6]`，macOS 上没有该文件属正常（无端口/WebSocket 证据），不影响其余审计。
- 预检正则（`CC-003`~`CC-008`）2026-07 修过一次 raw-string 过度转义（`\\s`→`\s` 等）；它只是给 Claude 的**内置预检提示**，真正的风险判断在 Claude。

## 改这个项目时注意

- **同步契约**：改了 Agent 面向的流程/字段/端点，`README.md`、`lesson20-lab.md`、`lesson20_architecture.md`、`checklists/` 要一起改到一致。
- **本项目没有 SKILL.md**——它是可运行控制台，不是 OpenClaw Skill，别往根 `CLAUDE.md` 的 Skill contracts 清单里加。
- **服务器路径是课程约定**：`/root/.openclaw`、`/root/projects/agentic-ai/security-guardian`、`http://<公网IP>:8511/dashboard.html` 是部署约定；截图里公网 IP 记得打码。审计页面别长期裸露公网，生产加 IP 白名单/Basic Auth/VPN/SSO。
