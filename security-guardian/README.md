# OpenClaw Security Guardian

第 20 章《企业级数字员工的安全审计与生产治理》实战项目。

Security Guardian 是一个面向云端 OpenClaw 的安全自审计控制台。它不做攻击演示，也不是一键修复器，而是把 OpenClaw 的真实日志、配置和运行证据交给 Claude Code 审查，再把 Claude 给出的风险、具体处置步骤和复核办法整理成报告、告警建议、治理建议和最终复检结论。

## 架构摘要

Security Guardian 位于 OpenClaw 和 Claude Code 之间：它只读采集 OpenClaw 的真实运行证据，复制到 evidence 前先做文本脱敏，再调用 Claude Code 做一次性安全判断。页面只展示风险、告警规则、治理建议和复检结论；真正的生产配置变更仍由人工、运维或 OpenClaw 执行官完成。

完整架构图见 [`lesson20_architecture.md`](lesson20_architecture.md)。

## 角色分工

| 模块 | 负责什么 | 不负责什么 |
|---|---|---|
| OpenClaw | 提供真实审计材料，触发检测流程 | 不把生产权限直接交给 Claude |
| Security Guardian | 采集证据、脱敏、调用 Claude、展示报告，并在 Claude 输出不足时使用兜底建议 | 不自动修改生产配置 |
| Claude Code | 基于审计包判断风险，输出 recommendation、remediationSteps、verification | 不读取真实密钥，不执行修复命令 |
| 人工 / 运维 | 根据建议执行真实治理并复核 | 不把“建议已生成”当成“已治理” |

## 审计内容

Security Guardian + Claude Code 重点检查：

- 控制面安全：公网监听、弱鉴权、Origin 校验、远程关闭安全策略
- Skill 供应链：社区来源、签名校验、敏感路径访问、网络出站
- 密钥与 Token：日志泄露、明文配置、旧 Token、轮换线索
- 工具调用：危险命令、敏感文件读取、denyList 缺失
- 网络出站：未知域名、webhook、POST 外传行为
- Token 熔断：单任务预算、每日预算、异常暴涨
- 审计追踪：工具调用日志、拒绝动作日志、审批记录

## 运行方式

前置要求：

- 云服务器已部署 OpenClaw
- 云服务器已安装并登录 Claude Code CLI
- `claude -p "请只回复 ok"` 可以正常返回

启动：

```bash
# 项目在课程仓库 DjangoPeng/agentic-ai 的 security-guardian/ 子目录
git clone https://github.com/DjangoPeng/agentic-ai.git /root/projects/agentic-ai   # 已克隆则 git -C /root/projects/agentic-ai pull
cd /root/projects/agentic-ai/security-guardian
chmod +x run_dashboard.sh
OPENCLAW_ROOT=/root/.openclaw CLAUDE_CODE_TIMEOUT=300 ./run_dashboard.sh
```

当前云端 OpenClaw 的运行根目录通常是 `/root/.openclaw`。如果你的实际目录不同，请把 `OPENCLAW_ROOT` 改成真实运行目录。`CLAUDE_CODE_TIMEOUT=300` 会给 Claude Code 留足读取 evidence 和输出 JSON 的时间。

Security Guardian 默认还会尝试只读扫描这些高价值审计目录：

```text
/root/.openclaw/logs
/root/.openclaw/cron
/root/.openclaw/agents
/root/.openclaw/extensions
/root/.openclaw/workspace/skills
/tmp/openclaw
/usr/lib/node_modules/openclaw/dist/extensions
/usr/lib/node_modules/openclaw/skills
```

如需额外指定目录，可以设置：

```bash
export OPENCLAW_AUDIT_PATHS="/root/.openclaw/logs;/tmp/openclaw"
```

默认会跳过高敏路径和文件名，例如 `identity`、`openclaw-weixin/accounts`、`.ssh`、`.aws`、`*.pem`、`*credential*`、`*secret*`、`*token*`。

为避免预检扫描过慢，预检匹配默认采用限额读取；这不影响写入 evidence 的脱敏证据副本完整性：

```bash
export OPENCLAW_MAX_AUDIT_FILES=30
export OPENCLAW_MAX_FILES_PER_ROOT=6
export OPENCLAW_MAX_FILE_BYTES=20000
```

默认优先读取最新的日志、session、cron run 和 Skill manifest，而不是递归扫描整个 `/root/.openclaw`。

默认监听：

```text
0.0.0.0:8511
```

访问（用你服务器的公网 IP）：

```text
http://<你的公网IP>:8511/dashboard.html
```

如果 Claude Code 调用方式不是默认的 `claude -p <prompt>`，可以设置：

```bash
export CLAUDE_CODE_COMMAND="claude -p"
```

## 页面流程

1. 执行真实检测：扫描 `OPENCLAW_ROOT`，生成审计包，并调用 Claude Code。
2. 生成告警规则：把 high / critical 风险整理成告警建议。
3. 生成治理建议：优先整理 Claude 针对每条证据给出的处置步骤和复核办法；Claude 输出不足时，再使用控制面、Skill、密钥、denyList、Token 熔断等兜底建议。
4. 最终复检：根据 Claude 调用状态、扫描覆盖范围和风险等级给出上线前判断。

## 生成文件

```text
openclaw_security_console/runtime/audit_runs/<run_id>/manifest.json
openclaw_security_console/runtime/audit_runs/<run_id>/evidence/
openclaw_security_console/runtime/audit_runs/<run_id>/audit_request.md
openclaw_security_console/runtime/audit_runs/<run_id>/report.md
openclaw_security_console/runtime/audit_runs/<run_id>/report.json
```

## 安全边界

- 只读检测，不主动修改 OpenClaw 生产配置。
- 疑似密钥字段会脱敏，不展示真实密钥明文。
- 写入 `evidence/` 的文本证据会在复制时脱敏，`manifest.json` 会记录 `redacted: true`。
- Claude Code 调用失败时会显示 `CC-CALL-FAILED`，不会伪造成功。
- 页面中的“建议已生成”不等于“生产已治理”。
- 同一个风险编号可能命中不同证据；Claude 的 `remediationSteps` 和 `verification` 用来体现本次证据的差异，Security Guardian 的固定建议只是兜底。
- 审计页面不建议长期裸露公网，生产环境请加 IP 白名单、Basic Auth、VPN 或企业 SSO。

## 配套文档

- `lesson20-lab.md`：课堂实验手册，给学员按步骤执行。
- `lesson20_architecture.md`：课程架构、系统逻辑和安全检查面。
- `checklists/OpenClaw生产上线安全核查表.md`：上线前人工复核清单。
