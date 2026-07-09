import copy
import json
import os
import re
import shlex
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
STATE_DIR = ROOT / "state"
STATE_FILE = STATE_DIR / "state.json"
RUNTIME_DIR = ROOT / "runtime"
RUNS_DIR = RUNTIME_DIR / "audit_runs"
STATE_LOCK = threading.RLock()
AUDIT_LOCK = threading.Lock()


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def initial_state():
    return {
        "openclaw": {
            "name": "OpenClaw",
            "mode": "real-security-audit",
        },
        "auditEvents": [],
        "guardianReports": [],
        "workflow": {
            "scan": False,
            "alertRules": False,
            "controlPlaneAdvice": False,
            "skillAdvice": False,
            "credentialAdvice": False,
            "governanceAdvice": False,
            "finalReview": False,
        },
        "cloud": {
            "server": "cloud-openclaw-prod-01",
            "publicUrl": "https://openclaw.example.internal",
            "runtime": "OpenClaw + Claude Code",
            "auditMethod": "manifest-driven workspace audit",
            "alertRulesGenerated": False,
            "logWindow": "last 24h",
            "openclawRoot": "",
            "auditRoots": [],
            "configSnapshot": {
                "openPorts": [],
                "websocketBind": "未检测",
                "skillSources": [],
                "secretStorage": "未检测",
                "auditLogEnabled": None,
                "tokenBudgetEnabled": None,
            },
            "logs": [],
            "claudeReport": None,
            "precheckFindings": [],
            "auditRunning": False,
            "auditStartedAt": "",
            "auditFinishedAt": "",
            "latestRunId": "",
            "claudeInvocation": {
                "ok": False,
                "command": "",
                "error": "",
                "prompt": "",
                "rawOutput": "",
            },
            "auditArtifacts": {
                "bundle": "",
                "promptMd": "",
                "reportMd": "",
                "reportJson": "",
                "manifest": "",
                "evidenceDir": "",
                "runDir": "",
            },
            "monitorAlerts": [],
        },
        "finalAudit": None,
    }


def merge_missing(target, defaults):
    for key, value in defaults.items():
        if key not in target:
            target[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(target.get(key), dict):
            merge_missing(target[key], value)
    return target


def normalize_state(state):
    normalized = merge_missing(state, initial_state())
    if "monitoringEnabled" in normalized.get("cloud", {}):
        normalized["cloud"]["alertRulesGenerated"] = bool(normalized["cloud"].pop("monitoringEnabled"))
    return normalized


def load_state():
    with STATE_LOCK:
        if not STATE_FILE.exists():
            state = initial_state()
            save_state(state)
            return state
        try:
            return normalize_state(json.loads(STATE_FILE.read_text(encoding="utf-8")))
        except Exception:
            state = initial_state()
            save_state(state)
            return state


def save_state(state):
    with STATE_LOCK:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp_path = STATE_FILE.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(STATE_FILE)


def add_event(state, action, target, allowed, risk="low", detail=""):
    event = {
        "time": now(),
        "action": redact_sensitive(str(action))[:120],
        "target": redact_sensitive(str(target))[:240],
        "allowed": allowed,
        "risk": risk,
        "detail": redact_sensitive(str(detail))[:500],
    }
    state["auditEvents"].insert(0, event)
    state["auditEvents"] = state["auditEvents"][:80]


def add_report(state, title, lines):
    report = {"time": now(), "title": title, "lines": lines}
    state["guardianReports"].insert(0, report)
    state["guardianReports"] = state["guardianReports"][:20]
    return report


SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(['\"]?\b(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|secret|api[_-]?key|apikey|password|passwd|private[_-]?key|authorization|auth)\b['\"]?\s*[:=]\s*)(['\"]?)[^'\"\s,}]+"
)
AUTH_BEARER_RE = re.compile(r"(?i)\b(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/=-]+")
BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
PRIVATE_KEY_BLOCK_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
QUERY_SECRET_RE = re.compile(r"(?i)([?&](?:token|access_token|refresh_token|api_key|apikey|password|secret)=)[^&\s]+")


def redact_sensitive(text):
    text = PRIVATE_KEY_BLOCK_RE.sub("<PRIVATE_KEY_BLOCK_REDACTED>", text)
    text = AUTH_BEARER_RE.sub(lambda m: f"{m.group(1)}<REDACTED>", text)
    text = BEARER_RE.sub(lambda m: f"{m.group(1)}<REDACTED>", text)
    text = SENSITIVE_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<REDACTED>", text)
    text = OPENAI_KEY_RE.sub("sk-<REDACTED>", text)
    text = AWS_ACCESS_KEY_RE.sub("<AWS_ACCESS_KEY_REDACTED>", text)
    text = QUERY_SECRET_RE.sub(lambda m: f"{m.group(1)}<REDACTED>", text)
    return text

def find_openclaw_root():
    env_root = os.getenv("OPENCLAW_ROOT", "").strip()
    candidates = []
    if env_root:
        candidates.append(Path(env_root))
    candidates.extend(
        [
            Path("/root/.openclaw"),
            Path("/root/projects/OpenClaw"),
            Path("/root/projects/openclaw"),
            Path("/root/projects/Openclaw"),
            Path("/root/projects"),
            ROOT.parent,
        ]
    )
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            if candidate.name.lower() == "security-guardian":
                continue
            return candidate.resolve()
    return None


def split_env_paths(value):
    parts = re.split(r"[;,\n]", value or "")
    return [Path(item.strip()) for item in parts if item.strip()]


def env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def default_audit_roots(root):
    roots = []
    if root:
        if root.name == ".openclaw":
            roots.extend(
                [
                    root / "openclaw.json",
                    root / "logs",
                    root / "cron" / "runs",
                    root / "agents",
                    root / "extensions",
                    root / "workspace" / "skills",
                ]
            )
        else:
            roots.append(root)
    roots.extend(split_env_paths(os.getenv("OPENCLAW_AUDIT_PATHS", "")))

    defaults = [
        Path("/root/.openclaw/logs"),
        Path("/root/.openclaw/cron/runs"),
        Path("/root/.openclaw/agents"),
        Path("/root/.openclaw/extensions"),
        Path("/root/.openclaw/workspace/skills"),
        Path("/tmp/openclaw"),
        Path("/usr/lib/node_modules/openclaw/dist/extensions"),
        Path("/usr/lib/node_modules/openclaw/skills"),
    ]
    if os.getenv("OPENCLAW_INCLUDE_DEFAULT_PATHS", "1").strip().lower() not in {"0", "false", "no"}:
        roots.extend(defaults)

    resolved = []
    seen = set()
    for item in roots:
        try:
            path = item.expanduser().resolve()
        except Exception:
            continue
        if not path.exists() or not (path.is_dir() or path.is_file()):
            continue
        if str(path) in seen:
            continue
        seen.add(str(path))
        resolved.append(path)
    return resolved


SENSITIVE_PATH_PARTS = {
    "identity",
    "openclaw-weixin",
    "accounts",
    ".ssh",
    ".aws",
}

SENSITIVE_FILE_PATTERNS = re.compile(r"(?i)(\.pem$|id_rsa|private[_-]?key|credential|credentials|secret|token)")


def should_skip_audit_path(path):
    parts = {part.lower() for part in path.parts}
    if parts & SENSITIVE_PATH_PARTS:
        return True
    return bool(SENSITIVE_FILE_PATTERNS.search(path.name))


def parse_proc_net_tcp(path):
    ports = []
    proc = Path(path)
    if not proc.exists():
        return ports
    try:
        lines = proc.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
    except Exception:
        return ports
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A":
            continue
        local = parts[1]
        addr_hex, port_hex = local.split(":")
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        if path.endswith("tcp6"):
            bind = "::" if set(addr_hex) == {"0"} else "tcp6"
        else:
            bind = "0.0.0.0" if addr_hex == "00000000" else "127.0.0.1" if addr_hex == "0100007F" else "tcp"
        ports.append({"port": port, "bind": bind})
    return ports


def collect_open_ports():
    ports = parse_proc_net_tcp("/proc/net/tcp") + parse_proc_net_tcp("/proc/net/tcp6")
    seen = set()
    result = []
    for item in ports:
        key = (item["bind"], item["port"])
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return sorted(result, key=lambda x: x["port"])


def safe_read_text(path, max_bytes=None):
    if max_bytes is None:
        max_bytes = env_int("OPENCLAW_MAX_FILE_BYTES", 20_000)
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def sort_recent(paths):
    def mtime(path):
        try:
            return path.stat().st_mtime
        except Exception:
            return 0

    return sorted(paths, key=mtime, reverse=True)


def candidate_files_for_target(target, allowed_suffixes):
    if target.is_file():
        return [target]

    name = target.name.lower()
    target_text = str(target).lower().replace("\\", "/")
    patterns = []
    recursive = False

    if "agents" in target_text:
        patterns = ["*/sessions/*.jsonl"]
    elif name == "runs" or "cron" in target_text:
        patterns = ["*.jsonl", "runs/*.jsonl"]
    elif name in {"logs", "openclaw"} or target_text.endswith("/tmp/openclaw"):
        patterns = ["*"]
    elif "extensions" in target_text or "skills" in target_text:
        patterns = ["*/openclaw.plugin.json", "*/SKILL.md", "*/_meta.json", "*/.clawhub/origin.json"]
        recursive = True
    else:
        recursive = True

    candidates = []
    for pattern in patterns:
        candidates.extend(target.glob(pattern))
    if recursive and not candidates:
        candidates.extend(target.rglob("*"))

    return [path for path in sort_recent(candidates) if path.is_file() and path.suffix.lower() in allowed_suffixes]


def iter_audit_files(roots):
    if not roots:
        return []
    allowed_suffixes = {".log", ".txt", ".json", ".jsonl", ".yml", ".yaml", ".toml", ".conf", ".md"}
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "site-packages"}
    max_files = env_int("OPENCLAW_MAX_AUDIT_FILES", 30)
    max_files_per_root = env_int("OPENCLAW_MAX_FILES_PER_ROOT", 6)
    files = []
    seen = set()
    for root in roots:
        try:
            root_count = 0
            for path in candidate_files_for_target(root, allowed_suffixes):
                if len(files) >= max_files or root_count >= max_files_per_root:
                    break
                if any(part in skip_dirs for part in path.parts):
                    continue
                if should_skip_audit_path(path):
                    continue
                if not path.is_file() or path.suffix.lower() not in allowed_suffixes:
                    continue
                try:
                    resolved = path.resolve()
                    if str(resolved) in seen:
                        continue
                    if path.stat().st_size > 2_000_000:
                        continue
                except Exception:
                    continue
                seen.add(str(resolved))
                files.append(path)
                root_count += 1
        except Exception:
            continue
    return files


def relative_location(path, roots):
    for root in sorted(roots, key=lambda item: len(str(item)), reverse=True):
        try:
            if root.is_file() and path.resolve() == root.resolve():
                return root.name
            return f"{root.name}/{path.relative_to(root)}"
        except ValueError:
            continue
    return str(path)


def evidence_event(source, level, message):
    return {"time": now(), "source": source, "level": level, "message": redact_sensitive(message)[:500]}


def collect_real_openclaw_evidence():
    root = find_openclaw_root()
    audit_roots = default_audit_roots(root)
    ports = collect_open_ports()
    open_ports = [f"{item['bind']}:{item['port']}/tcp" for item in ports]
    logs = []
    findings = []
    skill_sources = set()
    audit_log_enabled = None
    token_budget_enabled = None
    secret_storage = "未发现明文密钥证据"
    websocket_bind = "未检测"

    for item in ports:
        if item["port"] in {7070, 7071, 8080, 8511}:
            if item["port"] == 7070:
                websocket_bind = f"{item['bind']}:{item['port']}"
            if item["bind"] in {"0.0.0.0", "::"} and item["port"] == 7070:
                logs.append(evidence_event("proc-net", "critical", f"OpenClaw control-plane candidate listens on {item['bind']}:{item['port']}"))

    files = iter_audit_files(audit_roots)
    if not root:
        logs.append(evidence_event("auditor", "warn", "未找到 OpenClaw 根目录。请设置 OPENCLAW_ROOT 指向真实 OpenClaw 运行目录，例如 /root/.openclaw。"))
        findings.append(
            {
                "id": "CC-000",
                "severity": "high",
                "location": "OPENCLAW_ROOT",
                "evidence": "未配置 OPENCLAW_ROOT，且未发现明确 OpenClaw 运行目录",
                "risk": "审计范围不明确，Claude Code 无法确认是否覆盖真实生产 OpenClaw。",
                "recommendation": "启动 Security Guardian 前设置 OPENCLAW_ROOT=/root/.openclaw，并按需设置 OPENCLAW_AUDIT_PATHS 后重新执行审计。",
            }
        )

    patterns = [
        ("CC-001", "critical", "control-plane", re.compile(r"(?i)(0\.0\.0\.0|::).{0,40}(7070|websocket|control|ws)"), "控制面疑似暴露在公网监听地址。", "将控制面限制到内网/VPN，启用强鉴权和 Origin 校验。"),
        ("CC-002", "critical", "token-in-log", re.compile(r"(?i)(token|access_token|authorization).{0,20}(=|:).{4,}"), "日志中疑似出现 Token 或鉴权信息。", "立即吊销相关 Token，禁止 URL 查询串携带凭证，并脱敏日志。"),
        ("CC-003", "high", "unsigned-skill", re.compile(r"(?i)(community|market|skill).{0,80}(unsigned|signature\s*[:=]\s*false|未签名|未校验)"), "社区 Skill 可能未经过签名或来源校验。", "启用 Skill 签名校验，未签名 Skill 不允许进入生产。"),
        ("CC-004", "critical", "sensitive-path", re.compile(r"(?i)(/secrets|\.env|id_rsa|credentials|finance|密钥|私钥).{0,80}(read|request|access|读取|请求|访问)"), "日志显示存在读取敏感目录或敏感文件的行为。", "限制文件访问边界，敏感目录需要审批或默认拒绝。"),
        ("CC-005", "critical", "egress", re.compile(r"(?i)(curl\s+--data|wget\s+--post|POST\s+http|webhook|外传|出站)"), "日志显示存在可疑网络出站或外传行为。", "默认拒绝出站网络，只允许白名单 API。"),
        ("CC-006", "high", "token-spike", re.compile(r"(?i)(token).{0,40}(spike|surge|暴涨|超限|[1-9][0-9]{5,})"), "Token 用量可能异常增长。", "配置单任务和每日 Token 熔断，超限暂停并告警。"),
        ("CC-007", "medium", "denylist-empty", re.compile(r"(?i)(denyList|deny_list|黑名单).{0,40}(empty|\[\]|空|false)"), "高危命令或敏感文件 denyList 可能未配置。", "启用 denyList，覆盖外传、删除、读取密钥等高危模式。"),
        ("CC-008", "medium", "audit-disabled", re.compile(r"(?i)(auditLog|audit_log|审计).{0,40}(false|disabled|关闭)"), "审计日志可能未启用。", "启用工具调用、拒绝动作和网络请求审计。"),
    ]

    seen_findings = set()
    for path in files:
        rel = relative_location(path, audit_roots)
        content = safe_read_text(path)
        if not content:
            continue
        low = content.lower()
        if "community-market" in low or "community" in low:
            skill_sources.add("community-market")
        if "official" in low:
            skill_sources.add("official")
        if re.search(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^'\"\s]+", content):
            secret_storage = "发现疑似明文凭证配置，已脱敏"
        if re.search(r"(?i)(auditLog|audit_log).{0,40}(true|enabled|开启)", content):
            audit_log_enabled = True
        if re.search(r"(?i)(auditLog|audit_log).{0,40}(false|disabled|关闭)", content):
            audit_log_enabled = False
        if re.search(r"(?i)(tokenBudget|token_budget|熔断).{0,40}(true|enabled|开启)", content):
            token_budget_enabled = True
        if re.search(r"(?i)(tokenBudget|token_budget|熔断).{0,40}(false|disabled|关闭)", content):
            token_budget_enabled = False
        for fid, severity, source, regex, risk, recommendation in patterns:
            match = regex.search(content)
            if not match:
                continue
            key = (fid, rel)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            line = next((line.strip() for line in content.splitlines() if regex.search(line)), match.group(0))
            redacted = redact_sensitive(line)
            logs.append(evidence_event(rel, severity, redacted))
            findings.append(
                {
                    "id": fid,
                    "severity": severity,
                    "location": rel,
                    "evidence": redacted,
                    "risk": risk,
                    "recommendation": recommendation,
                }
            )

    if not findings and root:
        logs.append(evidence_event("auditor", "warn", f"已扫描 {len(files)} 个审计文件，未命中内置高危模式。"))

    return {
        "root": str(root) if root else "",
        "audit_roots": [str(item) for item in audit_roots],
        "open_ports": open_ports,
        "websocket_bind": websocket_bind,
        "skill_sources": sorted(skill_sources),
        "secret_storage": secret_storage,
        "audit_log_enabled": audit_log_enabled,
        "token_budget_enabled": token_budget_enabled,
        "logs": logs[:80],
        "findings": findings[:40],
        "scanned_files": len(files),
        "files": [str(path) for path in files],
    }


def safe_relative_to_root(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def sanitize_evidence_part(value):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value).strip())
    return cleaned[:80] or "item"


def evidence_relative_path(path, roots):
    rel = relative_location(path, roots).replace("\\", "/")
    parts = [sanitize_evidence_part(part) for part in rel.split("/") if part]
    if not parts:
        parts = [sanitize_evidence_part(path.name)]
    return Path(*parts)


def copy_evidence_file(source_text, evidence_dir, audit_roots):
    try:
        source = Path(source_text)
        if not source.is_file() or should_skip_audit_path(source):
            return None
        rel_path = evidence_relative_path(source, audit_roots)
        dest = evidence_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        original_bytes = source.stat().st_size
        content = source.read_text(encoding="utf-8", errors="ignore")
        if not content and original_bytes:
            return {
                "source": str(source),
                "error": "无法按文本读取，未复制到 evidence。",
                "redacted": True,
            }
        redacted = redact_sensitive(content)
        dest.write_text(redacted, encoding="utf-8")
        return {
            "source": str(source),
            "evidencePath": str(dest.relative_to(evidence_dir.parent)).replace("\\", "/"),
            "bytes": dest.stat().st_size,
            "sourceBytes": original_bytes,
            "redacted": True,
        }
    except Exception as exc:
        return {
            "source": str(source_text),
            "error": str(exc),
            "redacted": True,
        }

def create_audit_run_workspace(state, evidence):
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{int(time.time() * 1000) % 1000:03d}"
    run_dir = RUNS_DIR / run_id
    evidence_dir = run_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    audit_roots = [Path(item) for item in evidence.get("audit_roots", [])]
    evidence_files = []
    for source in evidence.get("files", []):
        copied = copy_evidence_file(source, evidence_dir, audit_roots)
        if copied:
            evidence_files.append(copied)

    manifest = {
        "runId": run_id,
        "generatedAt": now(),
        "mode": "manifest-driven workspace audit",
        "target": state["cloud"]["server"],
        "runtime": state["cloud"]["runtime"],
        "openclawRoot": evidence["root"],
        "auditRoots": evidence["audit_roots"],
        "allowedRoots": ["evidence"],
        "writeTargets": [],
        "denyPatterns": [".ssh", ".aws", "id_rsa", "private_key", "credentials", ".env"],
        "redaction": {
            "enabled": True,
            "method": "copy-time full-text redaction",
        },
        "rules": [
            "只读取 evidence/ 下的文件和 manifest.json。",
            "evidence/ 内文件已由 Security Guardian 在复制时脱敏；不要把脱敏占位符当成真实密钥。",
            "不要修改 evidence/，不要执行修复动作。",
            "不要联网，不要读取本次审计工作区之外的路径。",
            "发现疑似密钥时只报告位置和脱敏片段，不输出真实密钥明文。",
            "最终只在 stdout 输出 JSON 对象；Security Guardian 会负责写入 report.json 和 report.md。",
        ],
        "configSnapshot": state["cloud"]["configSnapshot"],
        "precheckLogs": evidence["logs"],
        "precheckFindings": evidence["findings"],
        "evidenceFiles": evidence_files,
        "expectedSchema": {
            "summary": {
                "overallRisk": "CRITICAL | HIGH | REVIEW | CLEAN",
                "findingCount": 0,
                "scannedFiles": 0,
                "openclawRoot": "...",
            },
            "findings": [
                {
                    "id": "CC-001",
                    "severity": "critical | high | medium | low",
                    "location": "evidence/...",
                    "evidence": "脱敏证据",
                    "risk": "影响说明",
                    "recommendation": "一句话结论",
                    "remediationSteps": ["基于该证据的具体处置步骤 1"],
                    "verification": ["完成处置后要检查的证据 1"],
                }
            ],
            "recommendedOrder": ["处置顺序 1"],
        },
    }

    manifest_path = run_dir / "manifest.json"
    prompt_path = run_dir / "audit_request.md"
    report_path = run_dir / "report.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    state["cloud"]["latestRunId"] = run_id
    state["cloud"]["auditArtifacts"] = {
        **state["cloud"].get("auditArtifacts", {}),
        "bundle": safe_relative_to_root(manifest_path),
        "manifest": safe_relative_to_root(manifest_path),
        "evidenceDir": safe_relative_to_root(evidence_dir),
        "runDir": safe_relative_to_root(run_dir),
        "promptMd": safe_relative_to_root(prompt_path),
        "reportJson": safe_relative_to_root(report_path),
    }
    return run_dir, manifest_path, prompt_path, report_path

def write_audit_artifacts(state, report, run_dir=None):
    target_dir = run_dir or RUNTIME_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    if run_dir:
        report_json_path = target_dir / "report.json"
        report_md_path = target_dir / "report.md"
    else:
        report_json_path = target_dir / "security_audit_report.json"
        report_md_path = target_dir / "security_audit_report.md"

    report_json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    md_lines = [
        "# OpenClaw Claude Code 安全审计报告",
        "",
        f"- 审计目标：{report['target']}",
        f"- 云服务器：{report['server']}",
        f"- 调用方式：{state['cloud']['auditMethod']}",
        f"- 日志窗口：{report['logWindow']}",
        f"- 整体风险：{report['summary']['overallRisk']}",
        "",
        "## 风险发现",
        "",
    ]
    for item in report["findings"]:
        remediation_steps = item.get("remediationSteps") or []
        verification = item.get("verification") or []
        md_lines.extend(
            [
                f"### {item['id']}｜{item['severity']}",
                "",
                f"- 位置：{item['location']}",
                f"- 证据：{item['evidence']}",
                f"- 影响：{item['risk']}",
                f"- 建议：{item['recommendation']}",
            ]
        )
        if remediation_steps:
            md_lines.append("- 具体处置：")
            md_lines.extend([f"  - {line}" for line in remediation_steps])
        if verification:
            md_lines.append("- 复核方式：")
            md_lines.extend([f"  - {line}" for line in verification])
        md_lines.append("")
    md_lines.extend(["## 建议处置顺序", ""])
    md_lines.extend([f"{line}" for line in report["recommendedOrder"]])
    report_md_path.write_text("\n".join(md_lines), encoding="utf-8")

    state["cloud"]["auditArtifacts"] = {
        **state["cloud"]["auditArtifacts"],
        "reportMd": safe_relative_to_root(report_md_path),
        "reportJson": safe_relative_to_root(report_json_path),
    }

def build_claude_prompt(manifest_path, report_path):
    manifest_name = manifest_path.name
    return f"""你现在是 Claude Code，正在被 OpenClaw Security Guardian 以受控审计模式调用。

当前工作目录就是本次审计 run 目录。请先读取 {manifest_name}，然后只在 manifest.allowedRoots 声明的 evidence/ 目录内查找证据。

硬性要求：
1. 不要把 prompt 当作完整证据，真实证据在 evidence/ 和 {manifest_name} 里。
2. 可以使用只读检索/读取动作来定位证据，例如 rg、读取文件片段、查看 manifest；不要修改 evidence/。
3. 不要联网，不要读取本次审计工作区之外的路径，不要执行修复动作。
4. 发现疑似密钥、Token、私钥时，只报告位置和脱敏片段，不要输出真实明文。
5. 每个 finding 都要给出针对该证据的 recommendation、remediationSteps 和 verification，不要只输出通用模板。
6. 如果审计范围不足，请在 finding 或 recommendedOrder 中明确指出缺少什么。
7. 不要写文件；必须只在 stdout 输出一个 JSON 对象，不要输出 Markdown 前后缀。Security Guardian 会负责写入 report.json 和 report.md。

JSON 结构必须是：
{{
  "summary": {{
    "overallRisk": "CRITICAL | HIGH | REVIEW | CLEAN",
    "findingCount": 0,
    "scannedFiles": 0,
    "openclawRoot": "..."
  }},
  "findings": [
    {{
      "id": "CC-001",
      "severity": "critical | high | medium | low",
      "location": "evidence/...",
      "evidence": "脱敏证据",
      "risk": "影响说明",
      "recommendation": "一句话结论",
      "remediationSteps": [
        "基于该证据的具体处置步骤 1"
      ],
      "verification": [
        "完成处置后要检查的证据 1"
      ]
    }}
  ],
  "recommendedOrder": [
    "处置顺序 1"
  ]
}}
"""

def claude_command_args(prompt):
    configured = os.getenv("CLAUDE_CODE_COMMAND", "").strip()
    if configured:
        if "{prompt}" in configured:
            return shlex.split(configured.replace("{prompt}", shlex.quote(prompt)))
        return [*shlex.split(configured), prompt]
    return ["claude", "--permission-mode", "acceptEdits", "-p", prompt]


def extract_json_object(text):
    match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if match:
        return match.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return ""
    return text[start : end + 1]


def list_of_strings(value, limit=8):
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        text = redact_sensitive(str(item).strip())
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def normalize_finding(item, idx):
    if not isinstance(item, dict):
        item = {"evidence": str(item)}
    severity = str(item.get("severity", "medium")).lower()
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "medium"
    return {
        "id": str(item.get("id") or f"CC-{idx:03d}"),
        "severity": severity,
        "location": str(item.get("location") or "未标明位置"),
        "evidence": redact_sensitive(str(item.get("evidence") or "Claude Code 未返回证据")),
        "risk": str(item.get("risk") or "Claude Code 未返回影响说明"),
        "recommendation": str(item.get("recommendation") or "请人工复核该风险。"),
        "remediationSteps": list_of_strings(item.get("remediationSteps") or item.get("remediation_steps")),
        "verification": list_of_strings(item.get("verification") or item.get("verificationSteps") or item.get("verification_steps")),
    }


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def report_from_claude_json(parsed, state, evidence, raw_output):
    if not isinstance(parsed, dict):
        parsed = {}
    findings = [normalize_finding(item, idx + 1) for idx, item in enumerate(parsed.get("findings") or [])]
    summary = parsed.get("summary") or {}
    overall_risk = str(summary.get("overallRisk") or "").upper()
    if overall_risk not in {"CRITICAL", "HIGH", "REVIEW", "CLEAN"}:
        if any(item["severity"] == "critical" for item in findings):
            overall_risk = "CRITICAL"
        elif any(item["severity"] == "high" for item in findings):
            overall_risk = "HIGH"
        elif findings:
            overall_risk = "REVIEW"
        else:
            overall_risk = "CLEAN"
    return {
        "time": now(),
        "auditor": "Claude Code",
        "target": state["cloud"]["runtime"],
        "server": state["cloud"]["server"],
        "auditMethod": state["cloud"]["auditMethod"],
        "logWindow": state["cloud"]["logWindow"],
        "summary": {
            "criticalLogs": sum(1 for item in state["cloud"]["logs"] if item["level"] == "critical"),
            "warnLogs": sum(1 for item in state["cloud"]["logs"] if item["level"] == "warn"),
            "findingCount": safe_int(summary.get("findingCount"), len(findings)),
            "overallRisk": overall_risk,
            "scannedFiles": safe_int(summary.get("scannedFiles"), evidence["scanned_files"]),
            "openclawRoot": str(summary.get("openclawRoot") or evidence["root"]),
        },
        "findings": findings,
        "recommendedOrder": [str(item) for item in (parsed.get("recommendedOrder") or [])],
    }


def report_from_claude_failure(state, evidence, error, raw_output=""):
    return {
        "time": now(),
        "auditor": "Claude Code",
        "target": state["cloud"]["runtime"],
        "server": state["cloud"]["server"],
        "auditMethod": state["cloud"]["auditMethod"],
        "logWindow": state["cloud"]["logWindow"],
        "summary": {
            "criticalLogs": sum(1 for item in state["cloud"]["logs"] if item["level"] == "critical"),
            "warnLogs": sum(1 for item in state["cloud"]["logs"] if item["level"] == "warn"),
            "findingCount": 1,
            "overallRisk": "HIGH",
            "scannedFiles": evidence["scanned_files"],
            "openclawRoot": evidence["root"],
        },
        "findings": [
            {
                "id": "CC-CALL-FAILED",
                "severity": "high",
                "location": "Claude Code CLI",
                "evidence": redact_sensitive(error),
                "risk": "未成功调用 Claude Code，当前无法生成可信的 Claude 审计结论。",
                "recommendation": "在云服务器安装并登录 Claude Code CLI，或设置 CLAUDE_CODE_COMMAND 后重新执行真实检测。",
            }
        ],
        "recommendedOrder": [
            "1. 先修复 Claude Code 调用链路。",
            "2. 确认 OPENCLAW_ROOT 指向真实 OpenClaw 目录。",
            "3. 重新执行 Security Guardian 真实检测。",
        ],
    }


def run_claude_code_audit(state, evidence, run_dir, manifest_path, prompt_path, report_path):
    prompt = build_claude_prompt(manifest_path, report_path)
    prompt_path.write_text(prompt, encoding="utf-8")
    state["cloud"]["auditArtifacts"]["promptMd"] = safe_relative_to_root(prompt_path)

    timeout = int(os.getenv("CLAUDE_CODE_TIMEOUT", "300"))
    args = claude_command_args(prompt)
    state["cloud"]["claudeInvocation"] = {
        "ok": False,
        "command": " ".join(args[:2]) if args else "",
        "error": "",
        "prompt": safe_relative_to_root(prompt_path),
        "rawOutput": "",
    }
    try:
        completed = subprocess.run(
            args,
            cwd=str(run_dir),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        error = f"未找到 Claude Code 命令：{args[0] if args else 'claude'}。{exc}"
        state["cloud"]["claudeInvocation"]["error"] = error
        return report_from_claude_failure(state, evidence, error)
    except subprocess.TimeoutExpired:
        error = f"Claude Code 调用超时：超过 {timeout} 秒。"
        state["cloud"]["claudeInvocation"]["error"] = error
        return report_from_claude_failure(state, evidence, error)
    except Exception as exc:
        error = f"Claude Code 调用异常：{exc}"
        state["cloud"]["claudeInvocation"]["error"] = error
        return report_from_claude_failure(state, evidence, error)

    raw_output = (completed.stdout or "").strip()
    raw_error = (completed.stderr or "").strip()
    state["cloud"]["claudeInvocation"]["rawOutput"] = redact_sensitive(raw_output[:8000])
    if completed.returncode != 0:
        error = f"Claude Code 返回非零退出码 {completed.returncode}：{raw_error or raw_output}"
        state["cloud"]["claudeInvocation"]["error"] = redact_sensitive(error)
        return report_from_claude_failure(state, evidence, error, raw_output)

    json_text = extract_json_object(raw_output)
    if not json_text:
        error = "Claude Code 已返回内容，但没有输出可解析的 JSON 对象。"
        state["cloud"]["claudeInvocation"]["error"] = error
        return report_from_claude_failure(state, evidence, error, raw_output)
    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as exc:
        error = f"Claude Code JSON 解析失败：{exc}"
        state["cloud"]["claudeInvocation"]["error"] = error
        return report_from_claude_failure(state, evidence, error, raw_output)

    state["cloud"]["claudeInvocation"]["ok"] = True
    return report_from_claude_json(parsed, state, evidence, raw_output)



def compute_risk(state):
    findings = get_findings(state)
    if not state["cloud"].get("claudeReport"):
        return "待检测"
    if any(item.get("severity") == "critical" for item in findings):
        return "CRITICAL"
    if any(item.get("severity") == "high" for item in findings):
        return "HIGH"
    if any(item.get("severity") == "medium" for item in findings):
        return "REVIEW"
    return "未发现高危"


def public_status(state):
    out = copy.deepcopy(state)
    out["riskLevel"] = compute_risk(state)
    out["cloud"]["auditRunning"] = bool(out["cloud"].get("auditRunning")) or AUDIT_LOCK.locked()
    cloud = out.get("cloud", {})
    cloud["logs"] = []
    cloud.pop("logSummary", None)
    invocation = out.get("cloud", {}).get("claudeInvocation") or {}
    invocation["rawOutput"] = ""
    if invocation.get("error"):
        invocation["error"] = redact_sensitive(str(invocation["error"]))[:1000]
    report = out.get("cloud", {}).get("claudeReport")
    if isinstance(report, dict):
        report.pop("rawOutput", None)
    return out


def get_findings(state):
    report = state["cloud"].get("claudeReport") or {}
    return list(report.get("findings") or [])


def findings_by_ids(state, prefixes):
    prefixes = tuple(prefixes)
    return [item for item in get_findings(state) if str(item.get("id", "")).startswith(prefixes)]


def finding_list_values(findings, key, limit=8):
    values = []
    for item in findings:
        for value in item.get(key) or []:
            text = str(value).strip()
            if text and text not in values:
                values.append(text)
            if len(values) >= limit:
                return values
    return values


def make_advice_lines(state, title, related, fallback, actions, evidence_required):
    lines = [f"建议主题：{title}", "说明：以下为基于真实审计证据生成的建议，不会自动修改 OpenClaw 生产配置。"]
    if related:
        lines.append("关联风险：")
        for item in related[:6]:
            lines.append(f"- {item['id']} {item['severity'].upper()}｜{item['location']}｜{item['risk']}")
    else:
        lines.append(f"当前审计包未命中直接证据：{fallback}")
    claude_steps = finding_list_values(related, "remediationSteps")
    claude_verification = finding_list_values(related, "verification")
    if claude_steps:
        lines.append("Claude 针对性处置建议：")
        lines.extend([f"- {item}" for item in claude_steps])
        lines.append("治理兜底动作：")
    else:
        lines.append("建议动作：")
    lines.extend([f"- {item}" for item in actions])
    if claude_verification:
        lines.append("Claude 复核证据：")
        lines.extend([f"- {item}" for item in claude_verification])
        lines.append("通用复核证据：")
    else:
        lines.append("复核证据：")
    lines.extend([f"- {item}" for item in evidence_required])
    return lines


def claude_code_analyze_cloud(state):
    evidence = collect_real_openclaw_evidence()
    state["workflow"]["scan"] = True
    state["cloud"]["openclawRoot"] = evidence["root"]
    state["cloud"]["auditRoots"] = evidence["audit_roots"]
    state["cloud"]["logs"] = evidence["logs"]
    state["cloud"]["precheckFindings"] = evidence["findings"]
    state["cloud"]["configSnapshot"] = {
        "openPorts": evidence["open_ports"],
        "websocketBind": evidence["websocket_bind"],
        "skillSources": evidence["skill_sources"],
        "secretStorage": evidence["secret_storage"],
        "auditLogEnabled": evidence["audit_log_enabled"],
        "tokenBudgetEnabled": evidence["token_budget_enabled"],
    }

    state["cloud"]['auditMethod'] = "manifest-driven workspace audit"
    run_dir, manifest_path, prompt_path, report_path = create_audit_run_workspace(state, evidence)
    report = run_claude_code_audit(state, evidence, run_dir, manifest_path, prompt_path, report_path)
    if not report["recommendedOrder"]:
        report["recommendedOrder"] = [
            "1. 优先处理 critical/high 风险发现。",
            "2. 处理后重新执行 Security Guardian 真实检测。",
            "3. 用最终复检结论判断是否进入上线前人工复核。",
        ]
    state["cloud"]["claudeReport"] = report
    write_audit_artifacts(state, report, run_dir)

    lines = [
        f"审计目标：{report['target']} on {report['server']}",
        f"调用方式：{report['auditMethod']}",
        f"Claude 调用：{'成功' if state['cloud']['claudeInvocation']['ok'] else '失败'}",
        f"日志窗口：{report['logWindow']}",
        f"OpenClaw 根目录：{evidence['root'] or '未找到，请设置 OPENCLAW_ROOT'}",
        f"审计目录数：{len(evidence['audit_roots'])}",
        f"扫描文件数：{evidence['scanned_files']}",
        f"发现数量：{len(report['findings'])}；整体风险：{report['summary']['overallRisk']}",
        f"审计清单：{state['cloud']['auditArtifacts']['manifest']}",
        f"Claude Prompt：{state['cloud']['auditArtifacts']['promptMd']}",
        f"Markdown 报告：{state['cloud']['auditArtifacts']['reportMd']}",
        f"JSON 报告：{state['cloud']['auditArtifacts']['reportJson']}",
    ]
    if state["cloud"]["claudeInvocation"]["error"]:
        lines.append(f"Claude 调用错误：{state['cloud']['claudeInvocation']['error']}")
    for item in report["findings"]:
        lines.append(f"{item['id']} {item['severity'].upper()}｜位置：{item['location']}｜证据：{item['evidence']}")
        lines.append(f"建议：{item['recommendation']}")
    add_event(state, "claude_code_log_audit", state["cloud"]["server"], state["cloud"]["claudeInvocation"]["ok"], "high")
    return add_report(state, "Claude Code 云端日志审计报告", lines)

def claude_code_enable_monitoring(state):
    state["cloud"]["alertRulesGenerated"] = True
    state["workflow"]["alertRules"] = True
    findings = (state["cloud"].get("claudeReport") or {}).get("findings", [])
    alerts = []
    for item in findings:
        if item["severity"] not in {"critical", "high"}:
            continue
        alerts.append(
            {
                "time": now(),
                "level": item["severity"],
                "rule": item["id"],
                "message": f"{item['location']}：{item['risk']}",
            }
        )
    if not alerts:
        alerts.append(
            {
                "time": now(),
                "level": "warn",
                "rule": "audit-coverage-review",
                "message": "未发现 high/critical 告警，请确认 OPENCLAW_ROOT 和日志范围是否覆盖真实 OpenClaw。",
            }
        )
    state["cloud"]["monitorAlerts"] = alerts
    add_event(state, "claude_code_monitoring", state["cloud"]["server"], True, "medium")
    return add_report(
        state,
        "Claude Code 告警规则已生成",
        [
            "规则来源：当前 Claude Code 真实审计发现。",
            f"已基于真实审计发现生成 {len(alerts)} 条告警。",
            "说明：这里生成的是建议告警规则，不代表已经改动云服务器上的监控系统。",
            "这些告警可交给 OpenClaw 或运维系统落地为处置工单、上线阻断条件或人工复核项。",
        ],
    )


def guardian_seal_control(state):
    state["workflow"]["controlPlaneAdvice"] = True
    related = findings_by_ids(state, ["CC-001"])
    add_event(state, "guardian_advice", "control-plane", True, "high")
    return add_report(
        state,
        "控制面访问风险建议",
        make_advice_lines(
            state,
            "控制面强鉴权与公网暴露收敛",
            related,
            "未发现控制面公网监听证据，但仍建议复核 WebSocket / API 入口。",
            [
                "将 OpenClaw 控制面限制在内网、VPN 或反向代理鉴权后方。",
                "对 WebSocket / API 启用强鉴权、Origin 校验和短会话 TTL。",
                "禁止通过远程请求关闭安全策略或审批策略。",
            ],
            [
                "端口监听列表不再出现公网绑定的控制面端口。",
                "OpenClaw 配置中存在鉴权、Origin 校验和会话过期策略。",
                "审计日志中未再出现未授权控制面访问。",
            ],
        ),
    )


def guardian_isolate_skill(state):
    state["workflow"]["skillAdvice"] = True
    related = findings_by_ids(state, ["CC-003", "CC-004", "CC-005"])
    add_event(state, "guardian_advice", "skill-isolation", True, "high")
    return add_report(
        state,
        "Skill 权限边界建议",
        make_advice_lines(
            state,
            "第三方 Skill 签名校验、最小权限和出站白名单",
            related,
            "未发现 Skill 外传或敏感路径访问证据，但仍需确认 Skill manifest 与运行日志完整。",
            [
                "只允许已签名、来源可信的 Skill 进入生产。",
                "第三方 Skill 默认只读，文件访问仅开放工作目录，敏感目录默认拒绝。",
                "网络出站默认拒绝，仅放行业务必需的内部 API。",
            ],
            [
                "Skill manifest 中有签名校验、权限边界和来源记录。",
                "运行日志中没有读取 .env、secrets、私钥、财务原始库等敏感路径。",
                "网络日志中没有未知域名、webhook 或 POST 外传行为。",
            ],
        ),
    )


def guardian_rotate_credentials(state):
    state["workflow"]["credentialAdvice"] = True
    related = findings_by_ids(state, ["CC-002"])
    add_event(state, "guardian_advice", "credential-rotation", True, "high")
    return add_report(
        state,
        "密钥与 Token 处置建议",
        make_advice_lines(
            state,
            "疑似暴露凭证吊销、轮换和日志脱敏",
            related,
            "未发现 Token 明文证据，但仍建议确认日志脱敏和密钥存储方式。",
            [
                "若日志中出现 Token、API Key 或 Authorization，立即吊销对应凭证。",
                "改用短期凭证或托管密钥服务，禁止把密钥写入日志和仓库。",
                "敏感操作增加人工审批或二次确认。",
            ],
            [
                "密钥平台或网关中存在吊销/轮换记录。",
                "最新日志中凭证字段已脱敏。",
                "代码仓库和配置文件中未发现明文密钥。",
            ],
        ),
    )


def guardian_apply_governance(state):
    state["workflow"]["governanceAdvice"] = True
    related = findings_by_ids(state, ["CC-006", "CC-007", "CC-008"])
    add_event(state, "guardian_advice", "governance-policy", True, "high")
    return add_report(
        state,
        "denyList、Token 熔断与审计建议",
        make_advice_lines(
            state,
            "高危命令拦截、Token 预算和审计日志",
            related,
            "未发现 denyList、Token 熔断或审计关闭证据，但仍建议核对生产配置。",
            [
                "配置高危命令 denyList，覆盖删除、外传、读取私钥、读取环境变量等模式。",
                "设置单任务和每日 Token 预算，超限暂停执行并告警。",
                "启用工具调用、拒绝动作、网络请求和审批记录审计。",
            ],
            [
                "配置文件中存在 denyList、Token budget 和 onExceed=suspend 等策略。",
                "审计日志能够记录被拒绝的命令、敏感文件读取和网络请求。",
                "Token 用量日志没有持续暴涨或异常超限。",
            ],
        ),
    )


def guardian_final_audit(state):
    state["workflow"]["finalReview"] = True
    findings = get_findings(state)
    critical = [item for item in findings if item.get("severity") == "critical"]
    high = [item for item in findings if item.get("severity") == "high"]
    medium = [item for item in findings if item.get("severity") == "medium"]
    report_exists = bool(state["cloud"].get("claudeReport"))
    scanned = (state["cloud"].get("claudeReport") or {}).get("summary", {}).get("scannedFiles", 0)
    root = state["cloud"].get("openclawRoot", "")
    checks = [
        {
            "name": "已定位真实 OpenClaw 根目录",
            "passed": bool(root),
            "detail": root or "未找到 OPENCLAW_ROOT",
        },
        {
            "name": "已扫描真实日志/配置文件",
            "passed": scanned > 0,
            "detail": f"扫描文件数：{scanned}",
        },
        {
            "name": "无严重风险发现",
            "passed": len(critical) == 0,
            "detail": f"严重风险：{len(critical)}",
        },
        {
            "name": "无高危风险发现",
            "passed": len(high) == 0,
            "detail": f"高危风险：{len(high)}",
        },
        {
            "name": "已生成建议治理动作",
            "passed": any(
                state["workflow"].get(key)
                for key in ["controlPlaneAdvice", "skillAdvice", "credentialAdvice", "governanceAdvice"]
            ),
            "detail": "至少需要根据审计结果生成一类建议。",
        },
    ]
    passed = sum(1 for item in checks if item["passed"])
    if not report_exists:
        conclusion = "未执行检测，禁止上线判断"
    elif critical or high:
        conclusion = "暂缓上线：存在未处置高危/严重风险"
    elif medium:
        conclusion = "可进入人工复核：仍有中危项需要确认"
    elif not root or scanned == 0:
        conclusion = "审计范围不足：需补齐真实日志后再判断"
    else:
        conclusion = "未发现高危证据：可进入受控上线前人工复核"
    state["finalAudit"] = {
        "time": now(),
        "passed": passed,
        "total": len(checks),
        "tests": checks,
        "findingSummary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
        },
        "releaseConclusion": conclusion,
    }
    add_event(state, "guardian_final_review", "OpenClaw", not (critical or high), "high")
    lines = [f"上线前复检：{passed}/{len(checks)} 项满足"]
    lines.extend([f"{'通过' if t['passed'] else '未通过'}：{t['name']} ({t['detail']})" for t in checks])
    lines.append(f"结论：{state['finalAudit']['releaseConclusion']}")
    return add_report(state, "最终复检与上线判断", lines)


def page_html():
    return r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Claude Code - OpenClaw Security Monitor</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #667085;
      --line: #d7dce2;
      --soft: #f9fafb;
      --red: #b42318;
      --red-bg: #fff1f0;
      --amber: #b54708;
      --amber-bg: #fff7e6;
      --green: #067647;
      --green-bg: #ecfdf3;
      --blue: #175cd3;
      --blue-bg: #eff8ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
      overflow-x: hidden;
    }
    header {
      min-height: 72px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    h1 { font-size: 22px; margin: 0; }
    .sub { color: var(--muted); font-size: 13px; margin-top: 4px; }
    .topline {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      padding: 4px 9px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--soft);
      font-size: 12px;
      font-weight: 650;
      color: var(--muted);
    }
    main {
      display: grid;
      grid-template-columns: minmax(340px, 0.92fr) minmax(520px, 1.35fr);
      gap: 18px;
      padding: 18px;
      max-width: 1500px;
      width: 100%;
      margin: 0 auto;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      min-width: 0;
      box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
    }
    h2 {
      font-size: 15px;
      margin: 0 0 12px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .roles {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .role {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: var(--soft);
      min-height: 86px;
    }
    .role b {
      display: block;
      margin-bottom: 5px;
      font-size: 14px;
    }
    .role span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }
    .item {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      min-height: 66px;
      background: #fff;
    }
    .label { color: var(--muted); font-size: 12px; }
    .value { font-size: 16px; font-weight: 700; margin-top: 5px; overflow-wrap: anywhere; }
    .critical { color: var(--red); }
    .high { color: var(--amber); }
    .controlled { color: var(--green); }
    .item.criticalBox { background: var(--red-bg); border-color: #fecdca; }
    .item.highBox { background: var(--amber-bg); border-color: #fedf89; }
    .item.safeBox { background: var(--green-bg); border-color: #abefc6; }
    button {
      min-height: 38px;
      border: 1px solid #b7c1cc;
      border-radius: 7px;
      background: #fff;
      color: var(--text);
      font-weight: 650;
      cursor: pointer;
      padding: 8px 10px;
      text-align: left;
    }
    button:hover { border-color: var(--blue); color: var(--blue); }
    button.done {
      border-color: #abefc6;
      background: var(--green-bg);
      color: var(--green);
    }
    button.next {
      border-color: #84caff;
      background: var(--blue-bg);
      color: var(--blue);
    }
    .actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .hint {
      border: 1px solid #84caff;
      background: var(--blue-bg);
      border-radius: 8px;
      padding: 10px;
      margin-bottom: 10px;
      font-size: 13px;
      line-height: 1.55;
      color: #1849a9;
    }
    .journey {
      display: grid;
      gap: 8px;
    }
    .step {
      display: grid;
      grid-template-columns: 30px 1fr;
      gap: 10px;
      align-items: start;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 9px;
      background: var(--soft);
      font-size: 13px;
    }
    .stepNum {
      width: 28px;
      height: 28px;
      border-radius: 999px;
      display: grid;
      place-items: center;
      font-weight: 800;
      background: #e4e7ec;
      color: #344054;
    }
    .step.done { border-color: #abefc6; background: var(--green-bg); }
    .step.done .stepNum { background: var(--green); color: #fff; }
    .step.next { border-color: #84caff; background: var(--blue-bg); }
    .step.next .stepNum { background: var(--blue); color: #fff; }
    .stepTitle { font-weight: 750; margin-bottom: 2px; }
    .stepText { color: var(--muted); line-height: 1.45; }
    pre {
      margin: 0;
      padding: 12px;
      background: #101828;
      color: #e4e7ec;
      border-radius: 8px;
      overflow: auto;
      max-height: 360px;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .stack { display: grid; gap: 16px; }
    .command {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: var(--soft);
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .log {
      display: grid;
      gap: 8px;
      max-height: 340px;
      overflow: auto;
    }
    .cards {
      display: grid;
      gap: 10px;
      max-height: 440px;
      overflow: auto;
    }
    .finding {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      display: grid;
      gap: 8px;
      font-size: 13px;
    }
    .findingHeader {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }
    .findingTitle {
      font-weight: 800;
      font-size: 14px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 800;
      border: 1px solid var(--line);
      white-space: nowrap;
    }
    .badge.critical { color: var(--red); background: var(--red-bg); border-color: #fecdca; }
    .badge.high { color: var(--amber); background: var(--amber-bg); border-color: #fedf89; }
    .badge.medium { color: var(--blue); background: var(--blue-bg); border-color: #84caff; }
    .kv {
      display: grid;
      grid-template-columns: 72px 1fr;
      gap: 8px;
      line-height: 1.45;
    }
    .kv b { color: var(--muted); font-weight: 700; }
    .miniList {
      margin: 0;
      padding-left: 16px;
      display: grid;
      gap: 4px;
    }
    .timeline {
      display: grid;
      gap: 10px;
      max-height: 360px;
      overflow: auto;
    }
    .timelineItem {
      border-left: 3px solid #84caff;
      background: var(--soft);
      border-radius: 7px;
      padding: 10px 10px 10px 12px;
      font-size: 13px;
      line-height: 1.5;
    }
    .timelineTitle {
      font-weight: 800;
      margin-bottom: 5px;
    }
    .row {
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 9px;
      font-size: 13px;
    }
    .row strong { display: block; margin-bottom: 4px; }
    .ok { color: var(--green); }
    .bad { color: var(--red); }
    @media (max-width: 960px) {
      main { grid-template-columns: 1fr; }
      .actions, .grid, .roles { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>OpenClaw 安全自审计控制台</h1>
      <div class="sub">读取云服务器上的真实 OpenClaw 日志与配置证据，调用 Claude Code 生成风险报告和建议动作</div>
      <div class="topline">
        <span class="pill">Cloud OpenClaw = 自审计发起方</span>
        <span class="pill">Claude Code = 日志审计与报告生成</span>
        <span class="pill">Security Guardian = 风险建议与复检</span>
      </div>
    </div>
    <button onclick="resetLab()">重置检测</button>
  </header>
  <main>
    <div class="stack">
      <section>
        <h2>实验角色</h2>
        <div class="roles">
          <div class="role"><b>云端 OpenClaw</b><span>部署在云服务器上的数字员工运行时。审计范围由 OPENCLAW_ROOT 和实际日志文件决定。</span></div>
          <div class="role"><b>Claude Code</b><span>读取 OpenClaw 日志与配置快照，输出风险编号、位置、证据、影响和修复建议。</span></div>
          <div class="role"><b>Security Guardian</b><span>建议动作生成器。只输出处置建议和复核证据要求，不自动修改生产配置。</span></div>
          <div class="role"><b>审计报告</b><span>最终交付物。用于判断 OpenClaw 是否可以进入上线前人工复核。</span></div>
        </div>
      </section>
      <section>
        <h2>OpenClaw 审计对象</h2>
        <div class="command">OPENCLAW_ROOT 指向的真实 OpenClaw 目录
OpenClaw 运行日志
OpenClaw 配置快照
OpenClaw Skill manifest / 行为日志
OpenClaw Token 用量记录
OpenClaw 工具调用审计日志</div>
      </section>
      <section>
        <h2>云端 OpenClaw 状态</h2>
        <div class="grid" id="cloudStatusGrid"></div>
      </section>
      <section>
        <h2>检测与建议流程</h2>
        <div class="journey" id="journey"></div>
      </section>
      <section>
        <h2>Claude Code 审计与监控</h2>
        <div class="hint" id="nextAction">Loading...</div>
        <div class="actions" id="guardianActions">
          <button data-action="scan" onclick="guardian('/claude-code/analyze-cloud')">1. 执行真实检测</button>
          <button data-action="monitor" onclick="guardian('/claude-code/enable-monitoring')">2. 生成告警规则</button>
          <button data-action="seal" onclick="guardian('/guardian/seal-control-plane')">3. 控制面建议</button>
          <button data-action="isolate" onclick="guardian('/guardian/isolate-skill')">4. Skill 建议</button>
          <button data-action="rotate" onclick="guardian('/guardian/rotate-secrets')">5. 密钥建议</button>
          <button data-action="govern" onclick="guardian('/guardian/apply-governance')">6. 治理策略建议</button>
          <button data-action="audit" onclick="guardian('/guardian/final-audit')">7. 最终复检</button>
        </div>
      </section>
      <section>
        <h2>最近审计日志</h2>
        <div class="log" id="auditLog"></div>
      </section>
    </div>
    <div class="stack">
      <section>
        <h2>真实检测状态总览</h2>
        <div class="grid" id="statusGrid"></div>
      </section>
      <section>
        <h2>Claude Code 风险发现</h2>
        <div class="cards" id="findingCards">Loading...</div>
      </section>
      <section>
        <h2>Security Guardian 建议治理动作</h2>
        <div class="timeline" id="reportTimeline">Loading...</div>
      </section>
      <section>
        <h2>告警规则</h2>
        <div class="cards" id="monitorAlerts">Loading...</div>
      </section>
      <section>
        <h2>最终复检</h2>
        <pre id="finalAudit">Not executed.</pre>
      </section>
    </div>
  </main>
  <script>
    async function post(path) {
      const res = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}});
      return await res.json();
    }
    async function guardian(path) {
      await post(path);
      await load();
    }
    async function resetLab() {
      await post('/api/reset');
      await load();
    }
    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
    }
    function item(label, value, cls='', box='') {
      return `<div class="item ${box}"><div class="label">${escapeHtml(label)}</div><div class="value ${cls}">${escapeHtml(value)}</div></div>`;
    }
    function yes(v) { return v ? 'ON' : 'OFF'; }
    function riskClass(r) {
      if (r === 'CRITICAL') return 'critical';
      if (r === 'HIGH' || r === 'ELEVATED') return 'high';
      if (r === 'REVIEW') return 'medium';
      if (r === 'CLEAN') return 'controlled';
      return 'controlled';
    }
    function riskBox(r) {
      if (r === 'CRITICAL') return 'criticalBox';
      if (r === 'HIGH' || r === 'ELEVATED') return 'highBox';
      if (r === 'REVIEW' || r === '待检测') return 'highBox';
      return 'safeBox';
    }
    function reportExists(s, title) {
      return s.guardianReports.some(r => r.title === title);
    }
    function phaseState(s) {
      const w = s.workflow || {};
      return {
        scan: !!w.scan || reportExists(s, 'Claude Code 云端日志审计报告'),
        monitor: !!w.alertRules || !!s.cloud.alertRulesGenerated,
        seal: !!w.controlPlaneAdvice,
        isolate: !!w.skillAdvice,
        rotate: !!w.credentialAdvice,
        govern: !!w.governanceAdvice,
        audit: !!s.finalAudit
      };
    }
    function nextPhase(p) {
      if (!p.scan) return ['scan', '先点“执行真实检测”：读取 OPENCLAW_ROOT 下的真实日志和配置，生成风险位置、证据和建议。'];
      if (!p.monitor) return ['monitor', '下一步点“生成告警规则”：把真实风险发现整理成可落地的告警规则。'];
      if (!p.seal) return ['seal', '下一步点“控制面建议”：输出强鉴权、Origin 校验和公网暴露收敛建议。'];
      if (!p.isolate) return ['isolate', '下一步点“Skill 建议”：输出第三方 Skill 最小权限和出站白名单建议。'];
      if (!p.rotate) return ['rotate', '下一步点“密钥建议”：输出疑似泄露凭证的吊销、轮换和脱敏建议。'];
      if (!p.govern) return ['govern', '下一步点“治理策略建议”：输出 denyList、Token 熔断和审计日志建议。'];
      if (!p.audit) return ['audit', '最后点“最终复检”：基于真实审计结果判断是否还有上线阻断风险。'];
      return ['done', '检测报告与建议已生成。请查看风险发现、建议动作和最终复检结论。'];
    }
    function renderJourney(s) {
      const p = phaseState(s);
      const [next] = nextPhase(p);
      const steps = [
        ['scan', 'Claude Code 日志审计', '读取云端 OpenClaw 日志，输出风险编号、位置、证据和建议。'],
        ['monitor', '生成告警规则', '把 Token 暴露、Skill 外传、Token 暴涨等发现转成告警规则建议。'],
        ['seal', '生成控制面建议', '输出强鉴权、Origin 校验、控制面入口收敛的建议和复核证据。'],
        ['isolate', '生成 Skill 建议', '输出第三方 Skill 签名校验、文件边界和网络出站建议。'],
        ['rotate', '生成密钥建议', '输出凭证吊销、轮换、短期化和日志脱敏建议。'],
        ['govern', '生成治理策略建议', '输出高危命令 denyList、Token 预算和审计日志建议。'],
        ['audit', '最终复检与判断', '基于真实 finding 数量和审计覆盖范围输出上线前判断。']
      ];
      document.getElementById('journey').innerHTML = steps.map((step, idx) => {
        const key = step[0];
        const cls = p[key] ? 'done' : key === next ? 'next' : '';
        const mark = p[key] ? '✓' : String(idx + 1);
        return `<div class="step ${cls}"><div class="stepNum">${mark}</div><div><div class="stepTitle">${step[1]}</div><div class="stepText">${step[2]}</div></div></div>`;
      }).join('');
      document.querySelectorAll('#guardianActions button').forEach(btn => {
        const key = btn.dataset.action;
        btn.classList.toggle('done', !!p[key]);
        btn.classList.toggle('next', key === next);
        btn.disabled = !!s.cloud.auditRunning && key === 'scan';
      });
      document.getElementById('nextAction').textContent = s.cloud.auditRunning ? 'Claude Code 正在审计 evidence 工作区，请等待当前任务完成。' : nextPhase(p)[1];
    }
    function severityLabel(value) {
      const v = String(value || '').toLowerCase();
      if (v === 'critical') return '严重';
      if (v === 'high') return '高危';
      if (v === 'medium') return '中危';
      if (v === 'low') return '低危';
      return value || '未知';
    }
    function severityClass(value) {
      const v = String(value || '').toLowerCase();
      if (v === 'critical') return 'critical';
      if (v === 'high') return 'high';
      if (v === 'medium') return 'medium';
      return 'medium';
    }
    function listItems(values) {
      const arr = Array.isArray(values) ? values.filter(Boolean) : [];
      if (!arr.length) return '';
      return `<ul class="miniList">${arr.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul>`;
    }
    function optionalKv(label, values) {
      const html = listItems(values);
      return html ? `<div class="kv"><b>${label}</b><span>${html}</span></div>` : '';
    }
    function renderFindings(s) {
      const report = s.cloud.claudeReport;
      if (!report || !report.findings || !report.findings.length) {
        document.getElementById('findingCards').innerHTML = '<div class="row">尚未生成 Claude Code 风险报告。请先执行“分析云端日志”。</div>';
        return;
      }
      document.getElementById('findingCards').innerHTML = report.findings.map(f => `
        <div class="finding">
          <div class="findingHeader">
            <div class="findingTitle">${escapeHtml(f.id)} · ${escapeHtml(f.location)}</div>
            <span class="badge ${severityClass(f.severity)}">${severityLabel(f.severity)}</span>
          </div>
          <div class="kv"><b>证据</b><span>${escapeHtml(f.evidence)}</span></div>
          <div class="kv"><b>影响</b><span>${escapeHtml(f.risk)}</span></div>
          <div class="kv"><b>建议</b><span>${escapeHtml(f.recommendation)}</span></div>
          ${optionalKv('处置', f.remediationSteps)}
          ${optionalKv('复核', f.verification)}
        </div>
      `).join('');
    }
    function renderReportTimeline(s) {
      if (!s.guardianReports.length) {
        document.getElementById('reportTimeline').innerHTML = '<div class="row">尚无建议治理动作。</div>';
        return;
      }
      document.getElementById('reportTimeline').innerHTML = s.guardianReports.map(r => `
        <div class="timelineItem">
          <div class="timelineTitle">[${escapeHtml(r.time)}] ${escapeHtml(r.title)}</div>
          ${r.lines.slice(0, 8).map(x => `<div>- ${escapeHtml(x)}</div>`).join('')}
        </div>
      `).join('');
    }
    function renderMonitorAlerts(s) {
      if (!s.cloud.monitorAlerts.length) {
        document.getElementById('monitorAlerts').innerHTML = '<div class="row">尚未启用监控告警。请执行“启用监控告警”。</div>';
        return;
      }
      document.getElementById('monitorAlerts').innerHTML = s.cloud.monitorAlerts.map(a => `
        <div class="finding">
          <div class="findingHeader">
            <div class="findingTitle">${escapeHtml(a.rule)}</div>
            <span class="badge ${severityClass(a.level)}">${severityLabel(a.level)}</span>
          </div>
          <div class="kv"><b>时间</b><span>${escapeHtml(a.time)}</span></div>
          <div class="kv"><b>告警</b><span>${escapeHtml(a.message)}</span></div>
        </div>
      `).join('');
    }
    async function load() {
      const res = await fetch('/api/status');
      const s = await res.json();
      const callMethod = s.cloud.auditMethod === 'manifest-driven workspace audit' ? 'manifest 工作区审计' : s.cloud.auditMethod === 'steer one-shot' ? 'steer 一次性调用' : s.cloud.auditMethod;
      const runtime = s.cloud.runtime === 'OpenClaw + Claude Code' ? 'OpenClaw + Claude Code' : s.cloud.runtime;
      const logWindow = s.cloud.logWindow === 'last 24h' ? '最近 24 小时' : s.cloud.logWindow;
      const report = s.cloud.claudeReport;
      const summary = report ? report.summary : {};
      const findings = report && report.findings ? report.findings : [];
      const criticalCount = findings.filter(x => x.severity === 'critical').length;
      const highCount = findings.filter(x => x.severity === 'high').length;
      const mediumCount = findings.filter(x => x.severity === 'medium').length;
      const skillSources = s.cloud.configSnapshot.skillSources
        .map(x => x === 'official' ? '官方' : x === 'community-market' ? '社区市场' : x)
        .join(', ');
      const secretStorage = s.cloud.configSnapshot.secretStorage === 'plain env file' ? '明文环境文件' : s.cloud.configSnapshot.secretStorage;
      const openPorts = s.cloud.configSnapshot.openPorts.length ? s.cloud.configSnapshot.openPorts.join(', ') : '待检测';
      const websocketBind = s.cloud.configSnapshot.websocketBind || '待检测';
      const claudeCall = s.cloud.auditRunning ? '运行中' : s.cloud.claudeInvocation && s.cloud.claudeInvocation.ok ? '成功' : report ? '失败' : '待调用';
      const auditRoots = s.cloud.auditRoots && s.cloud.auditRoots.length ? s.cloud.auditRoots.join('\\n') : '待检测';
      document.getElementById('cloudStatusGrid').innerHTML = [
        item('云服务器', s.cloud.server, '', 'safeBox'),
        item('运行时', runtime, '', 'safeBox'),
        item('审计运行', s.cloud.auditRunning ? '运行中' : '空闲', s.cloud.auditRunning ? 'high' : 'controlled', s.cloud.auditRunning ? 'highBox' : 'safeBox'),
        item('调用方式', callMethod, 'controlled', 'safeBox'),
        item('Claude 调用', claudeCall, claudeCall === '成功' ? 'controlled' : 'high', claudeCall === '成功' ? 'safeBox' : 'highBox'),
        item('日志窗口', logWindow, '', 'safeBox'),
        item('OpenClaw 根目录', s.cloud.openclawRoot || '待检测', s.cloud.openclawRoot ? 'controlled' : 'high', s.cloud.openclawRoot ? 'safeBox' : 'highBox'),
        item('审计目录', auditRoots, s.cloud.auditRoots && s.cloud.auditRoots.length ? 'controlled' : 'high', s.cloud.auditRoots && s.cloud.auditRoots.length ? 'safeBox' : 'highBox'),
        item('开放端口', openPorts, s.cloud.configSnapshot.openPorts.length ? 'high' : '', s.cloud.configSnapshot.openPorts.length ? 'highBox' : ''),
        item('WebSocket 绑定', websocketBind, websocketBind !== '未检测' && websocketBind !== '待检测' ? 'critical' : '', websocketBind !== '未检测' && websocketBind !== '待检测' ? 'criticalBox' : ''),
        item('Skill 来源', skillSources || '待检测', skillSources ? 'high' : '', skillSources ? 'highBox' : ''),
        item('密钥存储', secretStorage, secretStorage.includes('明文') ? 'critical' : '', secretStorage.includes('明文') ? 'criticalBox' : ''),
        item('告警规则', s.cloud.alertRulesGenerated ? '已生成' : '未生成', s.cloud.alertRulesGenerated ? 'controlled' : 'high', s.cloud.alertRulesGenerated ? 'safeBox' : 'highBox')
      ].join('');
      document.getElementById('statusGrid').innerHTML = [
        item('风险等级', s.riskLevel, riskClass(s.riskLevel), riskBox(s.riskLevel)),
        item('扫描文件数', summary.scannedFiles || 0, summary.scannedFiles ? 'controlled' : 'high', summary.scannedFiles ? 'safeBox' : 'highBox'),
        item('风险发现数', findings.length, findings.length ? 'high' : 'controlled', findings.length ? 'highBox' : 'safeBox'),
        item('严重风险', criticalCount, criticalCount ? 'critical' : 'controlled', criticalCount ? 'criticalBox' : 'safeBox'),
        item('高危风险', highCount, highCount ? 'high' : 'controlled', highCount ? 'highBox' : 'safeBox'),
        item('中危风险', mediumCount, mediumCount ? 'high' : 'controlled', mediumCount ? 'highBox' : 'safeBox'),
        item('审计清单', s.cloud.auditArtifacts.manifest || s.cloud.auditArtifacts.bundle || '未生成', (s.cloud.auditArtifacts.manifest || s.cloud.auditArtifacts.bundle) ? 'controlled' : '', (s.cloud.auditArtifacts.manifest || s.cloud.auditArtifacts.bundle) ? 'safeBox' : ''),
        item('Markdown 报告', s.cloud.auditArtifacts.reportMd || '未生成', s.cloud.auditArtifacts.reportMd ? 'controlled' : '', s.cloud.auditArtifacts.reportMd ? 'safeBox' : '')
      ].join('');
      renderJourney(s);

      renderFindings(s);
      renderReportTimeline(s);
      renderMonitorAlerts(s);

      document.getElementById('finalAudit').textContent = s.finalAudit
        ? JSON.stringify(s.finalAudit, null, 2)
        : '尚未执行最终复检。';

      document.getElementById('auditLog').innerHTML = s.auditEvents.slice(0, 12).map(e => {
        const cls = e.allowed ? 'ok' : 'bad';
        return `<div class="row"><strong class="${cls}">${escapeHtml(e.allowed ? 'ALLOWED' : 'BLOCKED')} · ${escapeHtml(e.action)}</strong>${escapeHtml(e.time)}<br>${escapeHtml(e.target)}<br>${escapeHtml(e.detail || '')}</div>`;
      }).join('') || '<div class="row">暂无审计事件。</div>';
    }
    load();
    setInterval(load, 5000);
  </script>
</body>
</html>"""


class OpenClawHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if not length:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path
        state = load_state()
        if path == "/" or path == "/dashboard.html":
            self.send_html(page_html())
            return
        if path == "/api/status":
            self.send_json(public_status(state))
            return
        self.send_json({"error": "not found"}, status=404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_json()
        state = load_state()

        if path == "/api/reset":
            state = initial_state()
            add_event(state, "reset", "security-audit", True, "low")
            save_state(state)
            self.send_json({"ok": True, "state": public_status(state)})
            return

        if path == "/guardian/seal-control-plane":
            report = guardian_seal_control(state)
            save_state(state)
            self.send_json({"ok": True, "report": report, "state": public_status(state)})
            return
        if path == "/guardian/isolate-skill":
            report = guardian_isolate_skill(state)
            save_state(state)
            self.send_json({"ok": True, "report": report, "state": public_status(state)})
            return
        if path == "/guardian/rotate-secrets":
            report = guardian_rotate_credentials(state)
            save_state(state)
            self.send_json({"ok": True, "report": report, "state": public_status(state)})
            return
        if path == "/guardian/apply-governance":
            report = guardian_apply_governance(state)
            save_state(state)
            self.send_json({"ok": True, "report": report, "state": public_status(state)})
            return
        if path == "/guardian/final-audit":
            report = guardian_final_audit(state)
            save_state(state)
            self.send_json({"ok": True, "report": report, "state": public_status(state)})
            return
        if path == "/claude-code/analyze-cloud":
            if not AUDIT_LOCK.acquire(blocking=False):
                state["cloud"]["auditRunning"] = True
                self.send_json({"ok": False, "error": "audit already running", "state": public_status(state)}, status=409)
                return
            try:
                state["cloud"]["auditRunning"] = True
                state["cloud"]["auditStartedAt"] = now()
                state["cloud"]["auditFinishedAt"] = ""
                save_state(state)
                report = claude_code_analyze_cloud(state)
                state["cloud"]["auditRunning"] = False
                state["cloud"]["auditFinishedAt"] = now()
                save_state(state)
                self.send_json({"ok": True, "report": report, "state": public_status(state)})
                return
            except Exception as exc:
                state["cloud"]["auditRunning"] = False
                state["cloud"]["auditFinishedAt"] = now()
                add_event(state, "claude_code_log_audit", state["cloud"]["server"], False, "high", str(exc))
                save_state(state)
                self.send_json({"ok": False, "error": str(exc), "state": public_status(state)}, status=500)
                return
            finally:
                AUDIT_LOCK.release()
        if path == "/claude-code/enable-monitoring":
            report = claude_code_enable_monitoring(state)
            save_state(state)
            self.send_json({"ok": True, "report": report, "state": public_status(state)})
            return

        self.send_json({"error": "not found"}, status=404)


def main():
    host = os.getenv("GUARDIAN_HOST", "0.0.0.0")
    port = int(os.getenv("GUARDIAN_PORT", "8511"))
    load_state()
    server = ThreadingHTTPServer((host, port), OpenClawHandler)
    print(f"OpenClaw Security Console running at http://{host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()















