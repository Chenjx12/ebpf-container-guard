"""
eBPF Container Guard — FastAPI server common utilities (v0.5.6)

Reusable data loading / actions for the API layer.
Migrated from dashboard/common.py:
  - paths unified to logs/ (matches main.py — fixes the events.log
    split that made the old Streamlit panel read nothing)
  - streamlit stripped (st.cache_data / st.error removed)
"""

import json
import sys
import time
from pathlib import Path

import pandas as pd

# ================================================================
# Paths (unified to logs/ — main.py writes here since v0.5.2)
# GUARD_LOGS_DIR 可覆盖: k8s DaemonSet 部署时日志在 /var/lib/ebpf-guard
# ================================================================
import os as _os
SCRIPT_DIR = Path(__file__).parent.parent.resolve()
LOGS_DIR = Path(_os.environ.get(
    "GUARD_LOGS_DIR", str(SCRIPT_DIR / "logs")))
EVENTS_LOG = LOGS_DIR / "events.log"
DECISIONS_LOG = LOGS_DIR / "decisions.log"
AI_RESULTS_LOG = LOGS_DIR / "ai_results.log"
BEHAVIORS_LOG = LOGS_DIR / "behaviors.log"

RULES_PATH = SCRIPT_DIR / "config" / "rules.yaml"
RULES_AUDIT_LOG = SCRIPT_DIR / "rules_audit.log"
AI_CONFIG_PATH = SCRIPT_DIR / "config" / "ai_config.yaml"
AUTH_AUDIT_LOG = SCRIPT_DIR / "auth_audit.log"

REFRESH_SECONDS = 3

# ================================================================
# Data loading (no cache — file volumes are small; frontend polls)
# ================================================================


def _read_jsonl(path: Path, tail_lines: int = None) -> pd.DataFrame:
    """Read JSONL into DataFrame. tail_lines: 只解析尾部 N 行 (大文件性能)。"""
    if not path.exists():
        return pd.DataFrame()
    rows = []
    try:
        if tail_lines:
            # 尾部窗口: deque 只保留最后 N 行, 避免全量解析
            from collections import deque
            with open(path, 'r') as f:
                tail = deque(f, maxlen=tail_lines)
            for line in tail:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        else:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
    except Exception:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def load_events(limit: int = 0) -> pd.DataFrame:
    """Load events.log (JSONL). v0.5.6: limit>0 只解析尾部 N 行 (15MB+ 提速)。"""
    df = _read_jsonl(EVENTS_LOG, tail_lines=limit or None)
    if not df.empty and 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    return df


def load_decisions() -> pd.DataFrame:
    """Load decisions.log (human verdicts)."""
    return _read_jsonl(DECISIONS_LOG)


def load_ai_results() -> pd.DataFrame:
    """Load ai_results.log (async AI verdicts, v0.3.2)."""
    return _read_jsonl(AI_RESULTS_LOG)


def load_behavior_log(limit: int = 0) -> pd.DataFrame:
    """Load behaviors.log tail (v0.3.10 — ALL syscall events).

    v0.5.6 性能: 文件可达数十 MB, 全量读入 pandas 每次 ~2s。
    limit>0 时只解析尾部 N 行 (deque 窗口), 面板轮询足够。
    """
    df = _read_jsonl(BEHAVIORS_LOG, tail_lines=limit or None)
    if not df.empty and 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    return df


def load_rules() -> list:
    """Load current rules from rules.yaml for display (list of dicts)."""
    try:
        import yaml
        with open(RULES_PATH, 'r') as f:
            return yaml.safe_load(f).get('rules', [])
    except Exception:
        return []


def load_rule_audit() -> pd.DataFrame:
    """Load rules_audit.log (rule change history)."""
    return _read_jsonl(RULES_AUDIT_LOG)


def load_auth_audit() -> pd.DataFrame:
    """Load auth_audit.log (token grants/uses/revokes)."""
    return _read_jsonl(AUTH_AUDIT_LOG)


def load_ai_config() -> dict:
    """Load ai_config.yaml (masked api_key)."""
    try:
        import yaml
        with open(AI_CONFIG_PATH, 'r') as f:
            cfg = yaml.safe_load(f) or {}
        if cfg.get('api_key'):
            cfg['api_key_masked'] = cfg['api_key'][:4] + "****"
            cfg.pop('api_key', None)
        return cfg
    except Exception:
        return {}


# ================================================================
# Actions
# ================================================================

CONDITION_OPS = ["==", "neq", "startswith", "endswith", "contains", "glob"]


def parse_condition_rows(rows) -> list:
    """表单条件行 → condition 节点列表 (v0.4.0)。

    每行 (field, op, value): 空行跳过; 值含逗号 = OR 列表; == 为精确匹配。
    (identical to dashboard/common.py — dashboard tests cover this)
    """
    nodes = []
    for field, op, value in rows:
        if not field or not value:
            continue
        values = ([v.strip() for v in value.split(",")]
                  if "," in value else value.strip())
        if op == "==":
            nodes.append({field: values})
        else:
            nodes.append({field: {op: values}})
    return nodes


def append_rule_to_yaml(rule: dict, source: str = "ai_suggestion") -> bool:
    """Append a rule to rules.yaml (guard hot-reloads within 3s).

    Returns (ok, error_msg). Audits to rules_audit.log.
    """
    try:
        src_dir = str(SCRIPT_DIR / "src")
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)
        from detector.rule_schema import normalize_ai_rule, validate_rule

        norm, err = normalize_ai_rule(rule)
        if err is not None:
            return False, f"规则 schema 非法: {err}"
        try:
            validate_rule(norm)
        except ValueError as e:
            return False, f"规则校验失败: {e}"
        rule = norm

        import yaml
        block = yaml.safe_dump(rule, allow_unicode=True,
                               sort_keys=False, default_flow_style=False)
        indented = "  - " + block.replace("\n", "\n    ").strip()
        with open(RULES_PATH, 'a') as f:
            f.write("\n" + indented + "\n")
        log_rule_audit("add_rule", rule.get('name', 'unnamed'), source, rule)
        return True, None
    except Exception as e:
        return False, f"规则写入失败: {e}"


def log_rule_audit(action: str, rule_name: str, source: str,
                   rule_content: dict):
    """Record a rule change to rules_audit.log (audit trail)."""
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'action': action,
        'rule_name': rule_name,
        'source': source,
        'rule': rule_content,
    }
    with open(RULES_AUDIT_LOG, 'a') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def save_ai_config(cfg: dict) -> tuple:
    """Atomic write ai_config.yaml: backup → write → yaml validate → rollback.

    Returns (ok, error_msg).
    """
    try:
        import yaml
        import shutil
        backup = AI_CONFIG_PATH.with_suffix('.yaml.bak')
        if AI_CONFIG_PATH.exists():
            shutil.copy2(AI_CONFIG_PATH, backup)
        with open(AI_CONFIG_PATH, 'w') as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        # validate round-trip; rollback on failure
        with open(AI_CONFIG_PATH, 'r') as f:
            yaml.safe_load(f)
        return True, None
    except Exception as e:
        try:
            if backup.exists():
                shutil.copy2(backup, AI_CONFIG_PATH)
        except Exception:
            pass
        return False, f"AI 配置写入失败: {e}"


def record_decision(container_id: str, decision: str, event_count: int = 1,
                    scope: str = "container"):
    """Append a verdict to decisions.log (DecisionExecutor polls it every 2s)."""
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'container_id': container_id,
        'decision': decision,
        'scope': scope,
        'event_count': event_count,
    }
    DECISIONS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(DECISIONS_LOG, 'a') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def get_container_profile(container_id: str):
    """Container metadata for human review (None if unavailable/deleted).

    v0.5.6: 双运行时支持 — k8s (ns/pod) 用 Kubernetes API 查 pod,
    Docker 用 docker API 查容器。此前只支持 Docker, k8s 逃逸容器
    画像恒为 None (面板显示"画像不可用")。
    """
    if not container_id:
        return None
    # k8s 形态: display = ns/pod
    if '/' in container_id and not container_id.startswith(('sha256:', 'http')):
        return _k8s_pod_profile(container_id)
    return _docker_container_profile(container_id)


def _k8s_pod_profile(container_id: str):
    """k8s pod 画像: ns/pod → Kubernetes API 查主容器元数据。"""
    try:
        ns, pod = container_id.split('/', 1)
        import sys as _sys
        import os as _os
        if str(SCRIPT_DIR) not in _sys.path:
            _sys.path.insert(0, str(SCRIPT_DIR))
        if str(SCRIPT_DIR / "src") not in _sys.path:
            _sys.path.insert(0, str(SCRIPT_DIR / "src"))
        from kubernetes import client as k8s_client
        # v0.5.6: 缓存 k8s client — load_kubeconfig + 新建 client 每次
        # 都做, 高频轮询下是主要耗时
        v1 = getattr(_k8s_pod_profile, '_v1', None)
        if v1 is None:
            from core.kube_utils import load_kubeconfig
            # k3s.yaml 是 root 600, 面板进程读不了 → 优先 ~/.kube/config 副本
            home_cfg = str(Path.home() / ".kube" / "config")
            load_kubeconfig(home_cfg if _os.path.exists(home_cfg)
                            else "/etc/rancher/k3s/k3s.yaml")
            v1 = k8s_client.CoreV1Api()
            _k8s_pod_profile._v1 = v1
        p = v1.read_namespaced_pod(pod, ns)
        if not p.spec.containers:
            return None
        c = p.spec.containers[0]
        status = p.status.phase
        # 主容器运行状态 (Created/Running/Terminated)
        cstatus = None
        for cs in (p.status.container_statuses or []):
            if cs.name == c.name:
                cstatus = cs.state
                break
        created = str(p.metadata.creation_timestamp or '')[:19]
        privileged = False
        if c.security_context:
            privileged = bool(c.security_context.privileged)
        pod_ip = p.status.pod_ip or ''
        return {
            'name': pod,
            'image': c.image or 'unknown',
            'status': status,
            'created': created,
            'privileged': privileged,
            'ports': pod_ip or '无',
            'pid': '—',  # k8s API 无宿主 PID (需 hostPID), 留占位
            'runtime': 'k8s',
        }
    except Exception:
        return None


def _docker_container_profile(container_id: str):
    """Docker 容器画像 (原逻辑, v0.3.x)。"""
    try:
        import docker
        client = docker.from_env()
        c = client.containers.get(container_id)
        ports = c.attrs['NetworkSettings'].get('Ports') or {}
        port_str = ", ".join(
            f"{k}->{v[0]['HostPort']}" for k, v in ports.items() if v
        ) if ports else "无"
        return {
            'name': c.name,
            'image': c.image.tags[0] if c.image.tags
            else (c.image.short_id or 'unknown'),
            'status': c.status,
            'created': str(c.attrs.get('Created', ''))[:19],
            'privileged': c.attrs['HostConfig'].get('Privileged', False),
            'ports': port_str,
            'pid': c.attrs['State'].get('Pid', 0),
            'runtime': 'docker',
        }
    except Exception:
        return None


# ================================================================
# Auth singleton (imported from dashboard/auth.py — no streamlit dep)
# ================================================================
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from dashboard.auth import AuthManager, TokenManager  # noqa: E402

AUTH = AuthManager(str(SCRIPT_DIR / "config" / "users.yaml"))
TOKENS = TokenManager(str(SCRIPT_DIR / "config" / "tokens.yaml"),
                      str(AUTH_AUDIT_LOG), auth=AUTH)


def ensure_initial_users() -> dict:
    """首次启动(users.yaml 为空)创建内置账号, 返回 {username: password}。

    admin = 管理员, test = 安全员 (v0.5.6 用户指定; 运维不预设)。
    密码随机生成, 打印到面板终端; 首次登录强制改密 (is_initial=True)。
    """
    if AUTH.users:
        return {}
    import secrets
    pwd_admin = secrets.token_urlsafe(12)
    pwd_test = secrets.token_urlsafe(12)
    AUTH.create_user('admin', pwd_admin, 'admin', is_initial=True)
    AUTH.create_user('test', pwd_test, 'analyst', is_initial=True)
    return {'admin': pwd_admin, 'test': pwd_test}
