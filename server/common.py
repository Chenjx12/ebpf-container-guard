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


def _read_jsonl(path, tail_lines: int = None) -> pd.DataFrame:
    """Read JSONL into DataFrame. tail_lines: 只解析尾部 N 行 (大文件性能)。

    path 可为 str (轮转文件 glob) 或 Path。
    """
    if isinstance(path, str):
        path = Path(path)
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


def load_behavior_rotated(limit: int = 0) -> pd.DataFrame:
    """Load behaviors.log 含轮转文件 (v0.5.8 attack-chain 用)。

    行为按天轮转 (behaviors.log.YYYY-MM-DD) — 攻击链查询可能跨天,
    需读当前文件 + 最近轮转文件。limit=0 全量 (攻击链低频, 需完整
    时间窗); limit>0 时每文件取尾部 N 行。
    """
    import glob as _glob
    files = [BEHAVIORS_LOG] + sorted(
        _glob.glob(str(BEHAVIORS_LOG) + ".*"), reverse=True)[:7]
    frames = [_read_jsonl(p, tail_lines=limit or None) for p in files]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, ignore_index=True)
    if 'timestamp' in df.columns:
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
# AI Profiles (v0.5.7) — 多配置管理 (方案 B: profiles 是源,
# ai_config.yaml 仅激活快照, guard 热加载零改动)
# ================================================================

AI_PROFILES_PATH = SCRIPT_DIR / "config" / "ai_profiles.yaml"


def _load_profiles_raw() -> dict:
    if not AI_PROFILES_PATH.exists():
        return {}
    try:
        import yaml
        with open(AI_PROFILES_PATH, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _save_profiles_raw(data: dict):
    import yaml
    AI_PROFILES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(AI_PROFILES_PATH, 'w') as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)


def load_ai_profiles() -> dict:
    """返回 {active, profiles: [{name, base_url, model, thresholds, api_key_masked}]}"""
    data = _load_profiles_raw()
    active = data.get('active', '')
    profiles = data.get('profiles', {})
    out = []
    for name, cfg in profiles.items():
        entry = dict(cfg)
        if entry.get('api_key'):
            entry['api_key_masked'] = entry['api_key'][:4] + "****"
            entry.pop('api_key', None)
        entry['name'] = name
        entry['active'] = (name == active)
        out.append(entry)
    return {'active': active, 'profiles': out}


def save_ai_profile(name: str, cfg: dict) -> tuple:
    """保存命名配置 (key 留空时保留原 key)。"""
    if not name or not cfg.get('base_url'):
        return False, "配置名和 base_url 必填"
    data = _load_profiles_raw()
    profiles = data.setdefault('profiles', {})
    old = profiles.get(name, {})
    merged = dict(cfg)
    if not merged.get('api_key'):
        merged['api_key'] = old.get('api_key', '')
    merged.pop('name', None)
    merged.pop('active', None)
    profiles[name] = merged
    if not data.get('active'):
        data['active'] = name
    _save_profiles_raw(data)
    return True, None


def delete_ai_profile(name: str) -> tuple:
    data = _load_profiles_raw()
    profiles = data.get('profiles', {})
    if name not in profiles:
        return False, f"配置 {name} 不存在"
    del profiles[name]
    if data.get('active') == name:
        data['active'] = next(iter(profiles), '')
    _save_profiles_raw(data)
    return True, None


def activate_ai_profile(name: str, thresholds: dict = None) -> tuple:
    """切换: 更新 active + 写 ai_config.yaml 快照 (guard 热加载)。

    thresholds (v0.5.7): 可选 {auto_response_threshold, pending_review_threshold}
    — 传入则保存回 profile 存储 (用户确认), 否则用 profile 原值。
    """
    data = _load_profiles_raw()
    profiles = data.get('profiles', {})
    if name not in profiles:
        return False, f"配置 {name} 不存在"
    data['active'] = name
    if thresholds:
        for k in ('auto_response_threshold', 'pending_review_threshold'):
            if k in thresholds and thresholds[k] is not None:
                profiles[name][k] = thresholds[k]
    _save_profiles_raw(data)
    cfg = dict(profiles[name])
    cfg.pop('name', None)
    ok, err = save_ai_config(cfg)
    if not ok:
        return False, f"快照写入失败: {err}"
    return True, None


def sync_ai_snapshot():
    """启动一致性 (v0.5.7): profiles 是源, ai_config.yaml 仅快照。

    - 无 profiles 且 ai_config.yaml 存在 → 迁移为 default profile
    - profiles 有 active → 覆盖写 ai_config.yaml (空/被手动改都收敛)
    """
    data = _load_profiles_raw()
    profiles = data.get('profiles', {})
    active = data.get('active', '')
    if not profiles:
        # 存量迁移: ai_config.yaml → default profile
        cfg = load_ai_config()  # masked — 需原始 key
        raw = {}
        try:
            import yaml
            with open(AI_CONFIG_PATH, 'r') as f:
                raw = yaml.safe_load(f) or {}
        except Exception:
            pass
        if raw.get('base_url') or raw.get('api_key'):
            raw.pop('api_key_masked', None)
            raw.setdefault('model', 'deepseek-chat')
            data['profiles'] = {'default': raw}
            data['active'] = 'default'
            _save_profiles_raw(data)
            print("[AI Profiles] 已从 ai_config.yaml 迁移为 default profile")
        return
    if active not in profiles:
        active = next(iter(profiles))
        data['active'] = active
        _save_profiles_raw(data)
    ok, err = activate_ai_profile(active)
    if ok:
        print(f"[AI Profiles] 快照已同步: active={active} → ai_config.yaml")


def fetch_models(base_url: str, api_key: str) -> tuple:
    """GET {base_url}/models (OpenAI 兼容, Bearer 鉴权) → 模型 id 列表。

    Returns (models_list, error_msg)。
    """
    import urllib.request
    base = (base_url or '').rstrip('/')
    if not base:
        return [], "base_url 必填"
    try:
        req = urllib.request.Request(
            f"{base}/models",
            headers={"Authorization": f"Bearer {api_key}"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        models = [m.get('id') for m in data.get('data', []) if m.get('id')]
        return models, None
    except Exception as e:
        return [], f"获取模型失败: {e}"


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


# Falco → 自研字段映射 (AI 建议规则兼容层, v0.5.6)
# AI 输出 Falco 风格字段名, 引擎注册表是自研字段 — 入库前映射否则校验失败
FALCO_FIELD_MAP = {
    'proc.name': 'comm',
    'proc.cmdline': 'target_path',
    'proc.pid': 'pid',
    'proc.uid': 'uid',
    'container.id': 'container_id',
    'container.name': 'container_id',  # 无单独 name 字段, 映射到容器 ID
    'fd.name': 'target_path',
    'fd.type': 'fstype',
    'fd': 'target_path',  # 裸 fd → target_path (近似; 校验失败兜底)
}
# 引擎不认识的 Falco 字段 — 丢弃该条件节点 (宁可简化不让入库失败)
FALCO_DROP_FIELDS = ('evt.type', 'evt.arg', 'proc.anomaly', 'user.name',
                     'user.uid', 'group.name', 'group.uid')


def _map_falco_fields(node):
    """递归映射 condition 树里的 Falco 字段名为引擎字段。

    v0.5.6: 无法映射的字段丢弃节点 (如 fd.startswith("0:") 对 connect
    事件无语义) — AI 建议规则宁可简化, 不让校验失败阻塞入库。
    """
    if not isinstance(node, dict):
        return node
    out = {}
    for k, v in node.items():
        if k in ('all', 'any'):
            mapped = [_map_falco_fields(x) for x in v]
            out[k] = [x for x in mapped if x is not None]
        elif k == 'not':
            mapped = _map_falco_fields(v)
            out[k] = mapped if mapped is not None else {}
        else:
            field = FALCO_FIELD_MAP.get(k, k)
            if field in FALCO_DROP_FIELDS or (k != field and field not in
                    ('comm', 'target_path', 'pid', 'uid', 'container_id',
                     'fstype', 'daddr', 'dport', 'target_pid', 'request',
                     'open_flags', 'cap_effective', 'cap_permitted',
                     'timestamp', 'event_type')):
                continue  # 未知字段丢弃
            out[field] = _map_falco_fields(v) if isinstance(v, dict) else v
    return out if out else None


def append_rule_to_yaml(rule: dict, source: str = "ai_suggestion",
                        user: str = "") -> bool:
    """Append a rule to rules.yaml (guard hot-reloads within 3s).

    Returns (ok, error_msg). Audits to rules_audit.log.
    """
    try:
        src_dir = str(SCRIPT_DIR / "src")
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)
        from detector.rule_schema import normalize_ai_rule, validate_rule

        # v0.5.6: AI 建议字段映射 (Falco → 引擎字段)
        if source == "ai_suggestion" and 'condition' in rule:
            rule['condition'] = _map_falco_fields(rule['condition'])

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
        log_rule_audit("add_rule", rule.get('name', 'unnamed'), source,
                       rule, user)
        # v0.5.6: k8s 部署时同步 configmap — 容器 guard 读 configmap,
        # 只写本地 rules.yaml 不生效 (架构断裂)
        _sync_rules_to_configmap()
        return True, None
    except Exception as e:
        return False, f"规则写入失败: {e}"


def _sync_rules_to_configmap():
    """面板加规则后同步到 k8s configmap + 重启 guard。

    configmap 更新是 symlink 原子替换, 文件 mtime 不变 → guard 的
    mtime watch 检测不到 → 必须 rollout restart 让新规则生效。
    本地部署 (无 kubectl/非 k8s) 自动跳过。
    """
    try:
        import subprocess
        import json as _json
        rules = open(RULES_PATH).read()
        patch = _json.dumps({"data": {"rules.yaml": rules}})
        r = subprocess.run(
            ['kubectl', 'patch', 'configmap', 'ebpf-guard-config',
             '-n', 'kube-system', '--type', 'merge', '-p', patch],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            print(f"[Panel] configmap 同步失败: {r.stderr.strip()[:120]}")
            return
        r2 = subprocess.run(
            ['kubectl', 'rollout', 'restart', 'ds/ebpf-guard',
             '-n', 'kube-system'],
            capture_output=True, text=True, timeout=30)
        if r2.returncode == 0:
            print("[Panel] 规则已同步 configmap + guard 重启生效")
    except Exception as e:
        print(f"[Panel] configmap 同步失败 (本地部署可忽略): {e}")


def log_rule_audit(action: str, rule_name: str, source: str,
                   rule_content: dict, user: str = ""):
    """Record a rule change to rules_audit.log (audit trail).

    v0.5.6: user 字段 — 记录操作者 (API 从登录会话传入), 规则页溯源
    "谁在什么时候允许规则入库"; 初始内置规则无审计条目显示 '-'.
    """
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'action': action,
        'rule_name': rule_name,
        'source': source,
        'user': user,
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
    """Append a verdict to decisions.log (DecisionExecutor polls it every 2s).

    v0.5.6: 写失败返回 (ok=False, err) — 面板进程可能无权写 k8s 日志目录
    (root 拥有), 捕获避免 500; 由调用方提示用户。
    """
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'container_id': container_id,
        'decision': decision,
        'scope': scope,
        'event_count': event_count,
    }
    try:
        DECISIONS_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(DECISIONS_LOG, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        return True, None
    except PermissionError as e:
        return False, (f"无权写入判决日志 {DECISIONS_LOG} — "
                       f"k8s 部署请用 sudo 启动面板或 chmod 目录")
    except Exception as e:
        return False, f"判决写入失败: {e}"


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
