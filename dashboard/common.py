"""
eBPF Container Guard — Dashboard common utilities (v0.3.7)

Shared data loading / actions for all dashboard pages.
"""

#!/usr/bin/env python3
"""
eBPF Container Guard — 安全监控面板 (v0.3.6)

Streamlit dashboard reading events.log (JSONL) written by main.py.

Features:
  - Overview stats (alerts / pending review / blocked / AI false positives)
  - Live alert stream (auto-refresh via st.fragment run_every)
  - Human review queue: confirm / dismiss buttons → decisions.log
  - Container filter (leverages v0.2.3 monitoring scope design)
  - Netblock view (reversible iptables blocks)

Run:  streamlit run dashboard/app.py
"""

import json
import sys
import time
from pathlib import Path

import docker
import pandas as pd
import streamlit as st

# ================================================================
# Paths
# ================================================================
SCRIPT_DIR = Path(__file__).parent.parent.resolve()
EVENTS_LOG = SCRIPT_DIR / "events.log"
DECISIONS_LOG = SCRIPT_DIR / "decisions.log"
AI_RESULTS_LOG = SCRIPT_DIR / "ai_results.log"
BEHAVIORS_LOG = SCRIPT_DIR / "behaviors.log"  # v0.3.10

REFRESH_SECONDS = 3

# ================================================================
# Data loading
# ================================================================

@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_events() -> pd.DataFrame:
    """Load events.log (JSONL) into a DataFrame."""
    if not EVENTS_LOG.exists():
        return pd.DataFrame()
    try:
        rows = []
        with open(EVENTS_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        df = pd.DataFrame(rows)
        if not df.empty and 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df
    except Exception as e:
        st.error(f"events.log 读取失败: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_decisions() -> pd.DataFrame:
    """Load decisions.log (human verdicts)."""
    if not DECISIONS_LOG.exists():
        return pd.DataFrame()
    try:
        rows = []
        with open(DECISIONS_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return pd.DataFrame(rows)
    except Exception:
        return pd.DataFrame()



@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_ai_results() -> pd.DataFrame:
    """Load ai_results.log (async AI verdicts, v0.3.2)."""
    if not AI_RESULTS_LOG.exists():
        return pd.DataFrame()
    try:
        rows = []
        with open(AI_RESULTS_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return pd.DataFrame(rows)
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=5, show_spinner=False)
def load_behavior_log() -> pd.DataFrame:
    """Load behaviors.log (v0.3.10 — ALL syscall events)."""
    if not BEHAVIORS_LOG.exists():
        return pd.DataFrame()
    try:
        rows = []
        with open(BEHAVIORS_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        df = pd.DataFrame(rows)
        if not df.empty and 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df
    except Exception:
        return pd.DataFrame()


RULES_PATH = SCRIPT_DIR / "config" / "rules.yaml"
RULES_AUDIT_LOG = SCRIPT_DIR / "rules_audit.log"
AI_CONFIG_PATH = SCRIPT_DIR / "config" / "ai_config.yaml"

# 规则表单操作符 (v0.4.0), 与 rule_schema.OPS 对应
CONDITION_OPS = ["==", "neq", "startswith", "endswith", "contains", "glob"]


def parse_condition_rows(rows) -> list:
    """表单条件行 → condition 节点列表 (v0.4.0)。

    每行 (field, op, value): 空行跳过; 值含逗号 = OR 列表; == 为精确匹配。
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
    """Append a rule to rules.yaml (v0.3.4/0.3.5).

    Guard's hot-reload watcher (v0.3.3) picks it up within 3s.
    Every change is recorded to rules_audit.log (audit trail).

    v0.4.0: 入库前 normalize (兼容旧式扁平 condition) + schema 校验,
    非法规则拒绝入库, 避免坏规则杀掉整个热加载。
    """
    try:
        src_dir = str(SCRIPT_DIR / "src")
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)
        from detector.rule_schema import normalize_ai_rule, validate_rule

        norm, err = normalize_ai_rule(rule)
        if err is not None:
            st.error(f"规则 schema 非法: {err}")
            return False
        try:
            validate_rule(norm)
        except ValueError as e:
            st.error(f"规则校验失败: {e}")
            return False
        rule = norm

        import yaml
        block = yaml.safe_dump(rule, allow_unicode=True,
                               sort_keys=False, default_flow_style=False)
        # 缩进为 rules 列表项格式: "  - name: ..." 子字段 4 空格
        indented = "  - " + block.replace("\n", "\n    ").strip()
        with open(RULES_PATH, 'a') as f:
            f.write("\n" + indented + "\n")
        log_rule_audit("add_rule", rule.get('name', 'unnamed'),
                       source, rule)
        return True
    except Exception as e:
        st.error(f"规则写入失败: {e}")
        return False


def log_rule_audit(action: str, rule_name: str, source: str,
                   rule_content: dict):
    """Record a rule change to rules_audit.log (v0.3.5).

    Rule changes are knowledge-asset modifications — auditable for
    compliance and rollback (original content preserved).
    """
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'action': action,
        'rule_name': rule_name,
        'source': source,  # 'ai_suggestion' | 'manual'
        'rule': rule_content,
    }
    with open(RULES_AUDIT_LOG, 'a') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_rules() -> pd.DataFrame:
    """Load current rules from rules.yaml for display."""
    try:
        import yaml
        with open(RULES_PATH, 'r') as f:
            rules = yaml.safe_load(f).get('rules', [])
        return pd.DataFrame(rules)
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_rule_audit() -> pd.DataFrame:
    """Load rules_audit.log (rule change history)."""
    if not RULES_AUDIT_LOG.exists():
        return pd.DataFrame()
    try:
        rows = []
        with open(RULES_AUDIT_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return pd.DataFrame(rows)
    except Exception:
        return pd.DataFrame()


def record_decision(container_id: str, decision: str, event_count: int = 1,
                    scope: str = "container"):
    """Append a verdict to decisions.log, then refresh.

    判决粒度 = 容器（决策记录 #14）：处置动作作用于容器，
    该容器的全部待判决事件联动标记。
    scope: 'container'（容器判决）或 'suggested_rule'（AI 建议规则审核）
    """
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'container_id': container_id,
        'decision': decision,
        'scope': scope,
        'event_count': event_count,
    }
    with open(DECISIONS_LOG, 'a') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    # 清除缓存，确保 rerun 后立刻读到新判决
    load_decisions.clear()


@st.cache_data(ttl=30, show_spinner=False)
def get_container_profile(container_id: str) -> dict:
    """查询容器元数据（镜像/特权/创建时间/端口/状态）。

    供人工判决参考 — 判断事件是否为真实攻击的证据之一。
    容器已删除时返回 None。
    """
    try:
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
        }
    except Exception:
        return None




# ================================================================
# Auth singleton (v0.3.8)
# ================================================================
from auth import AuthManager, TokenManager

AUTH = AuthManager(str(SCRIPT_DIR / "config" / "users.yaml"))
TOKENS = TokenManager(str(SCRIPT_DIR / "config" / "tokens.yaml"),
                      str(SCRIPT_DIR / "auth_audit.log"), auth=AUTH)
