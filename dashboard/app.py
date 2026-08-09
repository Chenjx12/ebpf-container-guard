#!/usr/bin/env python3
"""
eBPF Container Guard — 安全监控面板 (v0.3 prototype)

Streamlit dashboard reading events.log (JSONL) written by main.py.

Features:
  - Overview stats (alerts / pending review / blocked / AI false positives)
  - Live alert stream (auto-refresh)
  - Human review queue: confirm / dismiss buttons → decisions.log
  - Container filter (leverages v0.2.3 monitoring scope design)
  - Netblock view (reversible iptables blocks)

Run:  streamlit run dashboard/app.py
"""

import json
import os
import time
from pathlib import Path

import pandas as pd
import streamlit as st

# ================================================================
# Paths
# ================================================================
SCRIPT_DIR = Path(__file__).parent.parent.resolve()
EVENTS_LOG = SCRIPT_DIR / "events.log"
DECISIONS_LOG = SCRIPT_DIR / "decisions.log"

REFRESH_SECONDS = 3

st.set_page_config(
    page_title="eBPF Container Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


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
        if not df.empty:
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


def record_decision(event_ts: str, container_id: str, rule: str,
                    decision: str):
    """Append a human verdict to decisions.log."""
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'event_ts': event_ts,
        'container_id': container_id,
        'rule': rule,
        'decision': decision,
    }
    with open(DECISIONS_LOG, 'a') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


# ================================================================
# Sidebar
# ================================================================
st.sidebar.title("🛡️ eBPF Container Guard")
st.sidebar.caption("v0.3 prototype · 实时检测 · AI 研判 · 人机协同")

# Auto-refresh toggle
auto = st.sidebar.toggle("自动刷新", value=True,
                         help=f"每 {REFRESH_SECONDS} 秒刷新")
if auto:
    time.sleep(REFRESH_SECONDS)
    st.rerun()

st.sidebar.divider()
st.sidebar.subheader("📊 数据源")
st.sidebar.caption(f"events.log: {EVENTS_LOG.name}")
st.sidebar.caption(f"decisions.log: {DECISIONS_LOG.name}")

# ================================================================
# Load data
# ================================================================
events = load_events()
decisions = load_decisions()

if events.empty:
    st.warning("⚠️ 暂无事件数据 — 请先运行: sudo python3 main.py")
    st.info("面板会每 3 秒自动检查 events.log，事件产生后自动出现。")
    st.stop()

# ================================================================
# Overview stats
# ================================================================
st.title("🛡️ 容器安全监控")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("总告警", len(events))
col2.metric("待人工判决", (events['state'] == 'pending_review').sum())
col3.metric("已隔离 (quarantine)", (events['state'] == 'quarantine').sum())
col4.metric("流量阻断", int(events.get('netblocked', pd.Series(dtype=bool)).sum()))
col5.metric("AI 误报", (events.get('tier3_ai_verdict', pd.Series(dtype=str)) == 'false_positive').sum())

# ================================================================
# Container filter
# ================================================================
containers = sorted(events['container_id'].dropna().unique().tolist())
selected = st.selectbox("按容器筛选", ["全部"] + containers)

if selected != "全部":
    events = events[events['container_id'] == selected]

# ================================================================
# Human review queue (pending_review)
# ================================================================
st.header("⏳ 待人工判决队列")

pending = events[events['state'] == 'pending_review']
decided_keys = set()
if not decisions.empty and 'event_ts' in decisions.columns:
    decided_keys = set(decisions['event_ts'].astype(str))

if pending.empty:
    st.success("✅ 队列为空 — 当前没有需要人工判决的事件")
else:
    for _, ev in pending.iterrows():
        key = str(ev['timestamp'])
        if key in decided_keys:
            continue  # already decided
        with st.container(border=True):
            c1, c2 = st.columns([3, 1])
            with c1:
                sev = ev.get('severity', 'INFO')
                sev_color = {"CRITICAL": "🔴", "HIGH": "🟠",
                             "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                st.markdown(f"**{sev_color} [{sev}] {ev.get('rule', '?')}** "
                            f"— 容器 `{ev.get('container_id', '?')}`")
                st.caption(f"{ev.get('timestamp')} · "
                           f"事件类型: {ev.get('event_type', '?')} · "
                           f"矩阵置信度: {ev.get('tier2_confidence', '?')}%")
                if ev.get('tier3_ai_report'):
                    st.write(f"🤖 **AI 研判**: {ev['tier3_ai_report']}")
                if ev.get('tier3_ai_verdict'):
                    verdict = ev['tier3_ai_verdict']
                    verdict_str = ("✅ 真实攻击" if verdict == "true_positive"
                                   else "⚠️ 误报")
                    st.write(f"AI 判定: {verdict_str} "
                             f"(置信度 {ev.get('tier3_ai_confidence', '?')}%)")
                if ev.get('escalation'):
                    st.warning(f"⏫ 升级: {ev['escalation']}")
            with c2:
                if st.button("✅ 确认处置", key=f"confirm_{key}",
                             use_container_width=True):
                    record_decision(key, ev.get('container_id', ''),
                                    ev.get('rule', ''), 'confirmed')
                    st.success("已确认处置")
                    st.rerun()
                if st.button("❌ 驳回", key=f"dismiss_{key}",
                             use_container_width=True):
                    record_decision(key, ev.get('container_id', ''),
                                    ev.get('rule', ''), 'dismissed')
                    st.success("已驳回")
                    st.rerun()

# ================================================================
# Live alert stream
# ================================================================
st.header("📡 实时告警流")

# Merge decisions for display
if not decisions.empty and 'event_ts' in decisions.columns:
    dec_map = dict(zip(decisions['event_ts'].astype(str),
                       decisions['decision']))
    events['human_decision'] = events['timestamp'].astype(str).map(
        dec_map).fillna('')
else:
    events['human_decision'] = ''

display_cols = ['timestamp', 'severity', 'rule', 'container_id',
                'event_type', 'state', 'tier2_confidence',
                'tier3_ai_verdict', 'netblocked', 'human_decision']
existing = [c for c in display_cols if c in events.columns]
st.dataframe(
    events[existing].sort_values('timestamp', ascending=False).head(50),
    use_container_width=True,
    hide_index=True,
)

# ================================================================
# Blocked targets
# ================================================================
st.header("🚫 流量阻断记录")
blocked = events[events.get('netblocked', pd.Series(dtype=bool)) == True]
if blocked.empty:
    st.caption("暂无流量阻断记录")
else:
    st.dataframe(blocked[['timestamp', 'container_id', 'rule']],
                 use_container_width=True, hide_index=True)

st.sidebar.divider()
st.sidebar.caption(f"最后更新: {time.strftime('%H:%M:%S')}")
