#!/usr/bin/env python3
"""
eBPF Container Guard — 安全监控面板 (v0.3 prototype)

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


def record_decision(event_ts: str, container_id: str, rule: str,
                    decision: str):
    """Append a human verdict to decisions.log, then refresh caches."""
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'event_ts': event_ts,
        'container_id': container_id,
        'rule': rule,
        'decision': decision,
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
# Sidebar (static)
# ================================================================
st.sidebar.title("🛡️ eBPF Container Guard")
st.sidebar.caption("v0.3 prototype · 实时检测 · AI 研判 · 人机协同")
st.sidebar.caption(f"自动刷新: 每 {REFRESH_SECONDS} 秒")
st.sidebar.divider()
st.sidebar.subheader("📊 数据源")
st.sidebar.caption(f"events.log: {EVENTS_LOG.name}")
st.sidebar.caption(f"decisions.log: {DECISIONS_LOG.name}")

# ================================================================
# Main page
# ================================================================
st.title("🛡️ 容器安全监控")


def render_dynamic():
    """Dynamic section — auto-refreshes every REFRESH_SECONDS."""
    events = load_events()
    decisions = load_decisions()

    if events.empty:
        st.warning("⚠️ 暂无事件数据 — 请先运行: sudo python3 main.py")
        st.info("本面板每 3 秒自动读取 events.log，"
                "guard 检测到攻击后事件会自动出现在这里。")
        st.code("sudo python3 main.py   # 终端 1 启动 guard", language="bash")
        return

    # ---- Overview stats ----
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("总告警", len(events))
    c2.metric("待人工判决",
              int((events['state'] == 'pending_review').sum())
              if 'state' in events.columns else 0)
    c3.metric("已隔离 (quarantine)",
              int((events['state'] == 'quarantine').sum())
              if 'state' in events.columns else 0)
    netblocked = events.get('netblocked') if 'netblocked' in events.columns \
        else pd.Series(dtype=bool)
    c4.metric("流量阻断", int(netblocked.fillna(False).sum()))
    fp = events.get('tier3_ai_verdict') if 'tier3_ai_verdict' in events.columns \
        else pd.Series(dtype=str)
    c5.metric("AI 误报", int((fp == 'false_positive').sum()))

    # ---- Container filter ----
    containers = sorted(events['container_id'].dropna().unique().tolist())
    selected = st.selectbox("按容器筛选", ["全部"] + containers,
                            key="container_filter")
    if selected != "全部":
        events = events[events['container_id'] == selected]

    # ---- Human review queue ----
    st.header("⏳ 待人工判决队列")
    st.caption("AI 判定仅供参考 — 最终裁决权在人工。"
               "确认处置 = 认定真实攻击，执行不可逆动作（kill/拉黑）；"
               "驳回 = 认定误报/无害，不处置。")

    decided_keys = set()
    if not decisions.empty and 'event_ts' in decisions.columns:
        decided_keys = set(decisions['event_ts'].astype(str))

    pending = events[events['state'] == 'pending_review'] \
        if 'state' in events.columns else events.iloc[0:0]

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
                    st.markdown(f"**{sev_color} [{sev}] "
                                f"{ev.get('rule', '?')}** — "
                                f"容器 `{ev.get('container_id', '?')}`")
                    st.caption(f"{ev.get('timestamp')} · "
                               f"事件: {ev.get('event_type', '?')} · "
                               f"矩阵置信度: "
                               f"{ev.get('tier2_confidence', '?')}%")
                    if ev.get('tier3_ai_report'):
                        st.write(f"🤖 **AI 研判**: {ev['tier3_ai_report']}")
                    verdict = ev.get('tier3_ai_verdict')
                    if verdict:
                        vstr = ("✅ 真实攻击" if verdict == "true_positive"
                                else "⚠️ 误报")
                        st.write(f"AI 判定: {vstr} "
                                 f"(置信度 {ev.get('tier3_ai_confidence', '?')}%)")
                    else:
                        # 未触发 AI 研判 — 解释原因，避免误解为遗漏
                        conf2 = ev.get('tier2_confidence')
                        if ev.get('action') == 'block_image':
                            st.caption("🚫 镜像已被拉黑 — 最高置信度判决，"
                                       "无需 AI 研判")
                        elif conf2 and conf2 >= 85:
                            st.caption("🔴 矩阵高置信度 (≥85%) — "
                                       "确定性足够，未触发 AI 研判")
                        else:
                            st.caption("ℹ️ 未触发 AI 研判")
                    if ev.get('escalation'):
                        st.warning(f"⏫ 升级: {ev['escalation']}")

                    # ---- 证据视图：容器画像 + 行为时间线 ----
                    cid = ev.get('container_id', '')
                    with st.expander(f"🔍 判决证据 — 容器 {cid} 画像与行为时间线"):
                        profile = get_container_profile(cid)
                        if profile:
                            priv = "✅ 是（高危）" if profile['privileged'] \
                                else "❌ 否"
                            st.markdown(
                                f"**容器**: `{profile['name']}` · "
                                f"**镜像**: `{profile['image']}` · "
                                f"**状态**: {profile['status']} · "
                                f"**创建**: {profile['created']}")
                            st.markdown(
                                f"**Privileged**: {priv} · "
                                f"**端口映射**: {profile['ports']} · "
                                f"**PID**: {profile['pid']}")
                        else:
                            st.caption("⚠️ 容器已删除 — 只能依赖事件记录判决")

                        # 该容器全部事件时间线（攻击链）
                        cid_events = events[
                            events['container_id'] == cid
                        ].sort_values('timestamp')
                        if cid_events.empty:
                            st.caption("该容器无其他事件记录")
                        else:
                            st.caption(f"该容器共 {len(cid_events)} 条事件记录 "
                                       f"(攻击链):")
                            for _, ce in cid_events.iterrows():
                                sev_c = {"CRITICAL": "🔴", "HIGH": "🟠",
                                         "MEDIUM": "🟡"}.get(
                                             ce.get('severity', ''), "")
                                st.markdown(
                                    f"- `{str(ce['timestamp'])[11:19]}` "
                                    f"{sev_c} **{ce.get('rule', '?')}** · "
                                    f"{ce.get('event_type', '?')} · "
                                    f"置信度 {ce.get('tier2_confidence', '?')}%"
                                    f" · {ce.get('state', '?')}")
                with c2:
                    if st.button("✅ 确认处置",
                                 key=f"confirm_{key}",
                                 use_container_width=True,
                                 help="认定真实攻击 → 执行不可逆处置 (kill/拉黑)"):
                        record_decision(key, ev.get('container_id', ''),
                                        ev.get('rule', ''), 'confirmed')
                        st.toast("✅ 已确认处置 — 执行 kill/拉黑")
                        st.rerun()
                    if st.button("❌ 驳回",
                                 key=f"dismiss_{key}",
                                 use_container_width=True,
                                 help="认定误报/无害 → 不处置，解除隔离"):
                        record_decision(key, ev.get('container_id', ''),
                                        ev.get('rule', ''), 'dismissed')
                        st.toast("❌ 已驳回 — 误报，解除隔离")
                        st.rerun()

    # ---- Live alert stream ----
    st.header("📡 实时告警流")

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
        events[existing].sort_values('timestamp',
                                     ascending=False).head(50),
        use_container_width=True,
        hide_index=True,
    )

    # ---- Blocked targets ----
    st.header("🚫 流量阻断记录")
    blocked = events[
        events.get('netblocked', pd.Series(dtype=bool)).fillna(False) == True
    ] if 'netblocked' in events.columns else events.iloc[0:0]
    if blocked.empty:
        st.caption("暂无流量阻断记录")
    else:
        cols = [c for c in ['timestamp', 'container_id', 'rule']
                if c in blocked.columns]
        st.dataframe(blocked[cols], use_container_width=True,
                     hide_index=True)


render_dynamic()

st.caption(f"最后更新: {time.strftime('%H:%M:%S')} · "
           f"面板进程与 guard 独立运行")
