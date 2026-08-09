#!/usr/bin/env python3
"""
eBPF Container Guard — 安全监控面板 (v0.3.3)

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
AI_RESULTS_LOG = SCRIPT_DIR / "ai_results.log"

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

RULES_PATH = SCRIPT_DIR / "config" / "rules.yaml"


def append_rule_to_yaml(rule: dict) -> bool:
    """Append an AI-suggested rule to rules.yaml (v0.3.4).

    Guard's hot-reload watcher (v0.3.3) picks it up within 3s.
    """
    try:
        import yaml
        block = yaml.safe_dump(rule, allow_unicode=True,
                               sort_keys=False, default_flow_style=False)
        # 缩进为 rules 列表项格式: "  - name: ..." 子字段 4 空格
        indented = "  - " + block.replace("\n", "\n    ").strip()
        with open(RULES_PATH, 'a') as f:
            f.write("\n" + indented + "\n")
        return True
    except Exception as e:
        st.error(f"规则写入失败: {e}")
        return False


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
# Sidebar (static)
# ================================================================
st.sidebar.title("🛡️ eBPF Container Guard")
st.sidebar.caption("v0.3.3 · 实时检测 · AI 研判 · 人机协同")
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
    ai_results = load_ai_results()

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

    # ---- Human review queue (container-level) ----
    st.header("⏳ 待人工判决队列")
    st.caption("判决粒度 = **容器**（处置动作作用于容器）。"
               "确认处置 = 认定真实攻击 → kill/拉黑该容器（其全部事件联动标记）；"
               "驳回 = 认定误报/无害 → 解除隔离。"
               "AI 判定仅供参考，最终裁决权在人工。")

    # AI 异步结果映射（v0.3.2）：event timestamp -> AI verdict
    ai_map = {}
    if not ai_results.empty and 'event_ts' in ai_results.columns:
        for _, ar in ai_results.iterrows():
            ai_map[str(ar['event_ts'])] = ar

    # 已判决的容器（decisions.log 按 container_id 记录）
    decided_containers = set()
    if not decisions.empty and 'container_id' in decisions.columns:
        decided_containers = set(decisions['container_id'].astype(str))

    pending = events[events['state'] == 'pending_review'] \
        if 'state' in events.columns else events.iloc[0:0]

    if pending.empty:
        st.success("✅ 队列为空 — 当前没有需要人工判决的事件")
    else:
        # 按容器分组
        for cid, group in pending.groupby('container_id'):
            if str(cid) in decided_containers:
                continue  # 该容器已判决 → 全部事件联动标记，跳过

            with st.container(border=True):
                # ---- 容器头部 + 画像摘要 ----
                profile = get_container_profile(cid)
                if profile:
                    priv = "✅ 特权" if profile['privileged'] else "普通"
                    st.markdown(f"**📦 容器 `{cid}`** — "
                                f"`{profile['name']}` · "
                                f"镜像 `{profile['image']}` · "
                                f"{profile['status']} · {priv}")
                else:
                    st.markdown(f"**📦 容器 `{cid}`** — ⚠️ 已删除")

                n_pending = len(group)
                st.caption(f"该容器 {n_pending} 条待判决事件 — "
                           f"处置作用于整个容器，事件联动标记")

                # ---- 该容器的全部待判决事件 ----
                for _, ev in group.sort_values('timestamp').iterrows():
                    sev = ev.get('severity', 'INFO')
                    sev_color = {"CRITICAL": "🔴", "HIGH": "🟠",
                                 "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                    st.markdown(
                        f"- {sev_color} `{str(ev['timestamp'])[11:19]}` "
                        f"**{ev.get('rule', '?')}** · "
                        f"{ev.get('event_type', '?')} · "
                        f"矩阵置信度 {ev.get('tier2_confidence', '?')}%")
                    # v0.3.2: AI 结果来自 ai_results.log（异步回填）
                    ai_row = ai_map.get(str(ev['timestamp']))
                    if ai_row is not None:
                        vstr = ("✅ 攻击" if ai_row['ai_verdict']
                                == "true_positive" else "⚠️ 误报")
                        st.markdown(f"  🤖 AI: {vstr} "
                                    f"({ai_row['ai_confidence']}%) — "
                                    f"{ai_row.get('ai_report', '')[:80]}")
                    else:
                        conf2 = ev.get('tier2_confidence')
                        if ev.get('action') == 'block_image':
                            st.markdown("  🚫 镜像已拉黑 — 无需 AI 研判")
                        elif conf2 and conf2 >= 85:
                            st.markdown("  🔴 矩阵高置信度 — 未触发 AI 研判")
                        else:
                            st.markdown("  ⏳ AI 研判中…（异步回填）")
                    if ev.get('escalation'):
                        st.markdown(f"  ⏫ 升级: {ev['escalation']}")

                # ---- 证据视图：行为时间线（该容器全部事件）----
                with st.expander(f"🔍 判决证据 — 容器 {cid} 行为时间线"):
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

                # ---- 容器级判决按钮 ----
                b1, b2 = st.columns(2)
                with b1:
                    if st.button("✅ 确认处置（kill/拉黑容器）",
                                 key=f"confirm_{cid}",
                                 use_container_width=True,
                                 help="认定真实攻击 → 执行不可逆处置，"
                                      "该容器全部事件联动标记"):
                        record_decision(cid, 'confirmed',
                                        event_count=n_pending)
                        st.toast(f"✅ 已确认处置容器 {cid} — "
                                 f"{n_pending} 条事件联动标记")
                        st.rerun()
                with b2:
                    if st.button("❌ 驳回（误报，解除隔离）",
                                 key=f"dismiss_{cid}",
                                 use_container_width=True,
                                 help="认定误报/无害 → 不处置，"
                                      "该容器全部事件联动标记"):
                        record_decision(cid, 'dismissed',
                                        event_count=n_pending)
                        st.toast(f"❌ 已驳回容器 {cid} — "
                                 f"{n_pending} 条事件联动标记")
                        st.rerun()

    # ---- AI suggested rules (v0.3.4) ----
    st.header("🧠 AI 建议规则")
    st.caption("AI 在研判中发现未知攻击模式时建议新规则 — "
               "人工审核后一键入库（规则热加载自动生效）")

    # 已处理的建议（decisions.log scope=suggested_rule）
    processed_suggestions = set()
    if not decisions.empty and 'scope' in decisions.columns:
        processed_suggestions = set(
            decisions[decisions['scope'] == 'suggested_rule']
            ['container_id'].astype(str))

    suggestions = []
    if not ai_results.empty and 'suggested_rule' in ai_results.columns:
        for _, ar in ai_results.iterrows():
            if ar.get('suggested_rule'):
                suggestions.append(ar)

    if not suggestions:
        st.success("暂无 AI 建议规则 — AI 未发现未知攻击模式")
    else:
        for ar in suggestions:
            key = str(ar['event_ts'])
            if key in processed_suggestions:
                continue
            rule = ar['suggested_rule']
            with st.container(border=True):
                st.markdown(f"**🤖 AI 建议新规则**: "
                            f"`{rule.get('name', 'unnamed')}`")
                st.markdown(f"描述: {rule.get('description', '-')} · "
                            f"严重度: {rule.get('severity', '-')}")
                st.code(str(rule.get('condition', {})), language="yaml")
                st.caption(f"来源事件: {key} · 攻击向量: "
                           f"{ar.get('attack_vector', '?')}")
                b1, b2 = st.columns(2)
                with b1:
                    if st.button("✅ 确认入库",
                                 key=f"rule_confirm_{key}",
                                 use_container_width=True,
                                 help="追加到 rules.yaml，热加载立即生效"):
                        if append_rule_to_yaml(rule):
                            record_decision(key, 'confirmed', scope='suggested_rule')
                            st.toast(f"✅ 规则 {rule.get('name')} 已入库并生效")
                            st.rerun()
                        else:
                            st.error("规则写入失败")
                with b2:
                    if st.button("❌ 拒绝",
                                 key=f"rule_dismiss_{key}",
                                 use_container_width=True,
                                 help="拒绝该建议规则"):
                        record_decision(key, 'dismissed', scope='suggested_rule')
                        st.toast(f"❌ 已拒绝规则 {rule.get('name')}")
                        st.rerun()

    # ---- Live alert stream ----
    st.header("📡 实时告警流")

    # 容器级判决联动：decisions.log 按 container_id 记录
    if not decisions.empty and 'container_id' in decisions.columns:
        dec_map = dict(zip(decisions['container_id'].astype(str),
                           decisions['decision']))
        events['human_decision'] = events['container_id'].astype(str).map(
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
