"""📊 概览 — 系统指标 + 容器筛选 (v0.3.7)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import streamlit as st

from common import load_events, load_decisions, load_ai_results


def run():
    st.title("🛡️ 容器安全监控")

    events = load_events()
    decisions = load_decisions()
    ai_results = load_ai_results()

    if events.empty:
        st.warning("⚠️ 暂无事件数据")
        st.info("检测系统运行中 — 检测到攻击后事件会自动出现在这里。\n"
                "若长时间无数据，请确认检测服务已由部署者启动。")
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

    # ---- AI 状态 ----
    import yaml as _yaml
    ai_cfg = {}
    ai_path = Path(__file__).parent.parent / "config" / "ai_config.yaml"
    if ai_path.exists():
        try:
            ai_cfg = _yaml.safe_load(open(ai_path)) or {}
        except Exception:
            pass
    ai_status = "✅ 已启用" if ai_cfg.get('api_key') else "⚠️ 未配置"
    st.caption(f"AI 研判: {ai_status} · 模型 `{ai_cfg.get('model', 'deepseek-chat')}` · "
               f"AI 研判记录 {len(ai_results) if not ai_results.empty else 0} 条")

    # ---- Container filter ----
    containers = sorted(events['container_id'].dropna().unique().tolist())
    selected = st.selectbox("按容器筛选", ["全部"] + containers,
                            key="container_filter")
    if selected != "全部":
        events = events[events['container_id'] == selected]

    # ---- 最近事件快速预览 ----
    st.subheader("最近事件")
    cols = [c for c in ['timestamp', 'severity', 'rule', 'container_id',
                        'state'] if c in events.columns]
    st.dataframe(events[cols].sort_values('timestamp', ascending=False)
                 .head(10), use_container_width=True, hide_index=True)


run()
