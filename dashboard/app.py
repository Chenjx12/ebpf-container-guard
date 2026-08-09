#!/usr/bin/env python3
"""
eBPF Container Guard — 安全监控面板 (v0.3.7, multi-page)

Streamlit multi-page dashboard:
  - 📊 概览        overview.py      — metrics + container filter
  - ⏳ 判决队列     review_queue.py  — container-level human verdicts + evidence
  - 🧠 AI 建议规则  ai_rules.py      — unknown attack discovery review
  - 📜 规则管理     rules.py         — view/add/audit rules
  - ⚙️ 设置        settings.py      — AI config (hot-reload)
  - 📡 实时告警流   alerts.py        — alert stream + netblock records

Run:  streamlit run dashboard/app.py
"""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))

from common import REFRESH_SECONDS

st.set_page_config(
    page_title="eBPF Container Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.sidebar.title("🛡️ eBPF Container Guard")
st.sidebar.caption("v0.3.7 · 实时检测 · AI 研判 · 人机协同")
st.sidebar.caption(f"自动刷新: 每 {REFRESH_SECONDS} 秒")
st.sidebar.divider()

# ================================================================
# Multi-page navigation (v0.3.7)
# ================================================================
pages = [
    st.Page("pages/overview.py", title="概览", icon="📊",
            default=True),
    st.Page("pages/review_queue.py", title="判决队列", icon="⏳"),
    st.Page("pages/ai_rules.py", title="AI 建议规则", icon="🧠"),
    st.Page("pages/rules.py", title="规则管理", icon="📜"),
    st.Page("pages/alerts.py", title="实时告警流", icon="📡"),
    st.Page("pages/settings.py", title="设置", icon="⚙️"),
]

pg = st.navigation(pages)
pg.run()

st.sidebar.divider()
st.sidebar.caption("数据源: events.log · decisions.log · "
                   "ai_results.log · rules.yaml")
