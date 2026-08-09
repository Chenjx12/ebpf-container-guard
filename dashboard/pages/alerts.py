"""📡 实时告警流 + 🚫 流量阻断记录 (v0.3.7)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import streamlit as st

from common import load_events, load_decisions


def run():
    st.title("📡 实时告警流")

    events = load_events()
    decisions = load_decisions()

    if events.empty:
        st.info("暂无事件数据 — guard 检测到攻击后自动出现")
        return

    # 容器级判决联动
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

    # 流量阻断记录
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


run()
