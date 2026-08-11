"""行为日志 — 全量 syscall 事件检索 (v0.3.10)

Read-only analyzer: filter by event_type / container / comm / time range.
Loads from behaviors.log written by BehaviorLogger.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

from common import load_behavior_log

# ================================================================
# Sidebar: filter controls
# ================================================================
st.sidebar.header("🔍 筛选条件")

# --- Time range ---
TIME_OPTIONS = {
    "最近 1 分钟": timedelta(minutes=1),
    "最近 5 分钟": timedelta(minutes=5),
    "最近 30 分钟": timedelta(minutes=30),
    "全部": None,
    "自定义": "custom",
}
time_label = st.sidebar.selectbox(
    "时间范围", list(TIME_OPTIONS.keys()), index=2
)
time_delta = TIME_OPTIONS[time_label]

custom_start = custom_end = None
if time_label == "自定义":
    col1, col2 = st.sidebar.columns(2)
    custom_start = col1.date_input("开始日期", datetime.now().date())
    custom_end = col2.date_input("结束日期", datetime.now().date())

# --- Event type ---
EVENT_TYPES = ["mount", "ptrace", "execve", "connect", "openat"]
selected_types = st.sidebar.multiselect(
    "行为类型", EVENT_TYPES, default=EVENT_TYPES,
    help="空 = 不筛选"
)

# --- Container filter ---
st.sidebar.markdown("**容器/宿主机**")
host_filter = st.sidebar.radio(
    "范围", ["全部", "仅容器", "仅宿主机(host)"], horizontal=True,
    label_visibility="collapsed"
)

# --- Page size ---
page_size = st.sidebar.selectbox("每页行数", [50, 100, 200, 500], index=0)

# ================================================================
# Main area
# ================================================================
st.title("📋 全量行为日志")
st.caption("所有 eBPF syscall 事件的原始记录。筛选后查看，高频事件不会自动滚动。")

# Load data (in fragment so it auto-refreshes)
@st.fragment(run_every=5)
def _render():
    df = load_behavior_log()
    if df.empty:
        st.info("behaviors.log 为空或不存在，请确认 guard 已启动且 behavior_log 已启用。")
        return

    # Apply filters
    filtered = df.copy()

    # Time filter
    if custom_start and custom_end:
        start_dt = datetime.combine(custom_start, datetime.min.time())
        end_dt = datetime.combine(custom_end, datetime.max.time())
        filtered = filtered[
            (filtered["timestamp"] >= start_dt) & (filtered["timestamp"] <= end_dt)
        ]
    elif time_delta is not None:
        cutoff = datetime.now() - time_delta
        filtered = filtered[filtered["timestamp"] >= cutoff]

    # Event type filter
    if selected_types:
        filtered = filtered[filtered["event_type"].isin(selected_types)]

    # Host filter
    if host_filter == "仅容器":
        filtered = filtered[filtered["container_id"] != "host"]
    elif host_filter == "仅宿主机(host)":
        filtered = filtered[filtered["container_id"] == "host"]

    if filtered.empty:
        st.info("筛选条件下无匹配记录。")
        return

    # Sort newest first
    filtered = filtered.sort_values("timestamp", ascending=False)

    # Extract container dropdown from filtered data
    container_ids = sorted(filtered["container_id"].dropna().unique())
    with st.sidebar:
        sel_containers = st.multiselect(
            "容器 ID", container_ids, default=[],
            help="空 = 不筛选"
        )

    if sel_containers:
        filtered = filtered[filtered["container_id"].isin(sel_containers)]

    # Build display columns
    display_cols = {
        "timestamp": "时间",
        "event_type": "行为类型",
        "container_id": "容器",
        "comm": "进程",
        "pid": "PID",
        "uid": "UID",
        "target_path": "路径",
        "fstype": "文件系统",
        "target_pid": "目标 PID",
        "request": "请求",
    }
    # Add daddr:dport composite
    has_net = filtered["daddr"].notna().any()
    if has_net:
        filtered["目标地址"] = filtered.apply(
            lambda r: (
                f"{((int(r['daddr'])>>24)&0xFF)}."
                f"{((int(r['daddr'])>>16)&0xFF)}."
                f"{((int(r['daddr'])>>8)&0xFF)}."
                f"{int(r['daddr'])&0xFF}"
                f":{int(r['dport']) if pd.notna(r['dport']) else ''}"
            ) if pd.notna(r["daddr"]) else "",
            axis=1,
        )
        display_cols["目标地址"] = "目标地址"

    available = [c for c in display_cols if c in filtered.columns]
    shown = filtered[available].rename(columns=display_cols)

    # Pagination
    total = len(shown)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = st.number_input(
        f"页 (共 {total} 条)", min_value=1, max_value=total_pages,
        value=1,
    )
    start = (page - 1) * page_size
    end = min(start + page_size, total)

    st.dataframe(
        shown.iloc[start:end],
        use_container_width=True,
        hide_index=True,
        height=min(45 * (end - start) + 10, 600),
    )

    st.caption(f"第 {page}/{total_pages} 页 · {total} 条匹配")

_render()
