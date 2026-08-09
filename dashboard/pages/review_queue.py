"""⏳ 待人工判决队列 — 容器级判决 + 证据视图 (v0.3.7)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from common import (load_events, load_decisions, load_ai_results,
                    get_container_profile, record_decision)


def run():
    st.title("⏳ 待人工判决队列")
    st.caption("判决粒度 = **容器**（处置动作作用于容器）。"
               "确认处置 = 认定真实攻击 → kill/拉黑该容器（其全部事件联动标记）；"
               "驳回 = 认定误报/无害 → 解除隔离。"
               "AI 判定仅供参考，最终裁决权在人工。")

    events = load_events()
    decisions = load_decisions()
    ai_results = load_ai_results()

    if events.empty:
        st.info("暂无事件数据 — guard 检测到攻击后自动出现")
        return

    # AI 异步结果映射（v0.3.2）
    ai_map = {}
    if not ai_results.empty and 'event_ts' in ai_results.columns:
        for _, ar in ai_results.iterrows():
            ai_map[str(ar['event_ts'])] = ar

    # 已判决的容器
    decided_containers = set()
    if not decisions.empty and 'container_id' in decisions.columns:
        decided_containers = set(decisions['container_id'].astype(str))

    pending = events[events['state'] == 'pending_review'] \
        if 'state' in events.columns else events.iloc[0:0]

    if pending.empty:
        st.success("✅ 队列为空 — 当前没有需要人工判决的事件")
        return

    for cid, group in pending.groupby('container_id'):
        if str(cid) in decided_containers:
            continue

        with st.container(border=True):
            # 容器头部 + 画像摘要
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

            # 该容器的全部待判决事件
            for _, ev in group.sort_values('timestamp').iterrows():
                sev = ev.get('severity', 'INFO')
                sev_color = {"CRITICAL": "🔴", "HIGH": "🟠",
                             "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                st.markdown(
                    f"- {sev_color} `{str(ev['timestamp'])[11:19]}` "
                    f"**{ev.get('rule', '?')}** · "
                    f"{ev.get('event_type', '?')} · "
                    f"矩阵置信度 {ev.get('tier2_confidence', '?')}%")
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

            # 证据视图
            with st.expander(f"🔍 判决证据 — 容器 {cid} 行为时间线"):
                cid_events = events[
                    events['container_id'] == cid].sort_values('timestamp')
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

            # 判决按钮
            b1, b2 = st.columns(2)
            with b1:
                if st.button("✅ 确认处置（kill/拉黑容器）",
                             key=f"confirm_{cid}",
                             use_container_width=True,
                             help="认定真实攻击 → 执行不可逆处置，"
                                  "该容器全部事件联动标记"):
                    record_decision(cid, 'confirmed', event_count=n_pending)
                    st.toast(f"✅ 已确认处置容器 {cid} — "
                             f"{n_pending} 条事件联动标记")
                    st.rerun()
            with b2:
                if st.button("❌ 驳回（误报，解除隔离）",
                             key=f"dismiss_{cid}",
                             use_container_width=True,
                             help="认定误报/无害 → 不处置，"
                                  "该容器全部事件联动标记"):
                    record_decision(cid, 'dismissed', event_count=n_pending)
                    st.toast(f"❌ 已驳回容器 {cid} — "
                             f"{n_pending} 条事件联动标记")
                    st.rerun()


run()
