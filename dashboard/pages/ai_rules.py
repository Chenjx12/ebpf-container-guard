"""🧠 AI 建议规则 — 未知攻击发现审核 (v0.3.7)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
import streamlit as st

from common import (load_ai_results, load_decisions, load_rules,
                    load_rule_audit, append_rule_to_yaml, record_decision)


def run():
    st.title("🧠 AI 建议规则")
    st.caption("AI 在研判中发现未知攻击模式时建议新规则 — "
               "人工审核后一键入库（规则热加载自动生效）")

    ai_results = load_ai_results()
    decisions = load_decisions()

    # 已处理的建议
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
        return

    for ar in suggestions:
        key = str(ar['event_ts'])
        if key in processed_suggestions:
            continue
        rule = ar['suggested_rule']
        with st.container(border=True):
            st.markdown(f"**🤖 AI 建议新规则**: "
                        f"`{rule.get('name', 'unnamed')}`")
            st.markdown(f"描述: {rule.get('description', '-')} · "
                        f"严重度: {rule.get('severity', '-')} · "
                        f"事件类型: `{rule.get('event_type', '?')}`")
            st.code(yaml.dump(rule, allow_unicode=True,
                              sort_keys=False), language="yaml")
            st.caption(f"来源事件: {key} · 攻击向量: "
                       f"{ar.get('attack_vector', '?')}")
            b1, b2 = st.columns(2)
            with b1:
                if st.button("✅ 确认入库",
                             key=f"rule_confirm_{key}",
                             use_container_width=True,
                             help="追加到 rules.yaml，热加载立即生效"):
                    if append_rule_to_yaml(rule):
                        record_decision(key, 'confirmed',
                                        scope='suggested_rule')
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


run()
