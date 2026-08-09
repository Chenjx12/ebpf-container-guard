"""📜 规则管理 — 查看（所有角色）/ 添加（admin+运维，安全员需token）/ 审计 (v0.3.8)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from common import load_rules, load_rule_audit, append_rule_to_yaml, TOKENS


def run():
    username = st.session_state.get('username', '')
    role = st.session_state.get('role', '')

    st.title("📜 规则管理")
    st.caption("查看现有检测规则、手动添加规则 — 所有变更记录审计日志，"
               "热加载 3 秒生效。"
               "（安全员可查看规则以辅助研判；添加规则需 admin/运维 或临时 token）")

    # ---- 查看规则：所有角色 ----
    rules_df = load_rules()
    if not rules_df.empty:
        show_cols = [c for c in ['name', 'severity', 'description',
                                 'attack_vector'] if c in rules_df.columns]
        st.dataframe(rules_df[show_cols], use_container_width=True,
                     hide_index=True)

    # ---- 添加规则：admin/operator 直接; analyst 需 token ----
    can_add = role in ('admin', 'operator')
    if not can_add:
        with st.expander("🔑 添加规则（需临时 token）"):
            st.caption("向 admin/运维 索取 add_rule 临时 token")
            with st.form("analyst_rule_token"):
                token = st.text_input("临时 token", type="password")
                if st.form_submit_button("验证 token"):
                    if TOKENS.verify(token, 'add_rule', username):
                        st.session_state['rule_token_ok'] = True
                        st.success("✅ token 有效")
                        st.rerun()
                    else:
                        st.error("❌ token 无效或已过期")
        can_add = st.session_state.get('rule_token_ok', False)

    # 手动添加规则表单
    with st.expander("➕ 手动添加规则", expanded=can_add):
        if not can_add:
            st.caption("⛔ 无权限 — 需要 admin/运维 权限或临时 token")
        with st.form("manual_rule_form"):
            c1, c2 = st.columns(2)
            rule_name = c1.text_input("规则名 (英文+下划线)",
                                      placeholder="manual_rule_1")
            severity = c2.selectbox("严重度", ["CRITICAL", "HIGH",
                                              "MEDIUM", "LOW"])
            description = st.text_input("描述")
            c3, c4 = st.columns(2)
            event_type = c3.selectbox("事件类型", ["mount", "ptrace",
                                                  "openat", "execve",
                                                  "connect"])
            attack_vector = c4.text_input("攻击向量 (可选)",
                                          placeholder="my_vector")
            condition_key = st.text_input("条件字段名",
                                          placeholder="如 fstype / comm / target_path")
            condition_value = st.text_input("条件值",
                                            placeholder="如 proc / nsenter / /etc/shadow")
            submitted = st.form_submit_button("✅ 添加规则")

            if submitted:
                if not can_add:
                    st.error("⛔ 无权限添加规则")
                elif not rule_name or not condition_key or not condition_value:
                    st.error("规则名和条件必填")
                else:
                    rule = {
                        'name': rule_name,
                        'description': description or f"手动添加: {rule_name}",
                        'severity': severity,
                        'condition': {
                            'event_type': event_type,
                            condition_key: condition_value,
                        },
                        'action': 'alert_and_log',
                    }
                    if attack_vector:
                        rule['attack_vector'] = attack_vector
                    if append_rule_to_yaml(rule, source='manual'):
                        load_rules.clear()
                        st.toast(f"✅ 规则 {rule_name} 已添加并生效")
                        st.rerun()

    # 规则变更审计历史
    audit_df = load_rule_audit()
    if not audit_df.empty:
        with st.expander(f"📋 规则变更审计 ({len(audit_df)} 条)"):
            acols = [c for c in ['timestamp', 'action', 'rule_name',
                                 'source'] if c in audit_df.columns]
            st.dataframe(audit_df[acols].sort_values(
                'timestamp', ascending=False), use_container_width=True,
                hide_index=True)


run()
