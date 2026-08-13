"""📜 规则管理 — 查看（所有角色）/ 添加（admin+运维，安全员需token）/ 审计 (v0.3.8)

v0.4.0: 条件表单改为多行（字段 + 操作符 + 值），event_type 为顶层键。
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
import streamlit as st

from common import (load_rules, load_rule_audit, append_rule_to_yaml, TOKENS,
                    CONDITION_OPS, parse_condition_rows)


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
                                 'attack_vector', 'event_type']
                     if c in rules_df.columns]
        st.dataframe(rules_df[show_cols], use_container_width=True,
                     hide_index=True)
        with st.expander("🔍 规则条件详情 (YAML)"):
            for _, r in rules_df.iterrows():
                st.markdown(f"**{r.get('name')}** "
                            f"`{r.get('event_type', '?')}`")
                st.code(yaml.dump(r.get('condition', {}), allow_unicode=True),
                        language="yaml")

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
            st.caption("条件行: 字段 + 操作符 + 值。"
                       "多行之间为 AND；值用逗号分隔 = OR 列表；"
                       "操作符支持 neq/startswith/endswith/contains/glob")
            cond_rows = []
            for i in range(3):
                fc1, fc2, fc3 = st.columns([2, 2, 3])
                field = fc1.text_input(
                    "字段", key=f"cond_f{i}",
                    placeholder="如 fstype / comm / target_path")
                op = fc2.selectbox("操作符", CONDITION_OPS, key=f"cond_o{i}")
                value = fc3.text_input(
                    "值", key=f"cond_v{i}",
                    placeholder="如 proc / nsenter / /etc/shadow, /tmp/x")
                cond_rows.append((field, op, value))
            submitted = st.form_submit_button("✅ 添加规则")

            if submitted:
                if not can_add:
                    st.error("⛔ 无权限添加规则")
                elif not rule_name:
                    st.error("规则名必填")
                else:
                    nodes = parse_condition_rows(cond_rows)
                    if not nodes:
                        st.error("至少填写一行条件（字段 + 值）")
                    else:
                        rule = {
                            'name': rule_name,
                            'description': description or f"手动添加: {rule_name}",
                            'severity': severity,
                            'event_type': event_type,
                            'condition': (nodes[0] if len(nodes) == 1
                                          else {"all": nodes}),
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
