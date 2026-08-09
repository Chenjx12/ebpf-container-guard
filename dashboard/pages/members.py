"""👥 成员管理 — admin 添加成员; admin+运维查看 (v0.3.8)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from common import AUTH, TOKENS

ROLE_LABELS = {'admin': '管理员', 'operator': '运维', 'analyst': '安全员'}


def run():
    username = st.session_state.get('username', '')
    role = st.session_state.get('role', '')

    if role not in ('admin', 'operator'):
        st.error("⛔ 无权限访问成员管理")
        return

    st.title("👥 成员管理")
    st.caption("一个成员仅能是一种角色；创建时强制设置密码（≥6位）")

    # ---- 成员列表（admin + operator 可见）----
    st.subheader("当前成员")
    users = AUTH.list_users()
    if users:
        import pandas as pd
        df = pd.DataFrame(users, columns=['用户名', '角色', '创建时间'])
        df['角色'] = df['角色'].map(lambda r: ROLE_LABELS.get(r, r))
        st.dataframe(df, use_container_width=True, hide_index=True)

    # ---- 添加成员（admin 直接; operator 需 token）----
    st.subheader("添加成员")
    if role == 'admin':
        _show_add_form(bypass_token=True)
    else:
        # operator: token-gated
        st.caption("🔑 添加成员需要 admin 发放的临时 token")
        with st.form("op_token_form"):
            token = st.text_input("临时 token", type="password",
                                  placeholder="向 admin 索取")
            submit = st.form_submit_button("验证 token")
            if submit:
                if TOKENS.verify(token, 'add_member', username):
                    st.session_state['member_token_ok'] = True
                    st.success("✅ token 有效 — 可以添加成员")
                    st.rerun()
                else:
                    st.error("❌ token 无效或已过期")

        if st.session_state.get('member_token_ok', False):
            _show_add_form(bypass_token=True)


def _show_add_form(bypass_token=True):
    """添加成员表单（admin 或 token 验证通过后）"""
    with st.form("add_member_form"):
        c1, c2 = st.columns(2)
        new_user = c1.text_input("用户名", placeholder="如 analyst_2")
        new_role = c2.selectbox("角色", ["analyst", "operator"],
                                format_func=lambda r:
                                ROLE_LABELS.get(r, r))
        new_pw = st.text_input("初始密码（强制设置，≥6位）",
                               type="password")
        submit = st.form_submit_button("✅ 创建成员")

        if submit:
            if not new_user or len(new_pw) < 6:
                st.error("用户名必填，密码至少 6 位")
            elif AUTH.create_user(new_user, new_pw, new_role):
                st.toast(f"✅ 已创建 {new_user} ({ROLE_LABELS.get(new_role)})")
                st.rerun()
            else:
                st.error("创建失败（用户名已存在或角色无效）")


run()
