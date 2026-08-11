"""🔐 登录 — 进入面板前认证 (v0.3.8)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from auth import AuthManager
from common import AUTH

ROLE_LABELS = {'admin': '管理员', 'operator': '运维', 'analyst': '安全员'}


def run():
    st.title("🔐 登录 eBPF Container Guard")
    st.caption("角色: 管理员(admin) > 运维(operator) > 安全员(analyst)")

    with st.form("login_form"):
        username = st.text_input("用户名")
        password = st.text_input("密码", type="password")
        submitted = st.form_submit_button("登录", use_container_width=True)

        if submitted:
            if not username or not password:
                st.error("请输入用户名和密码")
            elif AUTH.verify(username, password):
                role = AUTH.get_role(username)
                st.session_state['username'] = username
                st.session_state['role'] = role
                st.session_state['logged_in'] = True
                # v0.3.10: force password change for initial passwords
                if AUTH.is_initial_password(username):
                    st.session_state['must_change_pw'] = True
                    st.rerun()
                st.toast(f"✅ 欢迎, {username} ({ROLE_LABELS.get(role, role)})")
                st.rerun()
            else:
                st.error("❌ 用户名或密码错误")


run()
