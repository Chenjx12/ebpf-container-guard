#!/usr/bin/env python3
"""
eBPF Container Guard — 安全监控面板 (v0.3.10, RBAC)

Multi-page dashboard with role-based access control:
  - Login required (admin / operator / analyst)
  - Navigation filtered by role
  - Temporary tokens for privileged ops (v0.3.8)
  - First-login forced password change (v0.3.10)

Run:  streamlit run dashboard/app.py
"""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))

from common import REFRESH_SECONDS, AUTH, TOKENS

ROLE_LABELS = {'admin': '管理员', 'operator': '运维', 'analyst': '安全员'}

st.set_page_config(
    page_title="eBPF Container Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ================================================================
# Initial admin bootstrap (first start — password printed to terminal)
# ================================================================
initial_pw = AUTH.ensure_initial_admin()
if initial_pw:
    print("=" * 60)
    print("🔐 首次启动 — 已创建初始管理员账号")
    print(f"   用户名: admin")
    print(f"   初始密码: {initial_pw}")
    print("   请立即登录后修改密码!")
    print("=" * 60)

# ================================================================
# Sidebar (user info / logout)
# ================================================================
st.sidebar.title("🛡️ eBPF Container Guard")
st.sidebar.caption("v0.3.10 · 实时检测 · AI 研判 · 人机协同")

logged_in = st.session_state.get('logged_in', False)
if logged_in:
    username = st.session_state['username']
    role = st.session_state['role']
    st.sidebar.markdown(f"👤 **{username}** · "
                        f"{ROLE_LABELS.get(role, role)}")

    # v0.3.10: logout only — password change moved to forced page
    if st.sidebar.button("🚪 退出登录"):
        for k in ['username', 'role', 'logged_in']:
            st.session_state.pop(k, None)
        st.rerun()
else:
    st.sidebar.caption("未登录")

st.sidebar.divider()

# ================================================================
# First-login: forced password change (v0.3.10)
# ================================================================
if logged_in and st.session_state.get('must_change_pw', False):
    st.title("🔄 首次登录 — 请修改初始密码")
    st.warning("您正在使用初始密码登录，为安全起见请立即修改密码。")

    with st.form("force_change_pw", clear_on_submit=True):
        new_pw = st.text_input("新密码（≥6位）", type="password",
                               key="fc_new")
        confirm_pw = st.text_input("确认新密码", type="password",
                                   key="fc_confirm")
        submitted = st.form_submit_button("修改密码并重新登录",
                                          use_container_width=True)

        if submitted:
            if not new_pw or not confirm_pw:
                st.error("请填写两个密码字段")
            elif len(new_pw) < 6:
                st.error("密码至少 6 位")
            elif new_pw != confirm_pw:
                st.error("两次输入的密码不一致")
            elif AUTH.change_password(username, new_pw):
                # Clear session to force re-login
                for k in ['username', 'role', 'logged_in', 'must_change_pw']:
                    st.session_state.pop(k, None)
                st.success("✅ 密码修改成功，请使用新密码重新登录")
                st.rerun()
            else:
                st.error("修改密码失败")

    st.stop()  # Don't render navigation below

# ================================================================
# Navigation (role-filtered)
# ================================================================

# Pages visible to all roles
common_pages = [
    st.Page("pages/overview.py", title="概览", icon="📊", default=True),
    st.Page("pages/behavior_log.py", title="行为日志", icon="📋"),
    st.Page("pages/review_queue.py", title="判决队列", icon="⏳"),
    st.Page("pages/ai_rules.py", title="AI 建议规则", icon="🧠"),
    st.Page("pages/rules.py", title="规则管理", icon="📜"),
    st.Page("pages/alerts.py", title="实时告警流", icon="📡"),
]

admin_pages = [
    st.Page("pages/members.py", title="成员管理", icon="👥"),
]

settings_pages = [
    st.Page("pages/settings.py", title="设置", icon="⚙️"),
]

if not logged_in:
    # Only login page visible before authentication
    pages = [st.Page("pages/login.py", title="登录", icon="🔐",
                     default=True)]
else:
    role = st.session_state['role']
    pages = list(common_pages)
    if role in ('admin', 'operator'):
        pages += settings_pages
    if role == 'admin':
        pages += admin_pages

pg = st.navigation(pages)
pg.run()

st.sidebar.divider()
st.sidebar.caption("数据源: events.log · decisions.log · "
                   "ai_results.log · rules.yaml")
