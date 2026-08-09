#!/usr/bin/env python3
"""
eBPF Container Guard — 安全监控面板 (v0.3.8, RBAC)

Multi-page dashboard with role-based access control:
  - Login required (admin / operator / analyst)
  - Navigation filtered by role
  - Temporary tokens for privileged ops (v0.3.8)

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
st.sidebar.caption("v0.3.8 · 实时检测 · AI 研判 · 人机协同")

logged_in = st.session_state.get('logged_in', False)
if logged_in:
    username = st.session_state['username']
    role = st.session_state['role']
    st.sidebar.markdown(f"👤 **{username}** · "
                        f"{ROLE_LABELS.get(role, role)}")

    # 修改密码（所有角色，侧边栏直达）
    with st.sidebar.expander("🔑 修改密码", expanded=False):
        with st.form("sidebar_change_pw"):
            old_pw = st.text_input("当前密码", type="password",
                                   key="sb_old")
            new_pw = st.text_input("新密码（≥6位）", type="password",
                                   key="sb_new")
            if st.form_submit_button("修改密码"):
                if not AUTH.verify(username, old_pw):
                    st.error("❌ 当前密码错误")
                elif len(new_pw) < 6:
                    st.error("新密码至少 6 位")
                elif AUTH.change_password(username, new_pw):
                    st.toast("✅ 密码已修改")
                    st.rerun()

    if st.sidebar.button("🚪 退出登录"):
        for k in ['username', 'role', 'logged_in']:
            st.session_state.pop(k, None)
        st.rerun()
else:
    st.sidebar.caption("未登录")

st.sidebar.divider()

# ================================================================
# Navigation (role-filtered)
# ================================================================

# Pages visible to all roles
common_pages = [
    st.Page("pages/overview.py", title="概览", icon="📊", default=True),
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
