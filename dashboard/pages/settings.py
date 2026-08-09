"""⚙️ 设置 — AI 配置(admin+运维) / 改密码(所有) / 临时授权(admin+运维) (v0.3.8)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml as _yaml
import streamlit as st

from common import AI_CONFIG_PATH, AUTH, TOKENS

ROLE_LABELS = {'admin': '管理员', 'operator': '运维', 'analyst': '安全员'}


def run():
    username = st.session_state.get('username', '')
    role = st.session_state.get('role', '')

    st.title("⚙️ 设置")

    # ================================================================
    # 修改自己密码 — 所有角色
    # ================================================================
    st.subheader("🔑 修改密码")
    with st.form("change_pw_form"):
        old_pw = st.text_input("当前密码", type="password")
        new_pw = st.text_input("新密码（≥6位）", type="password")
        if st.form_submit_button("修改密码"):
            if not AUTH.verify(username, old_pw):
                st.error("❌ 当前密码错误")
            elif len(new_pw) < 6:
                st.error("新密码至少 6 位")
            elif AUTH.change_password(username, new_pw):
                st.toast("✅ 密码已修改")
                st.rerun()

    st.divider()

    # ================================================================
    # AI 配置 — admin + operator
    # ================================================================
    if role in ('admin', 'operator'):
        st.subheader("🤖 AI 配置")
        st.caption("填写后点击保存 — guard 热加载 3 秒生效，无需重启。"
                   "API Key 仅保存在本地 ai_config.yaml（gitignored）")

        ai_cfg = {}
        if AI_CONFIG_PATH.exists():
            try:
                with open(AI_CONFIG_PATH, 'r') as f:
                    ai_cfg = _yaml.safe_load(f) or {}
            except Exception:
                pass

        has_key = bool(ai_cfg.get('api_key'))
        ai_status = "✅ 已启用" if has_key else "⚠️ 未配置 (AI 研判禁用)"
        st.markdown(f"**当前状态**: {ai_status} · "
                    f"Model: `{ai_cfg.get('model', 'deepseek-chat')}` · "
                    f"Base URL: `{ai_cfg.get('base_url', 'https://api.deepseek.com/v1')}`")

        with st.form("ai_config_form"):
            base_url = st.text_input(
                "Base URL（OpenAI 兼容端点）",
                value=ai_cfg.get('base_url', 'https://api.deepseek.com/v1'),
                placeholder="https://api.deepseek.com/v1")
            model = st.text_input(
                "Model", value=ai_cfg.get('model', 'deepseek-chat'))
            key_placeholder = ("已配置 (sk-...%s)" % ai_cfg['api_key'][-4:]
                               if has_key else "sk-...")
            api_key = st.text_input(
                "API Key（留空 = 保留现有）",
                type="password", placeholder=key_placeholder)
            c1, c2 = st.columns(2)
            auto_th = c1.number_input(
                "自动响应阈值 (%)",
                value=int(ai_cfg.get('auto_response_threshold', 85)),
                min_value=0, max_value=100)
            review_th = c2.number_input(
                "人工研判阈值 (%)",
                value=int(ai_cfg.get('pending_review_threshold', 60)),
                min_value=0, max_value=100)
            save_ai = st.form_submit_button("💾 保存 AI 配置")

            if save_ai:
                new_cfg = {
                    'api_key': api_key if api_key else ai_cfg.get('api_key', ''),
                    'model': model,
                    'base_url': base_url,
                    'auto_response_threshold': int(auto_th),
                    'pending_review_threshold': int(review_th),
                }
                try:
                    with open(AI_CONFIG_PATH, 'w') as f:
                        _yaml.safe_dump(new_cfg, f, allow_unicode=True,
                                        sort_keys=False)
                    st.toast("✅ AI 配置已保存 — guard 热加载生效")
                    st.rerun()
                except Exception as e:
                    st.error(f"保存失败: {e}")

        st.divider()

        # ================================================================
        # 临时授权 token — admin 可发 add_member/add_rule; operator 仅 add_rule
        # ================================================================
        st.subheader("🔑 临时授权")
        st.caption("为低权限角色（如安全员）发放一次性临时 token，"
                   "用于越权操作（添加规则/成员）。"
                   "有效期 1-5 分钟，使用后自动失效，全程审计。")

        grantable = ['add_rule'] if role == 'operator' \
            else ['add_member', 'add_rule']
        purpose_labels = {'add_member': '添加成员', 'add_rule': '添加规则'}

        with st.form("grant_token_form"):
            c1, c2 = st.columns(2)
            purpose = c1.selectbox(
                "授权用途",
                grantable,
                format_func=lambda p: purpose_labels.get(p, p))
            ttl = c2.slider("有效期（分钟）", 1, 5, 3)
            if st.form_submit_button("🎫 生成临时 token"):
                token = TOKENS.generate(purpose, username, ttl=ttl * 60)
                if token:
                    st.session_state['generated_token'] = token
                    st.session_state['token_purpose'] = purpose
                    st.rerun()
                else:
                    st.error("生成失败（权限或用途不合法）")

        if st.session_state.get('generated_token'):
            t = st.session_state['generated_token']
            p = st.session_state['token_purpose']
            st.code(t)
            st.caption(f"用途: {purpose_labels.get(p, p)} · "
                       f"有效期 {ttl} 分钟 · 使用后失效")
            if st.button("🎫 已发放完毕，清除显示"):
                st.session_state.pop('generated_token', None)
                st.session_state.pop('token_purpose', None)
                st.rerun()

        # 当前有效 token 列表 + 撤销
        active = TOKENS.list_active()
        if active:
            with st.expander(f"📋 有效 token ({len(active)} 个)"):
                for t in active:
                    st.markdown(
                        f"- `{t['token']}` · {purpose_labels.get(t['purpose'], t['purpose'])}"
                        f" · 发放者 {t['grantor']} · "
                        f"剩余 {int((t['expires'] - __import__('time').time()) / 60)} 分钟")
                    if st.button(f"撤销 {t['token']}", key=f"revoke_{t['token']}"):
                        TOKENS.revoke(t['token'], username)
                        st.toast("已撤销")
                        st.rerun()

        # 授权审计
        import json as _json
        audit_path = Path(__file__).parent.parent / "auth_audit.log"
        if audit_path.exists():
            with st.expander("📋 授权审计"):
                rows = []
                for line in open(audit_path):
                    line = line.strip()
                    if line:
                        try:
                            rows.append(_json.loads(line))
                        except Exception:
                            pass
                if rows:
                    import pandas as pd
                    df = pd.DataFrame(rows)
                    cols = [c for c in ['timestamp', 'action', 'grantor',
                                         'used_by', 'purpose']
                            if c in df.columns]
                    st.dataframe(df[cols].sort_values(
                        'timestamp', ascending=False).head(50),
                        use_container_width=True, hide_index=True)
    else:
        st.info("AI 配置和临时授权仅 admin/运维 可用 — 你可在此修改自己的密码")


run()
