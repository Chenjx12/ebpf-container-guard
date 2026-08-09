"""⚙️ 设置 — AI 配置 (v0.3.7)"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml as _yaml
import streamlit as st

from common import AI_CONFIG_PATH


def run():
    st.title("⚙️ 设置")

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


run()
