#!/usr/bin/env python3
"""
Compatibility shim (v0.6.4) — DO NOT add new logic here.

The authoritative auth module moved to server/auth.py (shared by the
FastAPI panel and this legacy dashboard). This file re-exports from it
so that legacy import paths keep working until dashboard/ is retired:

    from auth import AuthManager, TokenManager          # dashboard pages
    from dashboard.auth import AuthManager, ROLE_RANK   # server / tests

Original: Authentication & authorization for the dashboard
(v0.3.8, v0.5.6 Argon2id).
"""

import sys
from pathlib import Path

# 保证任意运行方式 (streamlit run dashboard/... / pytest / uvicorn)
# 下都能定位到项目根的 server 包 (与 server/common.py 的 sys.path 模式一致)
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.auth import (  # noqa: E402
    ROLE_RANK,
    ALL_ROLES,
    PURPOSES,
    ARGON2_M,
    ARGON2_T,
    ARGON2_P,
    AuthManager,
    TokenManager,
)
