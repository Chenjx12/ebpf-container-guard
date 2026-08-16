"""
eBPF Container Guard — session & role dependencies (v0.5.6)

In-memory sessions (8h TTL), HttpOnly cookie, no JWT (logout is
immediate). Requires single uvicorn worker (memory state).
"""

import secrets
import time

from fastapi import HTTPException, Request

from dashboard.auth import ROLE_RANK
from server import common

SESSION_TTL = 8 * 3600
_sessions: dict = {}  # session_id -> {'username': str, 'expires': float}


def create_session(username: str) -> str:
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = {'username': username,
                      'expires': time.time() + SESSION_TTL}
    return sid


def get_session_user(request: Request) -> str:
    """Resolve current user from cookie; raise 401 if invalid."""
    sid = request.cookies.get("guard_session")
    if not sid:
        raise HTTPException(status_code=401, detail="未登录")
    sess = _sessions.get(sid)
    if not sess or sess['expires'] < time.time():
        _sessions.pop(sid, None)
        raise HTTPException(status_code=401, detail="会话已过期")
    return sess['username']


def require_role(min_role: str):
    """Dependency factory: role gate (admin > operator > analyst)."""

    def _dep(request: Request) -> dict:
        username = get_session_user(request)
        role = common.AUTH.get_role(username)
        if ROLE_RANK.get(role, 0) < ROLE_RANK[min_role]:
            raise HTTPException(status_code=403,
                                detail=f"需要 {min_role} 及以上权限")
        return {'username': username, 'role': role}

    return _dep
