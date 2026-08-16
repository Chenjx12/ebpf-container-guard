"""
eBPF Container Guard — FastAPI server (v0.5.6)

REST API backend + Vue3 SPA frontend, replacing the Streamlit dashboard.

Security defaults:
  - /docs (Swagger) disabled unless ENABLE_DOCS=1 — security product
    exposes no API surface by default (defense-in-depth, ADR-045)
  - session cookie HttpOnly + SameSite=Lax, in-memory sessions (8h),
    no JWT — logout invalidates immediately
  - single uvicorn worker required (in-memory sessions + one-time tokens)

Run:  uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 1
"""

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles

from server import common
from server.deps import create_session
from server.routes import router

# Swagger docs: opt-in only (attack-surface minimization)
DOCS_ENABLED = os.environ.get("ENABLE_DOCS") == "1"
app = FastAPI(
    title="eBPF Container Guard API",
    version="0.5.6",
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url=None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
)


# ================================================================
# Auth routes (login/logout — cookie lifecycle)
# ================================================================


@app.post("/api/auth/login")
def login(body: dict, response: Response):
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not common.AUTH.verify(username, password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    sid = create_session(username)
    response.set_cookie(
        "guard_session", sid,
        max_age=8 * 3600, httponly=True, samesite="lax")
    return {
        "username": username,
        "role": common.AUTH.get_role(username),
        "must_change_password": common.AUTH.is_initial_password(username),
    }


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("guard_session")
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request):
    from server.deps import get_session_user
    try:
        username = get_session_user(request)
    except HTTPException:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "username": username,
        "role": common.AUTH.get_role(username),
        "must_change_password": common.AUTH.is_initial_password(username),
    }


@app.post("/api/auth/change-password")
def change_password(body: dict, request: Request):
    from server.deps import get_session_user
    username = get_session_user(request)
    old = body.get("old_password") or ""
    new = body.get("new_password") or ""
    if not common.AUTH.verify(username, old):
        raise HTTPException(status_code=400, detail="旧密码错误")
    if not common.AUTH.change_password(username, new):
        raise HTTPException(status_code=400, detail="新密码无效（至少 6 位）")
    return {"ok": True}


app.include_router(router)

# Static frontend (Vue3 SPA)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
