"""API 认证 + RBAC 单测 (v0.5.6 FastAPI 面板迁移).

用临时 users.yaml 隔离, 不污染真实 config/users.yaml。
TestClient 覆盖: 登录/401/403/改密/角色矩阵。
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient

from server import common


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """临时 users.yaml + 三个角色测试用户 + 日志路径隔离."""
    users_path = tmp_path / "users.yaml"
    tokens_path = tmp_path / "tokens.yaml"
    audit_path = tmp_path / "auth_audit.log"

    from dashboard.auth import AuthManager, TokenManager
    auth = AuthManager(str(users_path))
    auth.create_user("analyst", "analystpass", "analyst", is_initial=False)
    auth.create_user("operator", "operatorpass", "operator", is_initial=False)
    auth.create_user("admin", "adminpass", "admin", is_initial=False)

    monkeypatch.setattr(common, "AUTH", auth)
    monkeypatch.setattr(
        common, "TOKENS",
        TokenManager(str(tokens_path), str(audit_path), auth=auth))
    # 写路径隔离 — 测试判决不进真实 logs/
    monkeypatch.setattr(common, "DECISIONS_LOG", tmp_path / "decisions.log")

    from server.app import app
    return TestClient(app)


def _login(client, user, pwd):
    r = client.post("/api/auth/login", json={"username": user,
                                             "password": pwd})
    assert r.status_code == 200, r.text
    return r


class TestAuth:
    def test_login_success_sets_cookie(self, client):
        r = _login(client, "analyst", "analystpass")
        assert r.json()["role"] == "analyst"
        assert "guard_session" in client.cookies

    def test_login_wrong_password_401(self, client):
        r = client.post("/api/auth/login",
                        json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    def test_login_unknown_user_401(self, client):
        r = client.post("/api/auth/login",
                        json={"username": "ghost", "password": "x"})
        assert r.status_code == 401

    def test_me_unauthenticated(self, client):
        assert client.get("/api/auth/me").json()["authenticated"] is False

    def test_me_authenticated(self, client):
        _login(client, "operator", "operatorpass")
        me = client.get("/api/auth/me").json()
        assert me["authenticated"] is True
        assert me["role"] == "operator"

    def test_protected_endpoint_401_without_login(self, client):
        assert client.get("/api/overview/stats").status_code == 401

    def test_change_password(self, client):
        _login(client, "analyst", "analystpass")
        r = client.post("/api/auth/change-password", json={
            "old_password": "analystpass", "new_password": "newpass123"})
        assert r.status_code == 200
        # 新密码可登录
        client.post("/api/auth/logout")
        assert client.post("/api/auth/login", json={
            "username": "analyst", "password": "newpass123"}).status_code == 200

    def test_change_password_wrong_old_400(self, client):
        _login(client, "analyst", "analystpass")
        r = client.post("/api/auth/change-password", json={
            "old_password": "bad", "new_password": "newpass123"})
        assert r.status_code == 400


class TestRBAC:
    def test_analyst_read_ok(self, client):
        _login(client, "analyst", "analystpass")
        assert client.get("/api/rules").status_code == 200

    def test_analyst_write_forbidden(self, client):
        _login(client, "analyst", "analystpass")
        assert client.post("/api/review/decision", json={
            "container_id": "c", "decision": "confirmed"}).status_code == 403
        assert client.post("/api/members", json={
            "username": "x", "password": "xxxxxx",
            "role": "analyst"}).status_code == 403

    def test_operator_decision_ok(self, client):
        _login(client, "operator", "operatorpass")
        assert client.post("/api/review/decision", json={
            "container_id": "c1", "decision": "confirmed"}).status_code == 200

    def test_operator_member_forbidden(self, client):
        _login(client, "operator", "operatorpass")
        assert client.post("/api/members", json={
            "username": "x", "password": "xxxxxx",
            "role": "analyst"}).status_code == 403

    def test_operator_token_issue_forbidden(self, client):
        # add_member 签发限 admin
        _login(client, "operator", "operatorpass")
        r = client.post("/api/tokens/issue", json={
            "purpose": "add_member", "ttl": 120})
        assert r.status_code == 403

    def test_admin_member_ok(self, client):
        _login(client, "admin", "adminpass")
        assert client.post("/api/members", json={
            "username": "newuser", "password": "newuser1",
            "role": "analyst"}).status_code == 200

    def test_admin_issue_token(self, client):
        _login(client, "admin", "adminpass")
        r = client.post("/api/tokens/issue", json={
            "purpose": "add_member", "ttl": 120})
        assert r.status_code == 200
        assert len(r.json()["token"]) >= 16

    def test_bad_decision_value_400(self, client):
        _login(client, "operator", "operatorpass")
        r = client.post("/api/review/decision", json={
            "container_id": "c", "decision": "maybe"})
        assert r.status_code == 400
