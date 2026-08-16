#!/usr/bin/env python3
"""
Authentication & authorization for the dashboard (v0.3.8, v0.5.6 Argon2id).

Roles (high → low): admin > operator > analyst
- Password hashing: **Argon2id** (memory-hard KDF, OWASP first choice,
  GPU/ASIC-resistant) — v0.5.6 upgraded from PBKDF2-100k
- Users stored in config/users.yaml (gitignored)
- Initial admin created on first start, password printed to terminal
- Temporary tokens: high-role users grant low-role users one-off
  permissions (add_member / add_rule) for 1-5 minutes, all audited
"""

import json
import os
import secrets
import time
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ROLE_RANK = {'admin': 3, 'operator': 2, 'analyst': 1}
ALL_ROLES = ['admin', 'operator', 'analyst']

# Purpose definitions: who can grant, and what operation it unlocks
PURPOSES = {
    'add_member': {'grantable_by': ['admin'], 'ttl_max': 300},
    'add_rule': {'grantable_by': ['admin', 'operator'], 'ttl_max': 300},
}

# Argon2id 参数 (OWASP 推荐基线: 19 MiB / t=2 / p=1)
ARGON2_M = 19456
ARGON2_T = 2
ARGON2_P = 1

_hasher = PasswordHasher(time_cost=ARGON2_T, memory_cost=ARGON2_M,
                         parallelism=ARGON2_P)


# ================================================================
# AuthManager
# ================================================================

class AuthManager:
    def __init__(self, users_path: str = "config/users.yaml"):
        self.users_path = Path(users_path)
        self.users = self._load()

    # ---- persistence ----

    def _load(self) -> dict:
        if not self.users_path.exists():
            return {}
        try:
            import yaml
            with open(self.users_path, 'r') as f:
                data = yaml.safe_load(f) or {}
            return data.get('users', {})
        except Exception:
            return {}

    def _save(self):
        import yaml
        self.users_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.users_path, 'w') as f:
            yaml.safe_dump({'users': self.users}, f, allow_unicode=True,
                           sort_keys=False)
        # 限制权限：密码哈希敏感
        try:
            os.chmod(self.users_path, 0o600)
        except Exception:
            pass

    # ---- initial admin ----

    def ensure_initial_admin(self) -> str:
        """Create initial admin if no users exist. Returns plaintext password.

        Called at dashboard startup; password printed to terminal.
        """
        if self.users:
            return ""
        password = secrets.token_urlsafe(12)
        self.create_user('admin', password, 'admin')
        return password

    # ---- user management ----

    def verify(self, username: str, password: str) -> bool:
        user = self.users.get(username)
        if not user:
            return False
        try:
            return _hasher.verify(user['hash'], password)
        except (VerifyMismatchError, InvalidHashError):
            return False

    def create_user(self, username: str, password: str, role: str,
                     is_initial: bool = True) -> bool:
        """Create user. Password is required (enforced by caller + check)."""
        if not username or len(password) < 6:
            return False
        if username in self.users or role not in ALL_ROLES:
            return False
        self.users[username] = {
            'role': role,
            'hash': _hasher.hash(password),  # Argon2id 自含盐, 无需单独 salt
            'created': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'initial': is_initial,  # v0.3.10: force password change on first login
        }
        self._save()
        return True

    def change_password(self, username: str, new_password: str) -> bool:
        if username not in self.users or len(new_password) < 6:
            return False
        self.users[username]['hash'] = _hasher.hash(new_password)
        self.users[username]['initial'] = False  # v0.3.10: clear initial flag
        self._save()
        return True

    def list_users(self) -> list:
        """[(username, role, created), ...] without password material."""
        return [(u, d['role'], d.get('created', ''))
                for u, d in self.users.items()]

    def get_role(self, username: str) -> str:
        user = self.users.get(username)
        return user['role'] if user else ''

    def has_role(self, username: str, role: str) -> bool:
        return ROLE_RANK.get(self.get_role(username), 0) >= ROLE_RANK[role]

    # ---- initial password detection (v0.3.10) ----

    def is_initial_password(self, username: str) -> bool:
        """Check if user still has the initial (un-changed) password."""
        user = self.users.get(username)
        return bool(user.get('initial', False)) if user else False

    def clear_initial_flag(self, username: str):
        """Mark password as changed (remove initial flag)."""
        if username in self.users:
            self.users[username]['initial'] = False
            self._save()


# ================================================================
# TokenManager — temporary authorization
# ================================================================

class TokenManager:
    def __init__(self, tokens_path: str = "config/tokens.yaml",
                 audit_path: str = "auth_audit.log", auth=None):
        self.tokens_path = Path(tokens_path)
        self.audit_path = Path(audit_path)
        self.auth = auth  # AuthManager (for grantor role resolution)
        self.tokens = self._load()

    def _load(self) -> dict:
        if not self.tokens_path.exists():
            return {}
        try:
            import yaml
            with open(self.tokens_path, 'r') as f:
                data = yaml.safe_load(f) or {}
            return data.get('tokens', {})
        except Exception:
            return {}

    def _save(self):
        import yaml
        self.tokens_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.tokens_path, 'w') as f:
            yaml.safe_dump({'tokens': self.tokens}, f, allow_unicode=True,
                           sort_keys=False)

    def _audit(self, action: str, **fields):
        entry = {'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
                 'action': action, **fields}
        with open(self.audit_path, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    # ---- grant ----

    def generate(self, purpose: str, grantor: str, ttl: int = 180,
                 note: str = "") -> str:
        """Generate a temp token. Returns token string or '' on failure.

        grantor is a username; permission checked via auth.get_role().
        note (v0.5.6): optional remark shown in the token list (e.g. who
        it was granted for / why) — audited with the grant.
        """
        purpose_def = PURPOSES.get(purpose)
        if not purpose_def:
            return ''
        grantor_role = self.auth.get_role(grantor) if self.auth else ''
        if grantor_role not in purpose_def['grantable_by']:
            return ''  # grantor lacks permission for this purpose
        if ttl < 60 or ttl > purpose_def['ttl_max']:
            ttl = 180  # clamp to 1-5 min

        token = secrets.token_urlsafe(16)
        self.tokens[token] = {
            'purpose': purpose,
            'grantor': grantor,
            'note': (note or '')[:100],
            'expires': time.time() + ttl,
            'granted_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'used_by': None,
            'used_at': None,
        }
        self._save()
        self._audit('token_grant', purpose=purpose, grantor=grantor,
                    ttl=ttl, note=self.tokens[token]['note'],
                    expires=self.tokens[token]['expires'])
        return token

    # ---- verification ----

    def verify(self, token: str, purpose: str, username: str) -> bool:
        """Validate token: exists, purpose matches, not expired, unused."""
        if token not in self.tokens:
            return False
        t = self.tokens[token]
        if t['purpose'] != purpose:
            return False
        if time.time() > t['expires']:
            self._purge(token)
            return False
        if t.get('used_by'):
            return False  # single-use

        # Mark used + audit
        t['used_by'] = username
        t['used_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        self._save()
        self._audit('token_use', purpose=purpose, token=token[:8],
                    grantor=t['grantor'], used_by=username)
        return True

    def _purge(self, token: str):
        self.tokens.pop(token, None)
        self._save()

    def revoke(self, token: str, revoker: str):
        if token in self.tokens:
            info = self.tokens.pop(token)
            self._save()
            self._audit('token_revoke', token=token[:8], revoker=revoker,
                        grantor=info['grantor'], purpose=info['purpose'])

    def list_active(self) -> list:
        """Active (unused, unexpired) tokens for display."""
        now = time.time()
        return [{'token': k[:8], 'purpose': v['purpose'],
                 'grantor': v['grantor'], 'note': v.get('note', ''),
                 'expires': v['expires'], 'used_by': v.get('used_by')}
                for k, v in self.tokens.items()
                if now < v['expires'] and not v.get('used_by')]
