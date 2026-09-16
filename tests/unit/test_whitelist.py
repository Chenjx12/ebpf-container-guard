"""v0.6.5.1 白名单回归测试 —— 续期 (P1) + 非法 valid_until fail-closed (P2)。

背景: v0.6.5 的 HTTP e2e (tests/integration/rules_whitelist_e2e.py) 探到两个缺陷:
- P1: 过期条目会永久挡住同 match 重新加白 (幂等分支不看到期)
- P2: valid_until 非法格式被 whitelist_list 当作 exp=None → 永不过期 (fail-open)
"""

import time

import pytest

from server import common


def _iso(offset):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() + offset))


@pytest.fixture
def wl(tmp_path, monkeypatch):
    monkeypatch.setattr(common, 'WHITELIST_PATH', tmp_path / 'whitelist.yaml')
    monkeypatch.setattr(common, 'RULES_AUDIT_LOG', tmp_path / 'rules_audit.log')
    return common


def test_add_then_idempotent_while_active(wl):
    future = _iso(3600)
    ok, wid = wl.whitelist_add('comm', 'curl', future, 'n1', 'admin')
    assert ok and wid
    ok2, wid2 = wl.whitelist_add('comm', 'curl', _iso(7200), 'n2', 'admin')
    assert ok2 and wid2 == wid
    items = [w for w in wl.whitelist_list(active_only=False)
             if w['match'] == 'curl']
    assert len(items) == 1
    assert items[0]['note'] == 'n1'          # 有效期内不覆盖
    assert items[0]['active'] is True


def test_expired_then_readd_renews_same_id(wl):
    """P1: 过期后再加同 match 应续期，而不是被旧条目挡住。"""
    ok, wid = wl.whitelist_add('comm', 'curl', _iso(-3600), 'old', 'admin')
    assert ok
    assert wl.whitelist_list(active_only=True) == []
    future = _iso(3600)
    ok2, wid2 = wl.whitelist_add('comm', 'curl', future, 'renewed', 'admin')
    assert ok2 and wid2 == wid
    items = wl.whitelist_list(active_only=False)
    assert len(items) == 1
    assert items[0]['active'] is True
    assert items[0]['valid_until'] == future
    assert items[0]['note'] == 'renewed'
    assert wl.whitelist_active_until('comm', 'curl') == future


def test_malformed_valid_until_rejected(wl):
    """P2: 非法格式写入被拒。"""
    ok, err = wl.whitelist_add('comm', 'x', 'not-a-date', 'n', 'admin')
    assert ok is False
    assert 'valid_until' in err


def test_malformed_entry_treated_expired(wl):
    """P2: 存量/直写坏时间戳不能 fail-open（不能永久抑制告警）。"""
    wl._wl_save([{'id': 'bad1', 'kind': 'comm', 'match': 'x',
                  'valid_until': 'garbage', 'note': 'n',
                  'user': 'admin', 'created_at': _iso(0)}])
    assert wl.whitelist_list(active_only=True) == []
    allitems = wl.whitelist_list(active_only=False)
    assert len(allitems) == 1 and allitems[0]['active'] is False
    assert wl.whitelist_active_until('comm', 'x') == ''


def test_empty_valid_until_is_permanent(wl):
    ok, wid = wl.whitelist_add('container', 'redis', '', 'forever', 'admin')
    assert ok
    items = wl.whitelist_list(active_only=True)
    assert len(items) == 1 and items[0]['active'] is True
    ok2, wid2 = wl.whitelist_add('container', 'redis', '', 'again', 'admin')
    assert ok2 and wid2 == wid               # 永久条目幂等


def test_remove(wl):
    _, wid = wl.whitelist_add('comm', 'curl', _iso(3600), 'n', 'admin')
    ok, _ = wl.whitelist_remove(wid, 'admin')
    assert ok and wl.whitelist_list(active_only=False) == []
    ok2, err = wl.whitelist_remove('nope', 'admin')
    assert ok2 is False


def test_parse_until():
    assert common.whitelist_parse_until('') == (True, None)
    assert common.whitelist_parse_until('   ') == (True, None)
    okt, exp = common.whitelist_parse_until('2030-01-01T00:00:00')
    assert okt and exp > time.time()
    assert common.whitelist_parse_until('2026-13-99') == (False, None)
