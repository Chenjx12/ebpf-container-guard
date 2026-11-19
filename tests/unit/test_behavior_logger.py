"""BehaviorLogger buffered writer + 轮转单测 (v0.4.4)"""
import glob
import json
import os
import sys

import pytest

from core.behavior_logger import BehaviorLogger

EVENT = {'event_type': 'openat', 'container_id': 'c1', 'pid': 1,
         'uid': 0, 'comm': 'test', 'target_path': '/etc/shadow'}


@pytest.fixture
def logger(tmp_path):
    path = str(tmp_path / "behaviors.log")
    return path, BehaviorLogger(path, enabled=True, flush_interval=0)


class TestBufferedWrite:
    def test_write_appends_jsonl(self, logger):
        path, lg = logger
        lg.write(EVENT)
        lg.flush()
        lines = open(path).readlines()
        assert len(lines) == 1
        d = json.loads(lines[0])
        assert d['event_type'] == 'openat'
        assert d['comm'] == 'test'
        assert d['target_path'] == '/etc/shadow'

    def test_disabled_no_write(self, logger, tmp_path):
        path = str(tmp_path / "behaviors.log")
        lg = BehaviorLogger(path, enabled=False)
        lg.write(EVENT)
        lg.flush()
        assert not os.path.exists(path) or os.path.getsize(path) == 0

    def test_multiple_events(self, logger):
        path, lg = logger
        for _ in range(10):
            lg.write(EVENT)
        lg.flush()
        assert len(open(path).readlines()) == 10


class TestRotate:
    def test_rotate_on_date_change(self, logger, monkeypatch):
        path, lg = logger
        from datetime import datetime

        class FakeDate(datetime):
            _day = 14
            @classmethod
            def now(cls):
                return cls(2026, 8, cls._day, 10, 0, 0)

        monkeypatch.setattr('core.behavior_logger.datetime', FakeDate)
        lg.write(EVENT)   # 8-14
        FakeDate._day = 15
        lg.write(EVENT)   # 8-15 → 触发轮转
        lg.flush()
        # 旧文件改名 behaviors.log.2026-08-14.001（v2 起带序号）
        assert os.path.exists(f"{path}.2026-08-14.001")
        # 新活跃文件只有 8-15 的事件
        lines = open(path).readlines()
        assert len(lines) == 1
        assert json.loads(lines[0])['timestamp'].startswith('2026-08-15')

    def test_rotate_on_size(self, logger, monkeypatch):
        path, lg = logger
        # 用极小 max_bytes 触发大小轮转
        lg.max_bytes = 50
        lg.write(EVENT)   # 触发第一次 write → 文件 > 50B
        # 第二次 write 应轮转
        lg.write(EVENT)
        lg.flush()
        old = glob.glob(f"{path}.*")
        assert len(old) == 1
        assert os.path.basename(old[0]).endswith('.001')
        assert open(path).readlines()  # 新活跃文件有内容

    def test_same_day_rotation_does_not_overwrite(self, logger, monkeypatch):
        """回归缺陷 A：同一天内多次按大小轮转，旧文件不得互相覆盖。"""
        path, lg = logger
        lg.max_bytes = 50
        for _ in range(6):
            lg.write(EVENT)
        lg.flush()
        old = sorted(os.path.basename(p) for p in glob.glob(f"{path}.*"))
        assert len(old) >= 2, f"同一天轮转产生了覆盖: {old}"
        assert old[0].endswith('.001') and old[1].endswith('.002')

    def test_cleanup_handles_sequenced_names(self, tmp_path, monkeypatch):
        """回归缺陷 B：带序号的新文件名也要能被清理。"""
        from datetime import datetime

        class FakeDate(datetime):
            @classmethod
            def now(cls):
                return cls(2026, 8, 14, 10, 0, 0)

        monkeypatch.setattr('core.behavior_logger.datetime', FakeDate)
        path = str(tmp_path / "behaviors.log")
        open(f"{path}.2026-08-01.001", 'w').write('old')
        open(f"{path}.2026-08-01.002", 'w').write('old')
        open(f"{path}.2026-08-12.001", 'w').write('recent')
        BehaviorLogger(path, enabled=True)   # retain_days=7 → cutoff 08-07
        assert not os.path.exists(f"{path}.2026-08-01.001")
        assert not os.path.exists(f"{path}.2026-08-01.002")
        assert os.path.exists(f"{path}.2026-08-12.001")


class TestCleanup:
    def test_cleanup_old_files(self, tmp_path, monkeypatch):
        path = str(tmp_path / "behaviors.log")
        # 冻结"今天"= 2026-08-14，使 7 天保留 cutoff 固定为 08-07
        # （否则测试随真实日期漂移：超过 08-14 后 08-11 也会被误删）
        from datetime import datetime

        class FakeDate(datetime):
            @classmethod
            def now(cls):
                return cls(2026, 8, 14, 10, 0, 0)

        monkeypatch.setattr('core.behavior_logger.datetime', FakeDate)
        # 预置 10 天前旧文件 + 3 天前文件
        open(f"{path}.2026-08-04", 'w').write('old')
        open(f"{path}.2026-08-11", 'w').write('recent')
        lg = BehaviorLogger(path, enabled=True)  # retain_days=7
        # 2026-08-14 时, 8-04 早于 8-07 cutoff → 删; 8-11 保留
        assert not os.path.exists(f"{path}.2026-08-04")
        assert os.path.exists(f"{path}.2026-08-11")


# ======================================================================
# v2 哈希链
# ======================================================================
import hashlib
import hmac as _hmac
import re as _re

GENESIS = '0' * 64


def read_records(path):
    return [json.loads(x) for x in open(path, encoding='utf-8') if x.strip()]


def recompute(rec):
    d = dict(rec)
    claimed = d.pop('hash')
    body = json.dumps(d, ensure_ascii=False, separators=(',', ':'))
    calc = hashlib.sha256((d['prev'] + body).encode()).hexdigest()
    return calc, claimed


class TestChainFields:
    def test_first_record(self, logger):
        path, lg = logger
        lg.write(EVENT)
        lg.flush()
        r = read_records(path)[0]
        assert r['version'] == 2
        assert r['seq'] == 1
        assert r['prev'] == GENESIS
        calc, claimed = recompute(r)
        assert calc == claimed

    def test_continuity(self, logger):
        path, lg = logger
        for _ in range(100):
            lg.write(EVENT)
        lg.flush()
        recs = read_records(path)
        assert [r['seq'] for r in recs] == list(range(1, 101))
        for prev, cur in zip(recs, recs[1:]):
            assert cur['prev'] == prev['hash']
        for r in recs:
            assert recompute(r)[0] == recompute(r)[1]

    def test_rotation_keeps_chain(self, logger, monkeypatch):
        path, lg = logger
        from datetime import datetime

        class FakeDate(datetime):
            _day = 14
            @classmethod
            def now(cls):
                return cls(2026, 8, cls._day, 10, 0, 0)

        monkeypatch.setattr('core.behavior_logger.datetime', FakeDate)
        lg.write(EVENT)
        FakeDate._day = 15
        lg.write(EVENT)
        lg.flush()
        old = read_records(f"{path}.2026-08-14.001")
        new = read_records(path)
        assert new[0]['prev'] == old[-1]['hash']
        assert new[0]['seq'] == old[-1]['seq'] + 1

    def test_restart_resumes_chain(self, tmp_path):
        path = str(tmp_path / "behaviors.log")
        lg = BehaviorLogger(path, enabled=True, flush_interval=0)
        lg.write(EVENT)
        lg.write(EVENT)
        lg.close()

        lg2 = BehaviorLogger(path, enabled=True, flush_interval=0)
        lg2.write(EVENT)
        lg2.close()
        recs = read_records(path)
        assert [r['seq'] for r in recs] == [1, 2, 3]
        assert recs[2]['prev'] == recs[1]['hash']


class TestHMACMode:
    def test_hmac_chain(self, tmp_path):
        key_path = tmp_path / "chain.key"
        key_path.write_bytes(b'k' * 32)
        os.chmod(key_path, 0o600)
        path = str(tmp_path / "behaviors.log")
        lg = BehaviorLogger(path, enabled=True, flush_interval=0,
                            integrity_mode="hmac", key_path=str(key_path))
        lg.write(EVENT)
        lg.close()
        rec = read_records(path)[0]
        d = dict(rec)
        claimed = d.pop('hash')
        body = json.dumps(d, ensure_ascii=False, separators=(',', ':'))
        expected = _hmac.new(b'k' * 32, (d['prev'] + body).encode(),
                             hashlib.sha256).hexdigest()
        assert claimed == expected

    def test_missing_key_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            BehaviorLogger(str(tmp_path / "b.log"), integrity_mode="hmac",
                           key_path=str(tmp_path / "nope.key"))


class TestVerifyTool:
    def _run(self, log_dir, *extra):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        return subprocess.run(
            [sys.executable, os.path.join(root, "tools", "verify_chain.py"),
             str(log_dir), *extra],
            capture_output=True, text=True)

    def test_clean_chain_passes(self, tmp_path):
        path = str(tmp_path / "behaviors.log")
        lg = BehaviorLogger(path, enabled=True, flush_interval=0)
        for _ in range(20):
            lg.write(EVENT)
        lg.close()
        out = self._run(tmp_path)
        assert out.returncode == 0, out.stdout + out.stderr
        assert "链完整" in out.stdout

    def test_tamper_detected(self, tmp_path):
        path = str(tmp_path / "behaviors.log")
        lg = BehaviorLogger(path, enabled=True, flush_interval=0)
        for _ in range(10):
            lg.write(EVENT)
        lg.close()
        lines = open(path, encoding='utf-8').read().splitlines()
        lines[4] = lines[4].replace('"/etc/shadow"', '"/etc/shadoW"')
        open(path, 'w', encoding='utf-8').write("\n".join(lines) + "\n")
        out = self._run(tmp_path)
        assert out.returncode == 1
        assert "第 5 行" in out.stdout

    def test_deleted_line_detected(self, tmp_path):
        path = str(tmp_path / "behaviors.log")
        lg = BehaviorLogger(path, enabled=True, flush_interval=0)
        for _ in range(10):
            lg.write(EVENT)
        lg.close()
        lines = open(path, encoding='utf-8').read().splitlines()
        del lines[3]
        open(path, 'w', encoding='utf-8').write("\n".join(lines) + "\n")
        out = self._run(tmp_path)
        assert out.returncode == 1
        assert "SEQ_GAP" in out.stdout


class TestFastSerializer:
    """手写序列化必须与 json.dumps 逐字节一致（校验端依赖这一点）。"""

    BASE = {'version': 2, 'seq': 1, 'prev': 'a' * 64,
            'timestamp': '2026-11-14T20:00:00.000', 'event_type': 'openat',
            'container_id': 'abc', 'pid': 1, 'uid': 0, 'comm': 'bash',
            'target_path': '/etc/shadow', 'fstype': None, 'target_pid': None,
            'request': None, 'daddr': None, 'dport': None}

    def test_matches_json_dumps(self):
        from core.behavior_logger import _build_body, _json_body
        assert _build_body(self.BASE) == _json_body(self.BASE)

    def test_edge_cases_fall_back(self):
        from core.behavior_logger import _build_body, _json_body
        cases = [
            dict(self.BASE, comm='中文进程'),
            dict(self.BASE, target_path=''),
            dict(self.BASE, comm='a"b'),
            dict(self.BASE, target_path='c:\\win'),
            dict(self.BASE, comm='x\ny'),
            dict(self.BASE, comm='tab\there'),
            dict(self.BASE, comm='ctrl\x01'),
            dict(self.BASE, target_path='emoji😀'),
            dict(self.BASE, fstype='proc', target_pid=999,
                 daddr='1.2.3.4', dport=4444),
            dict(self.BASE, pid=None, uid=None),
        ]
        for c in cases:
            assert _build_body(c) == _json_body(c), c

    def test_fuzz_random_strings(self):
        import random as _r
        from core.behavior_logger import _build_body, _json_body
        _r.seed(7)
        alpha = ['a', '/', '-', '中', '😀', '"', '\\', '\n', '\t', '\x01', ' ', '0']
        for _ in range(500):
            c = dict(self.BASE)
            c['comm'] = ''.join(_r.choice(alpha) for _ in range(_r.randint(0, 8)))
            c['target_path'] = ''.join(_r.choice(alpha) for _ in range(_r.randint(0, 8)))
            assert _build_body(c) == _json_body(c)
