"""BehaviorLogger buffered writer + 轮转单测 (v0.4.4)"""
import glob
import json
import os

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
        # 旧文件改名 behaviors.log.2026-08-14
        assert os.path.exists(f"{path}.2026-08-14")
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
        assert open(path).readlines()  # 新活跃文件有内容


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
