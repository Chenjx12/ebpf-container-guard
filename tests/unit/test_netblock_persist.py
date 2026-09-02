#!/usr/bin/env python3
"""Unit tests: NetBlocker 持久化 + 重启重放 (v0.6.3, ADR-050 顺风车 1).

Coverage:
  - block → 快照落盘 (tmp+rename 原子)
  - unblock → 快照剔除
  - 新实例 load_persisted 恢复 blocked 表 (重启恢复)
  - replay() 重放 iptables FORWARD DROP (subprocess 命令断言)
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from core.netblock import NetBlocker


class TestNetBlockerPersist(unittest.TestCase):

    def test_block_persists_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            snap = str(Path(td) / "netblock_rules.json")
            nb = NetBlocker(persist_path=snap)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                self.assertTrue(nb.block("1.2.3.4", 4444))
            data = json.load(open(snap))
            self.assertIn("1.2.3.4:4444", data["blocks"])
            self.assertTrue(os.path.exists(snap))

    def test_unblock_removes_from_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            snap = str(Path(td) / "netblock_rules.json")
            nb = NetBlocker(persist_path=snap)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                nb.block("1.2.3.4", 4444)
                nb.unblock("1.2.3.4", 4444)
            data = json.load(open(snap))
            self.assertNotIn("1.2.3.4:4444", data["blocks"])

    def test_load_persisted_restores_after_restart(self):
        # 验收锚点: 重启后阻断规则仍在 (新实例从同一快照恢复)
        with tempfile.TemporaryDirectory() as td:
            snap = str(Path(td) / "netblock_rules.json")
            nb1 = NetBlocker(persist_path=snap)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                nb1.block("5.6.7.8", 22)
            nb2 = NetBlocker(persist_path=snap)  # 模拟 guard 重启
            n = nb2.load_persisted()
            self.assertEqual(n, 1)
            self.assertTrue(nb2.is_blocked("5.6.7.8", 22))

    def test_replay_reapplies_drop_rules(self):
        with tempfile.TemporaryDirectory() as td:
            snap = str(Path(td) / "netblock_rules.json")
            nb1 = NetBlocker(persist_path=snap)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                nb1.block("10.0.0.9", 9999)
            nb2 = NetBlocker(persist_path=snap)
            calls = []
            def fake_run(args, **kw):
                calls.append(args)
                # -C (check) 返回非 0: 规则不存在 → 应执行 -I 插入
                class _R:
                    returncode = 1 if "-C" in args else 0
                return _R()
            with patch("subprocess.run", side_effect=fake_run) as mock_run:
                ok = nb2.replay()
            self.assertEqual(ok, 1)
            self.assertTrue(any(
                "iptables" in c and "-I" in c and "10.0.0.9" in c
                and "9999" in c for c in calls))

    def test_replay_skips_existing_rules(self):
        # 幂等: host 网络重启后旧规则残留, -C 命中 → 跳过 -I, 不重复插入
        with tempfile.TemporaryDirectory() as td:
            snap = str(Path(td) / "netblock_rules.json")
            nb1 = NetBlocker(persist_path=snap)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                nb1.block("10.0.0.9", 9999)
            nb2 = NetBlocker(persist_path=snap)
            calls = []
            def fake_run(args, **kw):
                calls.append(args)
                class _R:
                    returncode = 0  # -C 命中: 规则已存在
                return _R()
            with patch("subprocess.run", side_effect=fake_run) as mock_run:
                ok = nb2.replay()
            self.assertEqual(ok, 1)
            self.assertFalse(any(
                "iptables" in c and "-I" in c for c in calls))
            self.assertTrue(any(
                "iptables" in c and "-C" in c for c in calls))


if __name__ == "__main__":
    unittest.main()