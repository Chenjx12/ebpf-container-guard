#!/usr/bin/env python3
"""Unit tests: isolation_backend / main._NsenterNetBlocker (v0.6.4, H2).

审查修复验证:
  - os.system 裸调用 → subprocess.run(shell=False) 列表参数
  - 返回真实执行状态 — 不再"iptables 失败仍报隔离/阻断成功"的静默失败
  - 幂等语义: -C 探测已存在 → 成功且不重复插入/删除

Coverage:
  - isolate/unisolate 命令序列与返回状态 (存在/不存在/失败三态)
  - in_cluster → nsenter 前缀 argv
  - pod_ip 为空 → 短路 False 且不调 subprocess
  - main.py _NsenterNetBlocker (ast 提取类, 避开顶层 docker/libbpf import)
"""
import ast
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from responder.isolation_backend import NsenterIptablesBackend


def _mock_run(returncodes):
    """构造 subprocess.run fake — 按调用序返回 rc 序列。

    check=True 且 rc != 0 → 抛 CalledProcessError (模拟真实 iptables 失败)。
    """
    state = {"n": 0}
    rc_seq = list(returncodes)

    def fake_run(argv, **kw):
        rc = rc_seq[state["n"] % len(rc_seq)] if rc_seq else 1
        state["n"] += 1
        if kw.get("check") and rc != 0:
            raise subprocess.CalledProcessError(rc, argv)
        return types.SimpleNamespace(returncode=rc)

    return fake_run


def _load_main_blocker_cls():
    """ast 提取 main.py 的 _NsenterNetBlocker 类 (不执行顶层 import 链)。"""
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    cls_node = next(n for n in tree.body
                    if isinstance(n, ast.ClassDef)
                    and n.name == "_NsenterNetBlocker")
    ns = {"subprocess": subprocess, "os": __import__("os"),
          "sys": sys, "time": __import__("time"), "Path": Path}
    exec(compile(ast.Module(body=[cls_node], type_ignores=[]),
                 "main.py", "exec"), ns)
    return ns["_NsenterNetBlocker"]


class TestNsenterIptablesBackend(unittest.TestCase):

    def _backend(self):
        b = NsenterIptablesBackend()
        b._in_cluster = False  # 宿主机模式 (测试默认)
        return b

    # ---- isolate ----

    def test_isolate_inserts_when_rule_absent(self):
        # -C rc=1 (不存在) → 执行 -I 插入 → True
        b = self._backend()
        with patch("subprocess.run", side_effect=_mock_run([1, 0])) as m:
            self.assertTrue(b.isolate("ns", "pod", "10.1.2.3"))
        self.assertEqual(m.call_count, 2)
        insert_argv = m.call_args_list[1].args[0]
        self.assertEqual(insert_argv[:5],
                         ["iptables", "-I", "FORWARD", "1", "-s"])
        self.assertEqual(insert_argv, ["iptables", "-I", "FORWARD", "1",
                                       "-s", "10.1.2.3", "-j", "DROP"])

    def test_isolate_idempotent_when_rule_exists(self):
        # -C rc=0 (已存在) → True 且不再执行 -I
        b = self._backend()
        with patch("subprocess.run", side_effect=_mock_run([0])) as m:
            self.assertTrue(b.isolate("ns", "pod", "10.1.2.3"))
        self.assertEqual(m.call_count, 1)

    def test_isolate_failure_returns_false(self):
        # 核心回归: iptables 插入失败 → 返回 False (旧实现静默返回 True)
        b = self._backend()
        with patch("subprocess.run", side_effect=_mock_run([1, 1])) as m:
            self.assertFalse(b.isolate("ns", "pod", "10.1.2.3"))
        self.assertEqual(m.call_count, 2)

    def test_isolate_empty_pod_ip_short_circuit(self):
        b = self._backend()
        with patch("subprocess.run", side_effect=_mock_run([0])) as m:
            self.assertFalse(b.isolate("ns", "pod", ""))
        m.assert_not_called()

    # ---- unisolate ----

    def test_unisolate_deletes_when_rule_exists(self):
        b = self._backend()
        with patch("subprocess.run", side_effect=_mock_run([0, 0])) as m:
            self.assertTrue(b.unisolate("ns", "pod", "10.1.2.3"))
        delete_argv = m.call_args_list[1].args[0]
        self.assertEqual(delete_argv, ["iptables", "-D", "FORWARD",
                                       "-s", "10.1.2.3", "-j", "DROP"])

    def test_unisolate_idempotent_when_rule_absent(self):
        # 规则已不存在 → 视为已恢复 (幂等)
        b = self._backend()
        with patch("subprocess.run", side_effect=_mock_run([1])) as m:
            self.assertTrue(b.unisolate("ns", "pod", "10.1.2.3"))
        self.assertEqual(m.call_count, 1)

    def test_unisolate_delete_failure_returns_false(self):
        b = self._backend()
        with patch("subprocess.run", side_effect=_mock_run([0, 1])) as m:
            self.assertFalse(b.unisolate("ns", "pod", "10.1.2.3"))
        self.assertEqual(m.call_count, 2)

    # ---- in_cluster nsenter 前缀 ----

    def test_in_cluster_prepends_nsenter(self):
        b = NsenterIptablesBackend()
        b._in_cluster = True
        with patch("subprocess.run", side_effect=_mock_run([1, 0])) as m:
            self.assertTrue(b.isolate("ns", "pod", "10.1.2.3"))
        insert_argv = m.call_args_list[1].args[0]
        self.assertEqual(insert_argv[:6],
                         ["nsenter", "-t", "1", "-m", "-n", "iptables"])
        self.assertEqual(insert_argv[-4:],
                         ["-s", "10.1.2.3", "-j", "DROP"])

    def test_argv_never_uses_shell(self):
        # 所有 subprocess 调用必须 shell=False 列表参数 (无 shell 注入面)
        b = self._backend()
        with patch("subprocess.run", side_effect=_mock_run([1, 0])) as m:
            b.isolate("ns", "pod", "10.1.2.3")
        for call in m.call_args_list:
            self.assertIsInstance(call.args[0], list)
            self.assertFalse(call.kwargs.get("shell", False))


class TestNsenterNetBlockerMain(unittest.TestCase):
    """main.py _NsenterNetBlocker — ast 提取类 + patch subprocess.run。"""

    @classmethod
    def setUpClass(cls):
        cls.Cls = _load_main_blocker_cls()

    def _blocker(self):
        return self.Cls()

    def test_block_inserts_rule_and_marks_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            nb = self._blocker()
            with patch("subprocess.run",
                       side_effect=_mock_run([1, 0])) as m:
                self.assertTrue(nb.block("1.2.3.4", 4444))
            self.assertIn("1.2.3.4:4444", nb.blocked)
            insert_argv = m.call_args_list[1].args[0]
            self.assertEqual(insert_argv[:2], ["nsenter", "-t"])
            self.assertEqual(insert_argv[-8:],
                             ["-d", "1.2.3.4", "-p", "tcp", "--dport",
                              "4444", "-j", "DROP"])

    def test_block_idempotent_existing_rule(self):
        nb = self._blocker()
        with patch("subprocess.run", side_effect=_mock_run([0])) as m:
            self.assertTrue(nb.block("1.2.3.4", 4444))
        self.assertEqual(m.call_count, 1)

    def test_block_failure_does_not_report_blocked(self):
        # 核心回归: iptables 失败 → False 且不标记 blocked (旧实现虚报成功)
        nb = self._blocker()
        with patch("subprocess.run", side_effect=_mock_run([1, 1])) as m:
            self.assertFalse(nb.block("1.2.3.4", 4444))
        self.assertNotIn("1.2.3.4:4444", nb.blocked)
        self.assertEqual(m.call_count, 2)

    def test_block_short_circuit_bad_port(self):
        nb = self._blocker()
        with patch("subprocess.run", side_effect=_mock_run([0])) as m:
            self.assertFalse(nb.block("1.2.3.4", 0))
        m.assert_not_called()

    def test_unblock_deletes_and_clears(self):
        nb = self._blocker()
        with patch("subprocess.run",
                   side_effect=_mock_run([1, 0])) as m:
            nb.block("1.2.3.4", 4444)
        nb.blocked["1.2.3.4:4444"] = 1234567.0  # 预置快照态
        with patch("subprocess.run",
                   side_effect=_mock_run([0, 0])) as m:
            self.assertTrue(nb.unblock("1.2.3.4", 4444))
        self.assertNotIn("1.2.3.4:4444", nb.blocked)
        delete_argv = m.call_args_list[1].args[0]
        self.assertEqual(delete_argv[:7], ["nsenter", "-t", "1", "-m", "-n",
                                           "iptables", "-D"])

    def test_unblock_idempotent_absent_rule(self):
        nb = self._blocker()
        with patch("subprocess.run", side_effect=_mock_run([1])) as m:
            self.assertTrue(nb.unblock("1.2.3.4", 4444))
        self.assertEqual(m.call_count, 1)


if __name__ == "__main__":
    unittest.main()
