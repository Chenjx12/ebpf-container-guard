#!/usr/bin/env python3
"""Unit tests: AssetClassifier + AssetStore (v0.6.3, ADR-050).

Coverage:
  - classifier: namespace glob / labels 全等 / image 正则 / 首条命中 /
    兜底 medium / 非法级别归一
  - store: PENDING_REVIEW 自动落 + auto_inference 留痕; confirm →
    CONFIRMED (human_decision + status_transition); override → OVERRIDDEN;
    元数据变更留痕; 重启恢复 (同一 state/audit 文件重建实例)
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from core.assets import AssetClassifier, AssetStore

ASSETS_YAML = str(ROOT / "config" / "assets.yaml")


class TestAssetClassifier(unittest.TestCase):

    def setUp(self):
        self.cls = AssetClassifier(ASSETS_YAML)

    def test_image_regex_db_critical(self):
        level, rule, _ = self.cls.classify(
            {"id": "a", "image": "mysql:8.0", "namespace": "prod",
             "labels": {}})
        self.assertEqual(level, "critical")
        self.assertIn("数据库", rule)

    def test_namespace_glob_kube_system(self):
        level, rule, _ = self.cls.classify(
            {"id": "b", "image": "nginx:1.25", "namespace": "kube-system",
             "labels": {}})
        self.assertEqual(level, "high")
        self.assertIn("kube-system", rule)

    def test_image_regex_network_first_match(self):
        # nginx 同时匹配 kube-system(ns) 之外 → 网络组件规则 (首条命中)
        level, rule, _ = self.cls.classify(
            {"id": "c", "image": "nginx:1.25", "namespace": "prod",
             "labels": {"app.kubernetes.io/component": "application"}})
        self.assertEqual(level, "high")
        self.assertIn("网络", rule)

    def test_labels_all_must_hit(self):
        # labels 多键: 缺一则不命中业务规则 → 兜底/后续规则
        level, _, _ = self.cls.classify(
            {"id": "d", "image": "random-app:v1", "namespace": "prod",
             "labels": {}})
        self.assertEqual(level, "medium")  # 兜底

    def test_fallback_default_medium(self):
        level, rule, _ = self.cls.classify(
            {"id": "e", "image": "unknown-app:1.0", "namespace": "custom",
             "labels": {}})
        self.assertEqual(level, "medium")
        self.assertIsNone(rule)

    def test_debug_image_low(self):
        level, _, _ = self.cls.classify(
            {"id": "f", "image": "python:3.10", "namespace": "dev",
             "labels": {}})
        self.assertEqual(level, "low")


class TestAssetStore(unittest.TestCase):

    def _store(self, tmp):
        return AssetStore(
            state_file=str(tmp / "assets.yaml"),
            audit_file=str(tmp / "assets_audit.log"),
            classifier=AssetClassifier(ASSETS_YAML))

    def test_new_asset_pending_review_with_auto_inference(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(Path(td))
            rec = store.ensure_asset(
                {"id": "abc123", "name": "db-1",
                 "image": "mysql:8.0", "namespace": "prod", "labels": {}})
            self.assertEqual(rec["state"], "PENDING_REVIEW")
            self.assertEqual(rec["level"], "critical")
            self.assertEqual(rec["level_source"], "auto")
            audit = store.audit_log("abc123")
            self.assertEqual(len(audit), 1)
            self.assertEqual(audit[0]["type"], "auto_inference")
            self.assertTrue(os.path.exists(Path(td) / "assets_audit.log"))

    def test_confirm_transition_and_audit(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(Path(td))
            store.ensure_asset(
                {"id": "abc123", "name": "db-1",
                 "image": "mysql:8.0", "namespace": "prod", "labels": {}})
            rec = store.confirm("abc123", "admin", "生产数据库，确认受控")
            self.assertEqual(rec["state"], "CONFIRMED")
            audit = store.audit_log("abc123")
            types = [a["type"] for a in audit]
            self.assertIn("human_decision", types)
            self.assertIn("status_transition", types)
            self.assertEqual(audit[-1]["detail"]["from"], "PENDING_REVIEW")
            self.assertEqual(audit[-1]["detail"]["to"], "CONFIRMED")

    def test_override_sets_level_and_state(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(Path(td))
            store.ensure_asset(
                {"id": "abc123", "name": "tool-1",
                 "image": "random-app:v1", "namespace": "prod", "labels": {}})
            rec = store.override("abc123", "high", "admin", "实际是核心服务")
            self.assertEqual(rec["state"], "OVERRIDDEN")
            self.assertEqual(rec["level"], "high")
            self.assertEqual(rec["level_source"], "override")
            audit = store.audit_log("abc123")
            self.assertEqual(
                len([a for a in audit if a["type"] == "human_decision"]), 1)

    def test_invalid_override_level_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(Path(td))
            store.ensure_asset(
                {"id": "abc123", "name": "t",
                 "image": "x", "namespace": "n", "labels": {}})
            with self.assertRaises(ValueError):
                store.override("abc123", "insane", "admin", "x")

    def test_metadata_change_audited(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(Path(td))
            store.ensure_asset(
                {"id": "abc123", "name": "old-name",
                 "image": "img:v1", "namespace": "prod", "labels": {}})
            rec = store.ensure_asset(
                {"id": "abc123", "name": "new-name",
                 "image": "img:v2", "namespace": "prod", "labels": {}})
            self.assertEqual(rec["name"], "new-name")
            types = [a["type"] for a in store.audit_log("abc123")]
            self.assertIn("auto_inference", types)  # metadata_sync 留痕

    def test_restart_restores_state(self):
        # 验收锚点: 重启后资产状态仍在 (同一 state 文件重建实例)
        with tempfile.TemporaryDirectory() as td:
            store1 = self._store(Path(td))
            store1.ensure_asset(
                {"id": "abc123", "name": "db-1",
                 "image": "mysql:8.0", "namespace": "prod", "labels": {}})
            store1.confirm("abc123", "admin", "确认")
            store2 = self._store(Path(td))  # 模拟 guard 重启
            rec = store2.get("abc123")
            self.assertIsNotNone(rec)
            self.assertEqual(rec["state"], "CONFIRMED")
            self.assertEqual(rec["level"], "critical")
            self.assertEqual(len(store2.audit_log("abc123")), 3)


if __name__ == "__main__":
    unittest.main()