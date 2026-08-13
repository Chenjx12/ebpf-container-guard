"""表单条件解析单测 (v0.4.0 规则引擎重构 — dashboard 侧)"""
import yaml
import pytest

# common.py 顶部 import streamlit/docker —— 无副作用, 可被 pytest import
from dashboard.common import parse_condition_rows, CONDITION_OPS


class TestParseConditionRows:
    def test_exact_match_scalar(self):
        assert parse_condition_rows([("fstype", "==", "proc")]) == [
            {"fstype": "proc"}]

    def test_exact_match_list(self):
        assert parse_condition_rows([("comm", "==", "curl, wget, nc")]) == [
            {"comm": ["curl", "wget", "nc"]}]

    def test_operator_row(self):
        assert parse_condition_rows(
            [("comm", "neq", "dockerd, containerd")]) == [
            {"comm": {"neq": ["dockerd", "containerd"]}}]
        assert parse_condition_rows([("target_path", "startswith", "/etc/")]) == [
            {"target_path": {"startswith": "/etc/"}}]
        assert parse_condition_rows([("target_path", "glob", "/proc/*")]) == [
            {"target_path": {"glob": "/proc/*"}}]

    def test_empty_rows_skipped(self):
        assert parse_condition_rows([("", "==", "x"), ("fstype", "==", "")]) == []

    def test_multiple_rows_all(self):
        nodes = parse_condition_rows(
            [("fstype", "==", "proc"), ("comm", "neq", "dockerd")])
        assert nodes == [{"fstype": "proc"}, {"comm": {"neq": "dockerd"}}]

    def test_ops_cover_schema(self):
        # 表单操作符必须是 rule_schema.OPS 的子集 (== 是表单对精确匹配的表达)
        from detector.rule_schema import OPS
        assert set(CONDITION_OPS[1:]) <= set(OPS)


class TestAppendRuleToYaml:
    def test_old_style_rule_normalized_and_written(self, monkeypatch, tmp_path):
        """旧式扁平 condition 经 append 归一化后合法落盘 (热加载可直接消费)"""
        from dashboard import common
        from detector.rule_schema import validate_rules

        rules_file = tmp_path / "rules.yaml"
        audit_file = tmp_path / "audit.log"
        rules_file.write_text("rules:\n")  # block 风格, 与真实 rules.yaml 一致
        monkeypatch.setattr(common, "RULES_PATH", rules_file)
        monkeypatch.setattr(common, "RULES_AUDIT_LOG", audit_file)

        ok = common.append_rule_to_yaml({
            "name": "test_append",
            "severity": "LOW",
            "condition": {"event_type": "execve", "comm": "curl"},
            "action": "alert_and_log",
        }, source="manual")
        assert ok
        data = yaml.safe_load(rules_file.read_text())
        assert validate_rules(data["rules"]) == []
        rule = data["rules"][0]
        assert rule["event_type"] == "execve"
        assert "event_type" not in rule["condition"]
        assert rule["condition"] == {"comm": "curl"}
        assert audit_file.exists()

    def test_invalid_rule_rejected(self, monkeypatch, tmp_path):
        """非法规则 (未知字段) 拒绝入库, 不写文件不写审计"""
        from dashboard import common

        rules_file = tmp_path / "rules.yaml"
        audit_file = tmp_path / "audit.log"
        rules_file.write_text(yaml.dump({"rules": []}))
        monkeypatch.setattr(common, "RULES_PATH", rules_file)
        monkeypatch.setattr(common, "RULES_AUDIT_LOG", audit_file)

        ok = common.append_rule_to_yaml({
            "name": "bad_rule",
            "severity": "LOW",
            "condition": {"event_type": "execve", "not_a_field": "curl"},
        }, source="manual")
        assert not ok
        data = yaml.safe_load(rules_file.read_text())
        assert data["rules"] == []
        assert not audit_file.exists()
