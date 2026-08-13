"""rule_schema 校验与归一化单测（v0.4.0 规则引擎重构）"""
import pytest

from detector.rule_schema import (
    RuleValidationError,
    validate_rule,
    validate_rules,
    normalize_ai_rule,
)

# 新 schema 合法规则示例
VALID_RULES = [
    {  # 纯 not（原 reverse_shell 白名单）
        "name": "reverse_shell",
        "event_type": "connect",
        "severity": "HIGH",
        "condition": {"not": {"comm": ["dockerd", "containerd", "docker-proxy"]}},
    },
    {  # all + not(any)（原 procfs_mount_escape）
        "name": "procfs_mount_escape",
        "event_type": "mount",
        "severity": "CRITICAL",
        "condition": {
            "all": [
                {"fstype": "proc"},
                {"not": {"any": [
                    {"comm": ["dockerd", "containerd", "runc:[2:INIT]", "runc"]},
                    {"target_path": [{"glob": "/proc/thread-self/fd/*"}]},
                ]}},
            ]
        },
    },
    {  # 操作符组合
        "name": "suspicious_exec",
        "event_type": "execve",
        "severity": "MEDIUM",
        "condition": {
            "all": [
                {"target_path": {"endswith": ["/bin/sh", "/bin/bash"]}},
                {"comm": {"neq": "runc"}},
                {"pid": {"exists": True}},
            ]
        },
    },
    {  # 深度 4 嵌套
        "name": "deep_nested",
        "event_type": "openat",
        "severity": "LOW",
        "condition": {
            "all": [
                {"any": [
                    {"target_path": {"startswith": "/etc/"}},
                    {"target_path": {"contains": "shadow"}},
                ]},
                {"not": {"any": [{"comm": "bash"}, {"comm": {"neq": "zsh"}}]}},
            ]
        },
    },
]

# (name, 非法规则) — 校验应 raise RuleValidationError
INVALID_RULES = [
    ("非 map", ["not_a_dict"]),
    ("缺 name", {"event_type": "mount", "severity": "HIGH", "condition": {"fstype": "proc"}}),
    ("name 为空", {"name": "", "event_type": "mount", "severity": "HIGH", "condition": {"fstype": "proc"}}),
    ("缺 event_type", {"name": "x", "severity": "HIGH", "condition": {"fstype": "proc"}}),
    ("event_type 非法", {"name": "x", "event_type": "read", "severity": "HIGH", "condition": {"fstype": "proc"}}),
    ("缺 severity", {"name": "x", "event_type": "mount", "condition": {"fstype": "proc"}}),
    ("severity 非法", {"name": "x", "event_type": "mount", "severity": "URGENT", "condition": {"fstype": "proc"}}),
    ("缺 condition", {"name": "x", "event_type": "mount", "severity": "HIGH"}),
    ("condition 双键", {"name": "x", "event_type": "mount", "severity": "HIGH",
                        "condition": {"fstype": "proc", "comm": "runc"}}),
    ("condition 未知字段", {"name": "x", "event_type": "mount", "severity": "HIGH",
                          "condition": {"fs_type": "proc"}}),
    ("未知操作符", {"name": "x", "event_type": "mount", "severity": "HIGH",
                   "condition": {"fstype": {"regex": "p.*"}}}),
    ("exists 值非 bool", {"name": "x", "event_type": "mount", "severity": "HIGH",
                          "condition": {"fstype": {"exists": "yes"}}}),
    ("空列表", {"name": "x", "event_type": "mount", "severity": "HIGH",
               "condition": {"all": []}}),
    ("嵌套列表", {"name": "x", "event_type": "mount", "severity": "HIGH",
                 "condition": {"fstype": [["proc"]]}}),
    ("超深 (6 层)", {"name": "x", "event_type": "mount", "severity": "HIGH",
                    "condition": {"all": [{"all": [{"all": [{"all": [
                        {"all": [{"fstype": "proc"}]}]}]}]}]}}),
    ("condition 内禁 event_type", {"name": "x", "event_type": "mount", "severity": "HIGH",
                                   "condition": {"event_type": "mount"}}),
    ("残留 exclude", {"name": "x", "event_type": "mount", "severity": "HIGH",
                      "condition": {"fstype": "proc"}, "exclude": {"comm": ["runc"]}}),
    ("not 值非节点", {"name": "x", "event_type": "mount", "severity": "HIGH",
                      "condition": {"not": ["comm"]}}),
    ("all 值非列表", {"name": "x", "event_type": "mount", "severity": "HIGH",
                      "condition": {"all": {"fstype": "proc"}}}),
    ("叶子值非法类型", {"name": "x", "event_type": "mount", "severity": "HIGH",
                       "condition": {"fstype": 1.5}}),
]


class TestValidateRule:
    @pytest.mark.parametrize("rule", VALID_RULES)
    def test_valid_rules_pass(self, rule):
        validate_rule(rule)  # 不 raise

    @pytest.mark.parametrize("name,rule", INVALID_RULES, ids=[n for n, _ in INVALID_RULES])
    def test_invalid_rules_raise(self, name, rule):
        with pytest.raises(RuleValidationError):
            validate_rule(rule)

    def test_message_contains_field_hint(self):
        with pytest.raises(RuleValidationError, match="event_type"):
            validate_rule(INVALID_RULES[3][1])


class TestValidateRules:
    def test_all_valid_returns_empty(self):
        assert validate_rules(VALID_RULES) == []

    def test_mixed_returns_indexed_errors(self):
        rules = [VALID_RULES[0], INVALID_RULES[1][1], VALID_RULES[1], INVALID_RULES[7][1]]
        errors = validate_rules(rules)
        assert [i for i, _ in errors] == [1, 3]

    def test_errors_are_readable(self):
        rules = [INVALID_RULES[9][1]]
        _, msg = validate_rules(rules)[0]
        assert "未知字段" in msg


class TestNormalizeAiRule:
    def test_old_flat_condition_convert(self):
        rule = {
            "name": "ai_rule",
            "severity": "HIGH",
            "condition": {
                "event_type": "execve",
                "comm": ["curl", "wget"],
            },
        }
        out, err = normalize_ai_rule(rule)
        assert err is None
        assert out["event_type"] == "execve"
        assert "event_type" not in out["condition"]
        assert out["condition"] == {"comm": ["curl", "wget"]}

    def test_exclude_convert_to_not_any(self):
        rule = {
            "name": "ai_rule",
            "severity": "HIGH",
            "condition": {"event_type": "mount", "fstype": "proc"},
            "exclude": {"comm": ["dockerd"]},
        }
        out, err = normalize_ai_rule(rule)
        assert err is None
        assert out["condition"] == {
            "all": [
                {"fstype": "proc"},
                {"not": {"any": [{"comm": ["dockerd"]}]}},
            ]
        }
        assert "exclude" not in out

    def test_pure_exclude_becomes_not(self):
        rule = {
            "name": "ai_rule",
            "severity": "HIGH",
            "condition": {"event_type": "connect"},
            "exclude": {"comm": ["dockerd", "containerd"]},
        }
        out, err = normalize_ai_rule(rule)
        assert err is None
        assert out["condition"] == {"not": {"any": [{"comm": ["dockerd", "containerd"]}]}}

    def test_new_style_preserved(self):
        rule = {
            "name": "ai_rule",
            "severity": "HIGH",
            "event_type": "execve",
            "condition": {"any": [{"comm": "curl"}, {"comm": "wget"}]},
        }
        out, err = normalize_ai_rule(rule)
        assert err is None
        assert out["condition"] == {"any": [{"comm": "curl"}, {"comm": "wget"}]}

    def test_top_level_event_type_wins(self):
        rule = {
            "name": "ai_rule",
            "severity": "HIGH",
            "event_type": "connect",
            "condition": {"event_type": "execve", "dport": 4444},
        }
        out, err = normalize_ai_rule(rule)
        assert err is None
        assert out["event_type"] == "connect"
        assert out["condition"] == {"dport": 4444}

    def test_non_dict_returns_error(self):
        rule, err = normalize_ai_rule(["bad"])
        assert rule is None and err is not None

    def test_empty_condition_returns_error(self):
        rule, err = normalize_ai_rule({"name": "x", "severity": "HIGH",
                                       "condition": {"event_type": "mount"}})
        assert rule is None and err is not None

    def test_missing_event_type_returns_error(self):
        rule, err = normalize_ai_rule({"name": "x", "severity": "HIGH",
                                       "condition": {"fstype": "proc"}})
        assert rule is None and err is not None
