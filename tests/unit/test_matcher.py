"""匹配器单测 (v0.4.0 规则引擎重构)

- 叶子/组合表驱动: 操作符矩阵 + 嵌套求值 + 边界
- 迁移等价性: fixture 旧规则 vs config 新规则, 事件池逐条一致 (安全网)
- 迁移脚本输出与 config 结构一致
- reload 校验语义: 坏规则保留旧集, 首次加载失败即 raise
"""
import fnmatch
from pathlib import Path

import pytest
import yaml

from detector.engine import EscapeDetector
from detector.rule_schema import RuleValidationError
from scripts.migrate_rules_v04 import migrate_rule

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG_RULES = Path(__file__).resolve().parents[2] / "config" / "rules.yaml"

# 合成事件池: 覆盖全部规则 × 边界 (白名单 comm、通配路径、字段缺失)
EVENT_POOL = [
    # mount
    {"event_type": "mount", "pid": 100, "comm": "attacker", "container_id": "c1", "fstype": "proc", "target_path": "/tmp/host_proc"},
    {"event_type": "mount", "pid": 100, "comm": "attacker", "container_id": "c1", "fstype": "proc", "target_path": "/mnt/x"},
    {"event_type": "mount", "pid": 1, "comm": "runc:[2:INIT]", "container_id": "c1", "fstype": "proc", "target_path": "/proc"},
    {"event_type": "mount", "pid": 1, "comm": "dockerd", "container_id": "c1", "fstype": "proc", "target_path": "/proc"},
    {"event_type": "mount", "pid": 100, "comm": "attacker", "container_id": "c1", "fstype": "proc", "target_path": "/proc/thread-self/fd/3"},
    {"event_type": "mount", "pid": 100, "comm": "attacker", "container_id": "c1", "fstype": "cgroup", "target_path": "/tmp/cg"},
    {"event_type": "mount", "pid": 1, "comm": "containerd", "container_id": "c1", "fstype": "cgroup", "target_path": "/sys/fs/cgroup"},
    {"event_type": "mount", "pid": 100, "comm": "attacker", "container_id": "c1", "fstype": "ext4", "target_path": "/mnt/data"},
    {"event_type": "mount", "pid": 100, "comm": "attacker", "container_id": "c1", "target_path": "/var/run/docker.sock"},
    {"event_type": "mount", "pid": 100, "comm": "attacker", "container_id": "c1", "fstype": "tmpfs", "target_path": "/run/docker.sock"},
    {"event_type": "mount", "pid": 100, "fstype": "proc", "target_path": "/tmp/host_proc"},  # comm 缺失
    # ptrace
    {"event_type": "ptrace", "pid": 200, "comm": "gdb", "container_id": "c1", "target_pid": 1, "request": "PTRACE_ATTACH"},
    {"event_type": "ptrace", "pid": 200, "comm": "gdb", "container_id": "c1", "target_pid": 42, "request": "PTRACE_ATTACH"},
    {"event_type": "ptrace", "pid": 200, "comm": "gdb", "container_id": "c1", "request": "PTRACE_ATTACH"},  # target_pid 缺失
    # execve
    {"event_type": "execve", "pid": 300, "comm": "nsenter", "container_id": "c1", "target_path": "/usr/bin/nsenter"},
    {"event_type": "execve", "pid": 300, "comm": "nsenter", "container_id": "c1", "target_path": "/usr/bin/other"},
    {"event_type": "execve", "pid": 300, "comm": "attacker", "container_id": "c1", "target_path": "/bin/sh"},
    {"event_type": "execve", "pid": 300, "comm": "bash", "container_id": "c1", "target_path": "/bin/bash"},
    {"event_type": "execve", "pid": 300, "comm": "dash", "container_id": "c1", "target_path": "/usr/bin/dash"},
    {"event_type": "execve", "pid": 300, "comm": "curl", "container_id": "c1", "target_path": "/usr/bin/curl"},
    {"event_type": "execve", "pid": 300, "comm": "attacker", "container_id": "c1", "target_path": "/usr/bin/wget"},
    {"event_type": "execve", "pid": 300, "comm": "attacker", "container_id": "c1", "target_path": "/usr/bin/python3"},
    {"event_type": "execve", "pid": 300, "comm": "attacker", "container_id": "c1"},  # target_path 缺失
    # connect
    {"event_type": "connect", "pid": 400, "comm": "nc", "container_id": "c1", "daddr": 3232235521, "dport": 4444},
    {"event_type": "connect", "pid": 400, "comm": "dockerd", "container_id": "c1", "daddr": 3232235521, "dport": 443},
    {"event_type": "connect", "pid": 400, "comm": "docker-proxy", "container_id": "c1", "daddr": 3232235521, "dport": 80},
    {"event_type": "connect", "pid": 400, "comm": "curl", "container_id": "c1", "daddr": 3232235521, "dport": 443},
    {"event_type": "connect", "pid": 400, "comm": "attacker", "container_id": "c1", "dport": 4444},  # daddr 缺失
    {"event_type": "connect", "pid": 400, "comm": "nc", "container_id": "c1"},  # dport 缺失
    {"event_type": "connect", "pid": 400, "daddr": 3232235521, "dport": 443},  # comm 缺失
    # openat
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/etc/shadow"},
    {"event_type": "openat", "pid": 500, "comm": "runc:[2:INIT]", "container_id": "c1", "target_path": "/etc/shadow"},
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/etc/passwd"},
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/proc/kcore"},
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/host_etc/shadow"},
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/host_proc/kcore"},
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/etc/hosts"},
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/run/docker.sock"},
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/host_sys/block"},
    {"event_type": "openat", "pid": 500, "comm": "attacker", "container_id": "c1", "target_path": "/home/user/notes.txt"},
]


@pytest.fixture(scope="module")
def detector():
    return EscapeDetector(str(CONFIG_RULES))


@pytest.fixture(scope="module")
def old_rules():
    data = yaml.safe_load((FIXTURES / "rules_v03_flat.yaml").read_text())
    return data["rules"]


@pytest.fixture(scope="module")
def new_rules():
    data = yaml.safe_load(CONFIG_RULES.read_text())
    return data["rules"]


# ---- v0.3 参照实现 (迁移等价性基准, 与历史 engine.py 逐字一致) ----

def _legacy_match(event, condition):
    for key, expected in condition.items():
        if key not in event:
            return False
        actual = event[key]
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _legacy_is_excluded(event, exclude):
    for key, patterns in exclude.items():
        if key not in event:
            continue
        actual = str(event[key])
        if isinstance(patterns, str):
            patterns = [patterns]
        for pattern in patterns:
            # 精确匹配优先——fnmatch 把 [2:INIT] 当字符集 (v0.3.11 修复)
            if actual == pattern:
                return True
            if fnmatch.fnmatch(actual, pattern):
                return True
    return False


def _legacy_check(rule, event):
    """旧 check_event 的单规则逻辑 (不含 event_type 索引)"""
    if not _legacy_match(event, rule["condition"]):
        return False
    return not _legacy_is_excluded(event, rule.get("exclude", {}))


class TestLeafMatch:
    @pytest.mark.parametrize("cond,event,expected", [
        # 标量精确
        ({"comm": "bash"}, {"comm": "bash"}, True),
        ({"comm": "bash"}, {"comm": "zsh"}, False),
        ({"target_pid": 1}, {"target_pid": 1}, True),
        ({"target_pid": 1}, {"target_pid": 2}, False),
        # 列表 OR 精确
        ({"comm": ["bash", "dash"]}, {"comm": "dash"}, True),
        ({"comm": ["bash", "dash"]}, {"comm": "fish"}, False),
        ({"comm": ["bash", "dash"]}, {"pid": 1}, False),  # 字段缺失
        # neq
        ({"comm": {"neq": "runc"}}, {"comm": "bash"}, True),
        ({"comm": {"neq": "runc"}}, {"comm": "runc"}, False),
        ({"comm": {"neq": ["dockerd", "containerd"]}}, {"comm": "runc"}, True),
        ({"comm": {"neq": ["dockerd", "containerd"]}}, {"comm": "dockerd"}, False),
        # startswith / endswith / contains
        ({"target_path": {"startswith": "/etc/"}}, {"target_path": "/etc/shadow"}, True),
        ({"target_path": {"startswith": "/etc/"}}, {"target_path": "/tmp/x"}, False),
        ({"target_path": {"endswith": ".sh"}}, {"target_path": "evil.sh"}, True),
        ({"target_path": {"endswith": ".sh"}}, {"target_path": "evil.py"}, False),
        ({"comm": {"contains": "dock"}}, {"comm": "dockerd"}, True),
        ({"comm": {"contains": "dock"}}, {"comm": "runc"}, False),
        # glob (含精确优先回归: runc:[2:INIT])
        ({"target_path": {"glob": "/proc/thread-self/fd/*"}}, {"target_path": "/proc/thread-self/fd/3"}, True),
        ({"target_path": {"glob": "/proc/thread-self/fd/*"}}, {"target_path": "/tmp/x"}, False),
        ({"comm": {"glob": "runc:[2:INIT]"}}, {"comm": "runc:[2:INIT]"}, True),
        ({"comm": {"glob": "runc:[2:INIT]"}}, {"comm": "runc"}, False),
        # exists
        ({"fstype": {"exists": True}}, {"fstype": "proc"}, True),
        ({"fstype": {"exists": True}}, {"comm": "runc"}, False),
        ({"fstype": {"exists": False}}, {"fstype": "proc"}, False),
        ({"fstype": {"exists": False}}, {"comm": "runc"}, True),
        # 列表内嵌操作符元素 (OR 语义)
        ({"target_path": ["/etc/shadow", {"endswith": "docker.sock"}]}, {"target_path": "/run/docker.sock"}, True),
        ({"target_path": ["/etc/shadow", {"endswith": "docker.sock"}]}, {"target_path": "/etc/hosts"}, False),
        ({"comm": [{"glob": "runc:[2:INIT]"}, "bash"]}, {"comm": "runc:[2:INIT]"}, True),
        # bitand (v0.4.2)
        ({"cap_effective": {"bitand": 2097152}}, {"cap_effective": 2097152}, True),   # CAP_SYS_ADMIN
        ({"cap_effective": {"bitand": 2097152}}, {"cap_effective": 1048576}, False),  # CAP_SYS_RAWIO
        ({"cap_effective": {"bitand": 2097152}}, {"cap_effective": 2097152 | 1}, True),
        ({"cap_effective": {"bitand": 2097152}}, {"comm": "x"}, False),  # 字段缺失
        ({"cap_effective": {"bitand": "2097152"}}, {"cap_effective": 2097152}, False),  # 非 int 值
        ({"cap_effective": [{"bitand": 2097152}, 0]}, {"cap_effective": 2097152}, True),  # list 内嵌
    ])
    def test_leaf(self, detector, cond, event, expected):
        (field, spec), = cond.items()
        assert detector._match_leaf(field, spec, event) == expected

    @pytest.mark.parametrize("cond,event,expected", [
        # all / any / not
        ({"all": [{"fstype": "proc"}, {"comm": "mount"}]},
         {"fstype": "proc", "comm": "mount"}, True),
        ({"all": [{"fstype": "proc"}, {"comm": "mount"}]},
         {"fstype": "proc", "comm": "dockerd"}, False),
        ({"any": [{"fstype": "proc"}, {"comm": "mount"}]},
         {"fstype": "ext4", "comm": "mount"}, True),
        ({"any": [{"fstype": "proc"}, {"comm": "mount"}]},
         {"fstype": "ext4", "comm": "bash"}, False),
        ({"not": {"comm": ["dockerd"]}}, {"comm": "attacker"}, True),
        ({"not": {"comm": ["dockerd"]}}, {"comm": "dockerd"}, False),
        # 嵌套 3 层
        ({"all": [{"fstype": "proc"},
                  {"not": {"any": [{"comm": ["dockerd", "containerd"]},
                                   {"fstype": "cgroup"}]}}]},
         {"fstype": "proc", "comm": "attacker"}, True),
        ({"all": [{"fstype": "proc"},
                  {"not": {"any": [{"comm": ["dockerd", "containerd"]},
                                   {"fstype": "cgroup"}]}}]},
         {"fstype": "proc", "comm": "dockerd"}, False),
        ({"all": [{"fstype": "proc"},
                  {"not": {"any": [{"comm": ["dockerd", "containerd"]},
                                   {"fstype": "cgroup"}]}}]},
         {"fstype": "cgroup", "comm": "attacker"}, False),
        # 字段缺失下的 not (comm 缺失 → 叶子 False → not → True)
        ({"not": {"comm": ["dockerd"]}}, {"pid": 1}, True),
        # 空列表语义 (校验层拒绝, 求值层兜底)
        ({"all": []}, {"comm": "x"}, True),
        ({"any": []}, {"comm": "x"}, False),
    ])
    def test_combinators(self, detector, cond, event, expected):
        assert detector._eval_node(cond, event) == expected

    def test_runc_bracket_regression(self, detector):
        """v0.3.11 回归: runc:[2:INIT] 不能被 fnmatch 字符集误判"""
        cond = {"not": {"any": [{"comm": ["dockerd", "containerd", "runc:[2:INIT]", "runc"]}]}}
        assert detector._eval_node(cond, {"comm": "runc:[2:INIT]"}) is False
        assert detector._eval_node(cond, {"comm": "bash"}) is True


class TestMigrationEquivalence:
    def test_migration_output_matches_config(self, old_rules, new_rules):
        """迁移脚本输出与 config/rules.yaml 同名规则逐条一致 (迁移忠实性)

        v0.4.2 起 config 含新增规则 (12 条), 只对比迁移覆盖的 10 条。
        """
        migrated = [r for r in new_rules if r["name"] in {o["name"]
                                                          for o in old_rules}]
        assert len(migrated) == len(old_rules)
        for old, new in zip(old_rules, migrated):
            assert old["name"] == new["name"]
            assert migrate_rule(old) == new, f"规则 {old['name']} 迁移输出与 config 不一致"

    def test_old_vs_new_semantics_equivalent(self, old_rules, detector):
        """语义等价性: 旧 check vs 新求值器, 事件池逐条一致"""
        new_rules = detector.rules
        mismatches = []
        for old in old_rules:
            new = next(r for r in new_rules if r["name"] == old["name"])
            if old["condition"].get("event_type") != new["event_type"]:
                mismatches.append((old["name"], "event_type 不匹配", old, new))
                continue
            for ev in EVENT_POOL:
                if ev.get("event_type") != old["condition"].get("event_type"):
                    continue
                old_hit = _legacy_check(old, ev)
                new_hit = detector._eval_node(new["condition"], ev)
                if old_hit != new_hit:
                    mismatches.append((old["name"], ev, old_hit, new_hit))
        assert mismatches == []

    def test_runc_init_exclusion_still_works(self, detector):
        """回归: procfs_mount_escape 对 runc:[2:INIT] 的挂载不告警 (白名单)"""
        rule = next(r for r in detector.rules if r["name"] == "procfs_mount_escape")
        base = {"event_type": "mount", "fstype": "proc", "target_path": "/proc"}
        assert detector._eval_node(rule["condition"], {**base, "comm": "runc:[2:INIT]"}) is False
        assert detector._eval_node(rule["condition"], {**base, "comm": "mount"}) is True

    def test_glob_exclusion_preserved(self, detector):
        """回归: /proc/thread-self/fd/* 通配排除语义保留"""
        rule = next(r for r in detector.rules if r["name"] == "procfs_mount_escape")
        base = {"event_type": "mount", "fstype": "proc", "comm": "mount"}
        assert detector._eval_node(rule["condition"], {**base, "target_path": "/proc/thread-self/fd/3"}) is False
        assert detector._eval_node(rule["condition"], {**base, "target_path": "/tmp/x"}) is True


VALID_RULE = {
    "name": "ok_rule",
    "event_type": "mount",
    "severity": "LOW",
    "condition": {"fstype": "proc"},
}
INVALID_RULE = {
    "name": "bad_rule",
    "event_type": "mount",
    "severity": "LOW",
    "condition": {"fstype": "proc", "comm": "x"},  # 双键节点
}


class TestReloadValidation:
    def test_first_load_raises_on_invalid(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(yaml.dump({"rules": [INVALID_RULE]}))
        with pytest.raises(RuleValidationError):
            EscapeDetector(str(rules_file))

    def test_reload_keeps_old_rules_on_invalid(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(yaml.dump({"rules": [VALID_RULE]}))
        d = EscapeDetector(str(rules_file))
        assert len(d.rules) == 1
        rules_file.write_text(yaml.dump({"rules": [VALID_RULE, INVALID_RULE]}))
        d.reload()
        assert len(d.rules) == 1, "坏规则不得清空规则集"

    def test_reload_applies_valid_changes(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(yaml.dump({"rules": [VALID_RULE]}))
        d = EscapeDetector(str(rules_file))
        extra = {**VALID_RULE, "name": "ok_rule_2"}
        rules_file.write_text(yaml.dump({"rules": [VALID_RULE, extra]}))
        d.reload()
        assert len(d.rules) == 2
