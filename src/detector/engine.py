#!/usr/bin/env python3
import fnmatch
from datetime import datetime

import yaml

from detector.rule_schema import (
    RuleValidationError,
    validate_rules,
)


def _op_glob(actual, pattern):
    # 精确匹配优先——fnmatch 把 [2:INIT] 当字符集 (v0.3.11 修复)
    if actual == pattern:
        return True
    return fnmatch.fnmatch(actual, pattern)


# 叶子操作符 (v0.4.0): 入参为 str(actual) 与校验过的操作符值
_LEAF_OPS = {
    "neq": lambda a, v: a not in v if isinstance(v, list) else a != v,
    "startswith": lambda a, v: a.startswith(v),
    "endswith": lambda a, v: a.endswith(v),
    "contains": lambda a, v: v in a,
    "glob": _op_glob,
}


class EscapeDetector:
    def __init__(self, rules_file):
        self.rules_file = rules_file
        self.rules = []
        self.rule_index = {}
        self.reload()
        print(f"[Detector] 已加载 {len(self.rules)} 条规则")

    def reload(self):
        """热加载规则文件（v0.3.3）— 修改 rules.yaml 后无需重启

        v0.4.0: 加载前先 schema 校验; 校验失败保留现有规则集, 避免热加载清空规则
        """
        with open(self.rules_file, 'r') as f:
            new_rules = yaml.safe_load(f).get('rules', [])
        errors = validate_rules(new_rules)
        if errors:
            idx, msg = errors[0]
            if not self.rules:
                raise RuleValidationError(f"规则校验失败 (第 {idx} 条): {msg}")
            print(f"[Detector] ⚠️ 规则校验失败，保留现有 {len(self.rules)} 条规则: "
                  f"{len(errors)} 处错误, 例: 第 {idx} 条 {msg}")
            return
        self.rules = new_rules
        self.rule_index = self._build_rule_index(new_rules)
        print(f"[Detector] 规则已重载: {len(self.rules)} 条")

    def _build_rule_index(self, rules):
        index = {}
        for rule in rules:
            event_type = rule.get('event_type')
            if event_type not in index:
                index[event_type] = []
            index[event_type].append(rule)
        return index

    def check_event(self, event_dict):
        event_type = event_dict.get('event_type')
        if not event_type or event_type not in self.rule_index:
            return []
        matched = []
        for rule in self.rule_index[event_type]:
            if self._eval_node(rule['condition'], event_dict):
                matched.append(rule)
        return matched

    def _eval_node(self, node, event):
        """递归求值条件树。节点为单键 dict (由 rule_schema 保证)。"""
        (key, val), = node.items()
        if key == 'all':
            return all(self._eval_node(n, event) for n in val)
        if key == 'any':
            return any(self._eval_node(n, event) for n in val)
        if key == 'not':
            return not self._eval_node(val, event)
        return self._match_leaf(key, val, event)

    def _match_leaf(self, field, spec, event):
        """叶子匹配: 标量精确 | 列表 OR (元素可为标量或操作符) | 单键操作符"""
        if isinstance(spec, dict):
            (op, v), = spec.items()
            if op == 'exists':
                return (field in event) == v
            if op == 'bitand':
                # 位包含检查 (v0.4.2): 值须为 int, 事件字段与掩码按位与非零
                return isinstance(v, int) and isinstance(
                    event.get(field), int) and (v & event[field]) != 0
            if field not in event:
                return False
            return _LEAF_OPS[op](str(event[field]), v)
        if field not in event:
            return False
        if isinstance(spec, list):
            actual = event[field]
            for item in spec:
                if isinstance(item, dict):
                    (op, v), = item.items()
                    if op == 'exists':
                        if (field in event) == v:
                            return True
                    elif op == 'bitand':
                        if isinstance(v, int) and isinstance(
                                actual, int) and (v & actual) != 0:
                            return True
                    elif _LEAF_OPS[op](str(actual), v):
                        return True
                elif actual == item:
                    return True
            return False
        return event[field] == spec

    def generate_alert(self, rule, event):
        return {
            'timestamp': datetime.now().isoformat(),
            'rule_name': rule['name'],
            'severity': rule['severity'],
            'description': rule['description'],
            'event': event
        }


def print_alert(alert):
    RED = '\033[91m'
    RESET = '\033[0m'
    BG_RED = '\033[101m'
    sev = alert['severity']
    color = BG_RED if sev == 'CRITICAL' else RED
    print(f"\n{color}🚨 安全告警 - {sev} 级别 {RESET}")
    print(f"{RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
    print(f"{RED}规则: {alert['rule_name']}{RESET}")
    print(f"{RED}描述: {alert['description']}{RESET}")
    evt = alert['event']
    print(f"{RED}容器: {evt.get('container_id', 'unknown')}{RESET}")
    print(f"{RED}进程: {evt.get('pid')} ({evt.get('comm')}){RESET}")
    if 'fstype' in evt:
        print(f"{RED}文件系统: {evt['fstype']} -> 目标: {evt.get('target_path')}{RESET}")
    if 'request' in evt:
        print(f"{RED}Ptrace请求: {evt['request']} -> 目标PID: {evt.get('target_pid')}{RESET}")
    # 🚀 留给读者的作业扩展：在告警中显示 openat 的路径
    if evt.get('event_type') == 'openat' and 'target_path' in evt:
        print(f"{RED}访问路径: {evt['target_path']}{RESET}")

    print(f"{color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}\n")


def log_alert(alert, log_file="detection.log"):
    evt = alert['event']
    with open(log_file, 'a') as f:
        f.write(f"[{alert['timestamp']}] {alert['severity']} | "
                f"{alert['rule_name']} | "
                f"容器={evt.get('container_id','?')} "
                f"PID={evt.get('pid','?')} "
                f"Comm={evt.get('comm','?')}\n")
