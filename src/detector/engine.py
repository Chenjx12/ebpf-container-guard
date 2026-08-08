#!/usr/bin/env python3
import yaml
from datetime import datetime
import fnmatch


class EscapeDetector:
    def __init__(self, rules_file):
        with open(rules_file, 'r') as f:
            self.rules = yaml.safe_load(f).get('rules', [])
        self.rule_index = self._build_rule_index()
        print(f"[Detector] 已加载 {len(self.rules)} 条规则")

    def _build_rule_index(self):
        index = {}
        for rule in self.rules:
            event_type = rule.get('condition', {}).get('event_type')
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
            if self._match(event_dict, rule['condition']):
                if not self._is_excluded(event_dict, rule.get('exclude', {})):
                    matched.append(rule)
        return matched

    def _match(self, event, condition):
        """精确匹配 + 列表OR匹配"""
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

    def _is_excluded(self, event, exclude):
        """检查事件是否匹配排除条件（支持通配符）"""
        for key, patterns in exclude.items():
            if key not in event:
                continue
            actual = event[key]
            if isinstance(patterns, str):
                patterns = [patterns]
            for pattern in patterns:
                if fnmatch.fnmatch(str(actual), pattern):
                    return True  # 命中排除规则，跳过
        return False

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
