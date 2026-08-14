#!/usr/bin/env python3
"""规则 schema 校验与归一化（v0.4.0 规则引擎重构）

condition 为嵌套条件树:
- 每个节点是单键 dict, 键 ∈ {all, any, not, 字段名}
- all / any: 值是条件节点列表
- not: 值是单个条件节点
- 字段名: 叶子, 值为 标量(精确) | 标量列表(OR 精确) | 单键操作符 dict
- 操作符: neq / startswith / endswith / contains / glob / exists
"""

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
EVENT_TYPES = ("mount", "ptrace", "execve", "connect", "openat", "capset")

# 与 main.py event_dict 构造同步; 新增探针字段时需更新此注册表
KNOWN_FIELDS = {
    "event_type", "pid", "uid", "comm", "container_id", "timestamp",
    "fstype", "target_path", "target_pid", "request", "daddr", "dport",
    "cap_effective", "cap_permitted", "open_flags",
}

CONDITION_KEYS = ("all", "any", "not")
OPS = ("neq", "startswith", "endswith", "contains", "glob", "exists", "bitand")
MAX_DEPTH = 5


class RuleValidationError(ValueError):
    """规则校验失败"""


def validate_rules(rules):
    """批量校验, 返回 [(index, error_msg)] 列表; 合法规则返回 []"""
    errors = []
    for i, rule in enumerate(rules):
        try:
            validate_rule(rule)
        except RuleValidationError as e:
            errors.append((i, str(e)))
    return errors


def validate_rule(rule):
    """校验单条规则, 非法时 raise RuleValidationError"""
    if not isinstance(rule, dict):
        raise RuleValidationError("规则必须是 YAML map")
    for required in ("name", "event_type", "severity", "condition"):
        if required not in rule:
            raise RuleValidationError(f"缺少必填字段: {required}")
    name = rule["name"]
    if not isinstance(name, str) or not name:
        raise RuleValidationError("name 必须是非空字符串")
    event_type = rule["event_type"]
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        raise RuleValidationError(
            f"event_type 必须是 {list(EVENT_TYPES)} 之一, got {event_type!r}")
    severity = rule["severity"]
    if not isinstance(severity, str) or severity.upper() not in SEVERITIES:
        raise RuleValidationError(
            f"severity 必须是 {list(SEVERITIES)} 之一, got {severity!r}")
    if "exclude" in rule:
        raise RuleValidationError(
            "exclude 已移除 (v0.4), 请用 condition 内的 not 表达")
    _validate_node(rule["condition"], "condition", depth=1)


def _validate_node(node, path, depth):
    """校验一个条件节点（单键 dict）"""
    if not isinstance(node, dict):
        raise RuleValidationError(f"{path}: 条件节点必须是 map, got {type(node).__name__}")
    if len(node) != 1:
        raise RuleValidationError(f"{path}: 条件节点必须只有 1 个键, got {sorted(node)}")
    if depth > MAX_DEPTH:
        raise RuleValidationError(f"{path}: 嵌套深度超过 {MAX_DEPTH}")
    (key, val), = node.items()
    if key == "event_type":
        raise RuleValidationError(f"{path}: event_type 必须放在规则顶层, 不能出现在 condition 内")
    if key in CONDITION_KEYS:
        _validate_combinator(key, val, path, depth)
    elif key in KNOWN_FIELDS:
        _validate_leaf(key, val, path)
    else:
        raise RuleValidationError(
            f"{path}: 未知字段 {key!r} (注册表: {sorted(KNOWN_FIELDS)})")


def _validate_combinator(key, val, path, depth):
    if key == "not":
        if not isinstance(val, dict):
            raise RuleValidationError(f"{path}.not: 必须是单个条件节点")
        _validate_node(val, f"{path}.not", depth + 1)
        return
    if not isinstance(val, list) or not val:
        raise RuleValidationError(f"{path}.{key}: 必须是非空条件节点列表")
    for i, item in enumerate(val):
        _validate_node(item, f"{path}.{key}[{i}]", depth + 1)


def _validate_leaf(field, spec, path):
    if isinstance(spec, dict):
        if len(spec) != 1:
            raise RuleValidationError(f"{path}.{field}: 操作符节点必须只有 1 个键")
        (op, v), = spec.items()
        if op not in OPS:
            raise RuleValidationError(
                f"{path}.{field}: 未知操作符 {op!r}, 可用 {list(OPS)}")
        _validate_op_value(op, v, f"{path}.{field}")
    elif isinstance(spec, list):
        if not spec:
            raise RuleValidationError(f"{path}.{field}: 列表不能为空")
        for item in spec:
            if isinstance(item, list):
                raise RuleValidationError(f"{path}.{field}: 列表元素不能嵌套列表")
            _validate_leaf(field, item, path)  # 元素: 标量 或 操作符 dict
    elif not isinstance(spec, (str, int, bool)):
        raise RuleValidationError(
            f"{path}.{field}: 叶子值必须是标量/列表/操作符 map")


def _validate_op_value(op, v, path):
    if op == "exists":
        if not isinstance(v, bool):
            raise RuleValidationError(f"{path}.exists: 值必须是 true/false")
        return
    if op == "bitand":
        if not isinstance(v, int) or isinstance(v, bool):
            raise RuleValidationError(f"{path}.bitand: 值必须是整数 (位掩码)")
        return
    if isinstance(v, (str, int, bool)):
        return
    if isinstance(v, list) and v and all(isinstance(x, (str, int, bool)) for x in v):
        return
    raise RuleValidationError(f"{path}.{op}: 值必须是标量或标量列表")


def normalize_ai_rule(rule):
    """AI 建议规则归一化到新 schema。

    兼容旧式扁平 condition（event_type 提顶层、多字段包 all、exclude 转 not/any）。
    返回 (rule, error); error 非 None 时 rule 不可用。
    """
    if not isinstance(rule, dict):
        return None, "规则必须是 map"
    out = {k: v for k, v in rule.items() if k != "exclude"}
    condition = out.get("condition")
    nodes = []

    if condition is not None:
        if not isinstance(condition, dict):
            return None, "condition 必须是 map"
        condition = dict(condition)
        if "event_type" in condition:  # 旧式: event_type 在 condition 内 → 提顶层
            if out.get("event_type") is None:
                out["event_type"] = condition.pop("event_type")
            else:
                del condition["event_type"]  # 顶层优先
        if any(k in CONDITION_KEYS for k in condition):
            nodes = [condition]  # 已是条件树
        else:
            nodes = [{k: v} for k, v in condition.items()]  # 旧式扁平多字段

    if "exclude" in rule:
        exc = rule["exclude"]
        if not isinstance(exc, dict) or not exc:
            return None, "exclude 必须是非空 map"
        nodes.append({"not": {"any": [{k: v} for k, v in exc.items()]}})

    if not nodes:
        return None, "condition 不能为空 (规则将恒真)"
    if len(nodes) == 1:
        out["condition"] = nodes[0]
    else:
        out["condition"] = {"all": nodes}
    if out.get("event_type") is None:
        return None, "缺少 event_type"
    return out, None
