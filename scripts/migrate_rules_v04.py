#!/usr/bin/env python3
"""一次性迁移: rules.yaml 扁平 condition → v0.4 嵌套条件树 (Falco 风格 AND/OR/not)

映射规则 (严格保语义, 新操作符只供新规则):
- event_type 提出 condition → 顶层 (做索引 + 隐式 AND)
- 多字段 → all
- 列表 → OR 精确匹配 (原样保留)
- exclude → not: {any: [...]}  (原 exclude 是跨字段 OR)

用法:
  python3 scripts/migrate_rules_v04.py [rules.yaml] [--out OUT] [--no-backup]
"""
import argparse
import shutil
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from detector.rule_schema import validate_rules  # noqa: E402


def _exclude_item(value):
    """exclude 值元素: 含 fnmatch 通配符(*? ) → glob 操作符 (保留旧通配语义), 否则保持精确
    (runc:[2:INIT] 等方括号模式由精确匹配优先覆盖, 无需转 glob)"""
    if isinstance(value, str) and any(c in value for c in "*?"):
        return {"glob": value}
    return value


def migrate_rule(rule):
    """单条旧式规则 → 新 schema (不修改原 dict)"""
    out = {k: v for k, v in rule.items() if k not in ("condition", "exclude")}
    cond = rule.get("condition", {})
    out["event_type"] = rule.get("event_type") or cond.get("event_type")
    if not out["event_type"]:
        raise ValueError(f"规则 {rule.get('name')!r}: 缺少 event_type")

    nodes = [{k: v} for k, v in cond.items() if k != "event_type"]
    exc = rule.get("exclude")
    if exc:
        if not isinstance(exc, dict) or not exc:
            raise ValueError(f"规则 {rule.get('name')!r}: exclude 必须是非空 map")
        any_nodes = [
            {k: [_exclude_item(x) for x in v] if isinstance(v, list) else _exclude_item(v)}
            for k, v in exc.items()
        ]
        nodes.append({"not": {"any": any_nodes}})
    if not nodes:
        raise ValueError(f"规则 {rule.get('name')!r}: 迁移后 condition 为空 (规则将恒真)")

    out["condition"] = nodes[0] if len(nodes) == 1 else {"all": nodes}
    return out


def main():
    parser = argparse.ArgumentParser(description="迁移 rules.yaml 到 v0.4 schema")
    parser.add_argument("rules_file", nargs="?", default="config/rules.yaml")
    parser.add_argument("--out", help="输出文件 (默认: 备份后原地覆盖)")
    parser.add_argument("--no-backup", action="store_true", help="不备份原文件")
    args = parser.parse_args()

    path = Path(args.rules_file)
    data = yaml.safe_load(path.read_text())
    old_rules = data.get("rules", [])
    print(f"读取 {len(old_rules)} 条规则: {path}")

    migrated = []
    for rule in old_rules:
        try:
            migrated.append(migrate_rule(rule))
        except ValueError as e:
            print(f"❌ {e}", file=sys.stderr)
            sys.exit(1)

    errors = validate_rules(migrated)
    if errors:
        for i, msg in errors:
            print(f"❌ 第 {i} 条迁移后校验失败: {msg}", file=sys.stderr)
        sys.exit(1)

    dump = yaml.dump({"rules": migrated}, allow_unicode=True, sort_keys=False)
    if args.out:
        Path(args.out).write_text(dump)
        print(f"✅ 已写入 {args.out} ({len(migrated)} 条, schema 校验通过)")
    else:
        if not args.no_backup:
            backup = path.with_suffix(path.suffix + ".v03.bak")
            shutil.copy2(path, backup)
            print(f"原文件备份: {backup}")
        path.write_text(dump)
        print(f"✅ 已迁移 {path} ({len(migrated)} 条, schema 校验通过)")


if __name__ == "__main__":
    main()
