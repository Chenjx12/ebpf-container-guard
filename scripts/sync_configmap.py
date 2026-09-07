#!/usr/bin/env python3
"""sync_configmap.py — 同步 config/rules.yaml 到 deploy/k8s/configmap.yaml (v0.6.4, H3)

背景 (审查修复): ConfigMap 是 K8s 部署的规则源, 但权威源始终是
config/rules.yaml。审查发现 configmap 曾长期漂移 (内嵌 v0.4.0/10 rules,
reverse_shell 排除列表缺 v0.5.6 追加的集群组件) — 生产若按 configmap
部署会以过期规则告警, 造成漏报/误报回归。

用法:
  python scripts/sync_configmap.py           # 就地同步 rules 块
  python scripts/sync_configmap.py --check   # 漂移检测 (漂移则 exit 1)

只改动 data.rules.yaml 块 (行级 4 空格缩进替换),
不影响 responses.yaml / monitor.yaml / blocklist.yaml / ai_config.yaml 段。
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_SRC = ROOT / "config" / "rules.yaml"
CONFIGMAP = ROOT / "deploy" / "k8s" / "configmap.yaml"
MARKER = "  rules.yaml: |"


def split_rules_block(lines):
    """定位 rules.yaml 块。返回 (marker_idx, end_idx) — 块内容行 [marker+1, end)。"""
    for i, ln in enumerate(lines):
        if ln.rstrip() == MARKER:
            j = i + 1
            while j < len(lines):
                if lines[j].strip() == "":
                    j += 1
                    continue
                indent = len(lines[j]) - len(lines[j].lstrip(" "))
                if indent < 4:  # 下一个顶层/2 空格键 (如 "  responses.yaml: |")
                    break
                j += 1
            return i, j
    raise SystemExit(f"错误: {CONFIGMAP} 中未找到块标记 {MARKER!r}")


def render_block(rules_text):
    """config/rules.yaml → configmap 块内行 (统一 4 空格缩进, 空行无缩进)。"""
    out = []
    for ln in rules_text.splitlines():
        out.append("    " + ln if ln.strip() else "")
    while out and out[-1].strip() == "":  # 去块尾多余空行
        out.pop()
    return out


def normalize(line):
    """归一化后比较 (空行缩进差异不视为漂移)。"""
    return "" if line.strip() == "" else line


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="只做漂移检测, 不同步 (漂移则 exit 1)")
    args = ap.parse_args()

    rules_text = RULES_SRC.read_text(encoding="utf-8")
    cm_lines = CONFIGMAP.read_text(encoding="utf-8").splitlines()

    marker_idx, end_idx = split_rules_block(cm_lines)
    new_block = render_block(rules_text)
    old_block = cm_lines[marker_idx + 1:end_idx]

    # 归一化比较 (规则语义行必须一致, 空行缩进忽略)
    drifted = len(new_block) != len(old_block) or \
        any(normalize(a) != normalize(b)
            for a, b in zip(new_block, old_block))

    if not drifted:
        print(f"✅ 无漂移: {CONFIGMAP} rules.yaml 块与 {RULES_SRC} 一致")
        return 0

    print(f"⚠️ 漂移检出: {CONFIGMAP} rules.yaml 块落后于 {RULES_SRC}")
    if args.check:
        print(f"   修复: python {Path(__file__).name}")
        return 1

    out = cm_lines[:marker_idx + 1] + new_block + cm_lines[end_idx:]
    CONFIGMAP.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"✅ 已同步 {len(old_block)} 行 → {len(new_block)} 行到 {CONFIGMAP}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
