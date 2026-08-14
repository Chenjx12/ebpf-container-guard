#!/bin/bash
# parity_check.sh — BCC vs CO-RE 双后端字段对照 (v0.4.1 M6)
# 需要 bcc 仍安装 (对照用); 迁移完成后可移除.
set -e
cd "$(dirname "$0")/../.."

# 从 v0.4.0 基线检出 BCC 版探针源码 (临时, gitignored)
BCC_FILE="tests/parity/.bcc_v040.c"
git show 8d64a5b:src/ebpf/escape-detect.bpf.c > "$BCC_FILE" 2>/dev/null || {
    echo "❌ git show 失败 — 需要 v0.4.0 提交 (8d64a5b)"; exit 1
}

echo "=== 双后端字段对照 (BCC vs CO-RE) ==="
sudo python3 tests/parity/parity_check.py
