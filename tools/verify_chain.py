#!/usr/bin/env python3
"""verify_chain.py — 校验行为日志哈希链完整性。

用法:
    python3 tools/verify_chain.py                       # 默认校验 logs/
    python3 tools/verify_chain.py logs/
    python3 tools/verify_chain.py logs/ --key /etc/ebpf-guard/chain.key
    python3 tools/verify_chain.py logs/ --quiet

校验内容（逐行）:
    1. 该行可解析为 JSON
    2. prev 等于上一条记录的 hash
    3. seq 等于上一条记录 + 1
    4. hash 等于 sha256(prev + body)（hmac 模式下为 HMAC-SHA256）

退出码: 0 = 通过, 1 = 发现完整性问题或格式错误。
"""

import argparse
import glob
import hashlib
import hmac
import json
import os
import re
import sys

LOG_NAME = "behaviors.log"
GENESIS = '0' * 64


def discover(log_dir):
    """返回按链顺序排列的文件列表：轮转文件按 (日期, 序号) 升序，活跃文件在最后。"""
    rotated = []
    for path in glob.glob(os.path.join(log_dir, LOG_NAME + ".*")):
        name = os.path.basename(path)
        m = re.match(r'^' + re.escape(LOG_NAME) + r'\.(\d{4}-\d{2}-\d{2})(?:\.(\d{3}))?$', name)
        if m:
            rotated.append(((m.group(1), int(m.group(2) or 0)), path))
    rotated.sort(key=lambda x: x[0])
    files = [p for _, p in rotated]
    live = os.path.join(log_dir, LOG_NAME)
    if os.path.exists(live) and os.path.getsize(live) > 0:
        files.append(live)
    return files


def body_of(record):
    """去掉 hash 字段后按文件中的键顺序重新序列化（与写入端完全一致）。"""
    record.pop('hash')
    return json.dumps(record, ensure_ascii=False, separators=(',', ':'))


def digest(prev_hex, body, key=None):
    payload = (prev_hex + body).encode('utf-8')
    if key:
        return hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def verify(files, key=None, quiet=False):
    expect_seq = None
    expect_hash = None
    total = 0
    reseed = True          # 期望值未知（链起点 / v1 文件之后），由下一条记录自举
    failures = []          # (文件, 行号, 类型, 说明)
    legacy = []
    frozen = False         # 首次失败后折叠后续细节

    for path in files:
        name = os.path.basename(path)
        count = 0
        bad_before = len(failures)

        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    failures.append((name, lineno, 'PARSE_ERROR', '该行不是合法 JSON'))
                    frozen = True
                    continue

                if 'seq' not in rec or 'hash' not in rec:
                    # v1 文件无链信息：记录并跳过，后续文件重新自举（链在此处断开）
                    legacy.append(name)
                    reseed = True
                    break

                count += 1
                total += 1

                if reseed:
                    expect_seq = rec['seq']
                    expect_hash = rec['prev']
                    if rec['prev'] != GENESIS and total == 1 and not quiet:
                        print(f"[NOTE] 链起点非创世值（prev={rec['prev'][:16]}…），"
                              f"可能是保留期清理后的续链")
                    reseed = False

                if frozen:
                    continue

                claimed = rec['hash']
                prev = rec.get('prev')
                seq = rec.get('seq')
                calc = digest(prev or '', body_of(dict(rec)), key)

                if seq != expect_seq:
                    failures.append((name, lineno, 'SEQ_GAP',
                                     f'期望 seq={expect_seq}，实际 {seq}（有记录缺失）'))
                    frozen = True
                elif prev != expect_hash:
                    failures.append((name, lineno, 'CHAIN_BROKEN',
                                     f'prev 与上一条 hash 不一致（上一条被修改或删除）'))
                    frozen = True
                elif calc != claimed:
                    failures.append((name, lineno, 'HASH_MISMATCH',
                                     f'内容被修改（期望 {claimed[:16]}…，实际 {calc[:16]}…）'))
                    frozen = True
                else:
                    expect_seq = seq + 1
                    expect_hash = claimed

        if count and len(failures) == bad_before and not quiet:
            print(f"[OK]   {name:<40s} {count:>8,d} 条")

    # ---------------- 报告 ----------------
    if failures:
        name, lineno, kind, desc = failures[0]
        print()
        print(f"[FAIL] {name}  第 {lineno} 行")
        print(f"       类型：{kind}")
        print(f"       说明：{desc}")
        if frozen and total > lineno:
            print(f"       后续记录链全部失效（{total - lineno} 条，自该行之后不再逐条比对）")
        if len(failures) > 1:
            print(f"       另有 {len(failures) - 1} 处异常已折叠")
        print("-" * 52)
        print(f"合计 {total:,d} 条，发现问题，验签未通过。")
        return 1

    if legacy:
        print(f"[SKIP] {len(legacy)} 个文件为 v1 格式（无哈希链），未参与校验："
              f"{', '.join(sorted(set(legacy)))}")
        if not total:
            print("-" * 52)
            print("未发现可校验的 v2 记录。")
            return 0

    if not quiet:
        print("-" * 52)
    print(f"合计 {total:,d} 条，链完整，验签通过。")
    return 0


def main():
    ap = argparse.ArgumentParser(description="校验行为日志哈希链完整性")
    ap.add_argument("log_dir", nargs="?", default="logs",
                    help="日志目录（默认 logs/）")
    ap.add_argument("--key", help="hmac 模式密钥文件路径")
    ap.add_argument("--quiet", action="store_true", help="只输出结论")
    args = ap.parse_args()

    if not os.path.isdir(args.log_dir):
        print(f"[FAIL] 目录不存在: {args.log_dir}", file=sys.stderr)
        return 1

    key = None
    if args.key:
        with open(args.key, 'rb') as f:
            key = f.read()

    files = discover(args.log_dir)
    if not files:
        print(f"[FAIL] {args.log_dir} 下没有找到 {LOG_NAME}", file=sys.stderr)
        return 1

    return verify(files, key=key, quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
