#!/usr/bin/env python3
"""parity_check.py — BCC vs CO-RE 双后端字段对照 (v0.4.1 M6)

同一触发动作同时喂给 BCC 版与 CO-RE 版探针 (同 pid 同事件),
逐字段对比事件数据 — E2E 兜不住 dport/daddr 错位这类字段级 bug。

用法: sudo python3 tests/parity/parity_check.py
"""
import ctypes
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from core.bpf_runtime import Event as CoreEvent  # noqa: E402

BCC_C_FILE = str(ROOT / "tests" / "parity" / ".bcc_v040.c")

TYPE_NAMES = {1: "mount", 2: "ptrace", 3: "openat", 4: "execve", 5: "connect"}

# 参与对比的字段 (排除 pid/uid/cgroup_id — 触发进程相同则 pid 相同, 但为稳妥仍对比)
COMPARE_FIELDS = ["event_type", "pid", "uid", "comm", "container_id",
                  "target_path", "fstype", "target_pid", "request_raw",
                  "daddr", "dport"]


def parse_bcc_event(data):
    """BCC 事件解析 (直接按 struct 布局 memcpy)"""
    ev = CoreEvent()
    ctypes.memmove(ctypes.byref(ev), data, ctypes.sizeof(CoreEvent))
    return ev


def event_to_dict(ev, strip=True):
    d = {}
    for f in COMPARE_FIELDS:
        v = getattr(ev, f)
        if isinstance(v, bytes):
            v = v.decode(errors="replace").rstrip("\x00") if strip else v
        d[f] = v
    return d


def main():
    if not Path(BCC_C_FILE).exists():
        print(f"❌ 缺少 BCC 版源码 {BCC_C_FILE} — "
              f"先执行: git show 8d64a5b:src/ebpf/escape-detect.bpf.c > {BCC_C_FILE}")
        sys.exit(1)

    from bcc import BPF  # 延迟导入 (parity 只在 BCC 存在时跑)

    bcc = BPF(src_file=BCC_C_FILE)
    core = None
    from core.libbpf import BpfObject, RingBuffer, bpf_program__fd
    from core.libbpf import bpf_object__find_map_by_name

    core_obj = BpfObject(str(ROOT / ".build" / "escape-detect.bpf.o"))
    traces = [
        ("tracepoint__syscalls__sys_enter_mount", "syscalls", "sys_enter_mount"),
        ("tracepoint__syscalls__sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
        ("tracepoint__syscalls__sys_enter_execve", "syscalls", "sys_enter_execve"),
        ("tracepoint__syscalls__sys_enter_connect", "syscalls", "sys_enter_connect"),
        ("tracepoint__syscalls__sys_enter_openat", "syscalls", "sys_enter_openat"),
    ]
    for prog_name, cat, tp in traces:
        core_obj.attach_tracepoint(prog_name, cat, tp)
    core_map = core_obj.map("events")

    bcc_events, core_events = [], []
    bcc["events"].open_ring_buffer(
        lambda cpu, data, size: bcc_events.append(data))
    rb = RingBuffer(core_map.fd, lambda raw: core_events.append(raw))

    time.sleep(0.5)

    # ---- 统一触发动作 ----
    mnt = "/mnt/parity_mnt"
    os.makedirs(mnt, exist_ok=True)
    subprocess.run(["mount", "-t", "tmpfs", "tmpfs", mnt], capture_output=True)
    subprocess.run(["python3", "-c", "open('/etc/passwd').read(10)"],
                   capture_output=True)          # openat
    subprocess.run(["/bin/ls", "/tmp"], capture_output=True)   # execve
    subprocess.run(["python3", "-c",
                    "import socket; s=socket.socket(); s.settimeout(0.2); "
                    "s.connect(('127.0.0.1', 9))"], capture_output=True)  # connect
    subprocess.run(["python3", "-c",
                    "import os; os.ptrace(0, 0, 0, 0)"],
                   capture_output=True)          # ptrace (可能失败, 事件仍产生)
    time.sleep(0.3)
    subprocess.run(["umount", mnt], capture_output=True)

    bcc.ring_buffer_poll()  # BCC 的 poll 在 BPF 对象上
    rb.poll(500)
    time.sleep(0.3)

    bcc_dicts = [event_to_dict(parse_bcc_event(d)) for d in bcc_events]
    core_dicts = [event_to_dict(CoreEvent.from_buffer_copy(d))
                  if len(d) >= ctypes.sizeof(CoreEvent) else None
                  for d in core_events]
    core_dicts = [d for d in core_dicts if d]

    # ---- 按 (pid, event_type) 配对 ----
    def index(ds):
        idx = {}
        for d in ds:
            idx.setdefault((d["pid"], d["event_type"]), []).append(d)
        return idx

    bi, ci = index(bcc_dicts), index(core_dicts)
    pairs = set(bi) & set(ci)
    if not pairs:
        print(f"❌ 无配对事件 (BCC {len(bcc_dicts)}, CO-RE {len(core_dicts)})")
        sys.exit(1)

    mismatches = []
    checked = 0
    for key in sorted(pairs, key=str):
        b_list, c_list = bi[key], ci[key]
        for bd, cd in zip(b_list, c_list):
            checked += 1
            diffs = {f: (bd[f], cd[f]) for f in COMPARE_FIELDS
                     if bd[f] != cd[f]}
            if diffs:
                mismatches.append((key, TYPE_NAMES.get(key[1]), diffs))

    print(f"配对 {len(pairs)} 组, 对比 {checked} 条事件 (BCC {len(bcc_dicts)} "
          f"/ CO-RE {len(core_dicts)})")
    for key, tname, diffs in mismatches[:10]:
        print(f"  ❌ [{tname}] pid={key[0]}: {diffs}")

    core_obj.close()
    if mismatches:
        print(f"❌ 字段不一致 {len(mismatches)} 处")
        sys.exit(1)
    print("✅ 双后端字段一致 (parity OK)")
    sys.exit(0)


if __name__ == "__main__":
    main()
