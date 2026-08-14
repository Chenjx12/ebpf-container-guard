#!/usr/bin/env python3
"""bpf_smoke.py — CO-RE 加载层独立冒烟 (v0.4.1 M2)

不碰主管线: 加载 .bpf.o → attach 5 个 tracepoint → 触发事件 →
ringbuf poll → 解析 struct event → 打印原始字段。
验证: libbpf.py ctypes 封装 ABI + args[N] 下标映射 + ringbuf reserve/submit。

用法: sudo python3 tools/bpf_smoke.py
"""
import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from core.libbpf import BpfObject, RingBuffer, LibbpfError  # noqa: E402


# 与 src/ebpf/escape-detect.bpf.c 的 struct event 逐字节一致
class Event(ctypes.Structure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("cgroup_id", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("container_id", ctypes.c_char * 64),
        ("target_path", ctypes.c_char * 256),
        ("fstype", ctypes.c_char * 32),
        ("target_pid", ctypes.c_uint32),
        ("request_raw", ctypes.c_uint64),
        ("daddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
    ]


TYPE_NAMES = {1: "mount", 2: "ptrace", 3: "openat", 4: "execve", 5: "connect"}


def main():
    obj_path = ROOT / ".build" / "escape-detect.bpf.o"
    if not obj_path.exists():
        print("❌ 缺少 .build/escape-detect.bpf.o — 先 make build")
        sys.exit(1)

    print(f"加载 {obj_path}")
    obj = BpfObject(str(obj_path))

    traces = [
        ("tracepoint__syscalls__sys_enter_mount", "syscalls", "sys_enter_mount"),
        ("tracepoint__syscalls__sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
        ("tracepoint__syscalls__sys_enter_execve", "syscalls", "sys_enter_execve"),
        ("tracepoint__syscalls__sys_enter_connect", "syscalls", "sys_enter_connect"),
        ("tracepoint__syscalls__sys_enter_openat", "syscalls", "sys_enter_openat"),
    ]
    for prog_name, cat, tp in traces:
        obj.attach_tracepoint(prog_name, cat, tp)
        print(f"  ✅ attach {cat}/{tp}")

    events_map = obj.map("events")
    print(f"  ✅ events map fd={events_map.fd} max_entries={events_map.max_entries}")

    seen = []
    rb = RingBuffer(events_map.fd, lambda data: seen.append(data))

    # ---- 触发事件 ----
    time.sleep(0.5)
    # openat: 读 /etc/passwd (命中敏感路径过滤)
    subprocess.run(["python3", "-c", "open('/etc/passwd').read(10)"],
                   capture_output=True)
    # execve: 执行 /bin/ls
    subprocess.run(["/bin/ls", "/tmp"], capture_output=True)
    # mount: 挂载 tmpfs
    mnt = "/mnt/smoke_mnt"
    os.makedirs(mnt, exist_ok=True)
    subprocess.run(["mount", "-t", "tmpfs", "tmpfs", mnt], capture_output=True)
    time.sleep(0.3)
    subprocess.run(["umount", mnt], capture_output=True)
    # connect: 连本机端口
    subprocess.run(["python3", "-c",
                    "import socket; s=socket.socket(); "
                    "s.settimeout(0.2); "
                    "s.connect(('127.0.0.1', 1))"],
                   capture_output=True)

    # ---- poll 消费 ----
    n = rb.poll(500)
    print(f"\nring_buffer__poll 返回 {n} 批事件, 共收到 {len(seen)} 条")

    got = set()
    for data in seen:
        if len(data) < ctypes.sizeof(Event):
            print("  ⚠️ 短事件:", len(data))
            continue
        ev = Event()
        ctypes.memmove(ctypes.byref(ev), data, ctypes.sizeof(Event))
        tname = TYPE_NAMES.get(ev.event_type, f"type{ev.event_type}")
        got.add(ev.event_type)
        path = ev.target_path.decode(errors="replace").rstrip("\x00")[:40]
        fstype = ev.fstype.decode(errors="replace").rstrip("\x00")[:16]
        print(f"  [{tname}] pid={ev.pid} comm={ev.comm.decode(errors='replace').rstrip(chr(0))} "
              f"container={ev.container_id.decode(errors='replace').rstrip(chr(0))} "
              f"path={path!r} fstype={fstype!r} target_pid={ev.target_pid} "
              f"dport={ev.dport}")

    ok = got == {1, 3, 4, 5}  # mount/openat/execve/connect
    print("\n✅ 冒烟通过 (mount+openat+execve+connect 事件齐全)" if ok
          else f"\n❌ 冒烟失败: 收到类型 {sorted(got)}, 缺 {sorted({1,3,4,5}-got)}")
    obj.close()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
