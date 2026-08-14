#!/usr/bin/env python3
"""BpfRuntime — BCC 兼容门面 (v0.4.1, CO-RE 迁移)

main.py / identity.py 原 BCC 用法:
  bpf = BPF(src_file=...)          →  BpfRuntime(obj_path)
  bpf['events'].event(data)        →  MapView.event(data)   (解析 ctypes 结构)
  bpf['events'].open_ring_buffer(cb) → MapView.open_ring_buffer(cb)
  bpf.ring_buffer_poll()           →  BpfRuntime.ring_buffer_poll()
  bpf['container_map'].Leaf        →  MapView.Leaf (ctypes 值类型)
  bpf['container_map'][key] = val  →  __setitem__
  bpf['container_map'].keys()/get()/del → 迭代/读/删

全部由 core.libbpf (ctypes 封装 libbpf.so.1) 实现, 零 BCC 依赖。
"""

import ctypes
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

from core.libbpf import (BpfObject, RingBuffer, LibbpfError,  # noqa: E402
                         bpf_xdp_attach, bpf_xdp_detach,
                         bpf_program__fd)


# ================================================================
# 事件结构 (与 src/ebpf/escape-detect.bpf.c 逐字节一致)
# ================================================================
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
        # v0.4.2: 尾部追加 (capset/openat 专用)
        ("cap_effective", ctypes.c_uint32),
        ("cap_permitted", ctypes.c_uint32),
        ("open_flags", ctypes.c_uint32),
    ]


class ContainerId(ctypes.Structure):
    _fields_ = [("id", ctypes.c_char * 64)]


class BlockIpKey(ctypes.Structure):
    _fields_ = [("ip", ctypes.c_uint32)]


class BlockIpPortKey(ctypes.Structure):
    _fields_ = [("ip", ctypes.c_uint32),
                ("port", ctypes.c_uint16),
                ("__pad", ctypes.c_uint16)]


_LEAF_TYPES = {
    "events": Event,
    "container_map": ContainerId,
    "block_ip_map": ctypes.c_uint32,
    "block_port_map": ctypes.c_uint32,
}

# 与 escape-detect.bpf.c 的 SEC 段一一对应
_TRACEPOINTS = [
    ("tracepoint__syscalls__sys_enter_mount", "syscalls", "sys_enter_mount"),
    ("tracepoint__syscalls__sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
    ("tracepoint__syscalls__sys_enter_execve", "syscalls", "sys_enter_execve"),
    ("tracepoint__syscalls__sys_enter_connect", "syscalls", "sys_enter_connect"),
    ("tracepoint__syscalls__sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("tracepoint__syscalls__sys_enter_capset", "syscalls", "sys_enter_capset"),
]


class MapView:
    """BCC 风格 map 访问 (key/value 均为 ctypes 对象)。"""

    def __init__(self, name, bpf_map, leaf_type):
        self._name = name
        self._map = bpf_map
        self._leaf_type = leaf_type
        self._ringbuf = None

    @property
    def Leaf(self):
        return self._leaf_type

    def __getitem__(self, key):
        value = self._leaf_type()
        if not self._map.lookup(key, value):
            raise KeyError(f"{self._name}[{key}] 不存在")
        return value

    def __setitem__(self, key, value):
        if not self._map.update(key, value):
            raise RuntimeError(f"{self._name}[{key}] 更新失败")

    def __delitem__(self, key):
        self._map.delete(key)

    def get(self, key):
        """BCC 兼容: 不存在返回 None"""
        value = self._leaf_type()
        return value if self._map.lookup(key, value) else None

    def keys(self):
        """BCC 兼容: container_map 的 key 类型固定 u32"""
        return self._map.keys(ctypes.c_uint32)

    def event(self, data):
        """解析 ringbuf 事件数据 (bytes 或指针) → Event 结构"""
        if isinstance(data, (bytes, bytearray)):
            buf = bytes(data)
        else:
            buf = ctypes.string_at(data, ctypes.sizeof(self._leaf_type))
        ev = self._leaf_type()
        ctypes.memmove(ctypes.byref(ev), buf, ctypes.sizeof(self._leaf_type))
        return ev

    def open_ring_buffer(self, callback):
        """BCC 兼容: callback(cpu, data, size) — data 传 bytes"""
        def _handler(raw):
            callback(0, raw, len(raw))
        self._ringbuf = RingBuffer(self._map.fd, _handler)

    def poll(self, timeout_ms=100):
        return self._ringbuf.poll(timeout_ms) if self._ringbuf else 0


class BpfRuntime:
    """加载 .bpf.o + attach tracepoints/maps/ringbuf/XDP 访问。"""

    def __init__(self, obj_path=None, auto_build=True, attach_tracepoints=True):
        obj_path = obj_path or str(ROOT / ".build" / "escape-detect.bpf.o")
        if auto_build and not Path(obj_path).exists():
            print("[BpfRuntime] .bpf.o 缺失, 执行 make build...")
            subprocess.run(["make", "build"], cwd=str(ROOT), check=True)
        self._obj_path = str(obj_path)
        self._obj = BpfObject(obj_path)
        if attach_tracepoints:
            for prog_name, cat, tp in _TRACEPOINTS:
                self._obj.attach_tracepoint(prog_name, cat, tp)
        self._views = {}
        self._xdp_iface = None
        # 预创建主探针对象 map view — ring_buffer_poll 回调中首次访问
        # 会触发 __getitem__ 修改 _views, 迭代时崩溃 (v0.4.2 修复)。
        # XDP 对象无 events/container_map, 缺失则跳过 (容错)。
        for name in ("events", "container_map"):
            try:
                self[name]
            except LibbpfError:
                pass

    def attach_xdp(self, iface, prog_name="xdp_block"):
        """attach XDP 程序到网卡 (bpftool, generic 模式 — 虚拟网卡只支持 skb 模式)。

        libbpf 1.8 的 bpf_xdp_attach 无 flags 参数, 只支持 native XDP,
        对 docker0 等 bridge 网卡必然失败; bpftool 的 net attach 自动
        走 generic。返回 True/False (失败不抛, 调用方回退 iptables)。
        """
        try:
            obj_path = self._obj_path
            pin = "/sys/fs/bpf/guard_xdp_block"
            subprocess.run(["bpftool", "prog", "load", obj_path, pin,
                            "type", "xdp"], check=True,
                           capture_output=True)
            subprocess.run(["bpftool", "net", "attach", "xdp", "pinned",
                            pin, "dev", iface], check=True,
                           capture_output=True)
            self._xdp_iface = (iface, pin)
            return True
        except Exception as e:
            print(f"  [!] XDP attach {iface} 失败: {e}", file=sys.stderr)
            return False

    def remove_xdp(self):
        """detach XDP 程序 (bpftool)"""
        if self._xdp_iface:
            iface, pin = self._xdp_iface
            subprocess.run(["bpftool", "net", "detach", "xdp", "dev", iface],
                           capture_output=True)
            subprocess.run(["rm", "-f", pin])
            self._xdp_iface = None

    def __getitem__(self, name):
        if name not in self._views:
            bpf_map = self._obj.map(name)
            leaf = _LEAF_TYPES.get(name)
            if leaf is None:
                raise LibbpfError(f"未知 map {name} (缺 Leaf 类型注册)")
            self._views[name] = MapView(name, bpf_map, leaf)
        return self._views[name]

    def ring_buffer_poll(self, timeout_ms=100):
        n = 0
        for view in list(self._views.values()):  # 快照防回调中新增 view
            n += view.poll(timeout_ms)
        return n

    def close(self):
        self.remove_xdp()
        for view in self._views.values():
            if view._ringbuf:
                view._ringbuf.close()
        self._views = {}
        self._obj.close()


def _ifindex(iface: str) -> int:
    """网卡名 → ifindex (SIOCGIFINDEX)"""
    import fcntl
    import socket
    import struct
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return struct.unpack(
            "i", fcntl.ioctl(sock.fileno(), 0x8933,  # SIOCGIFINDEX
                             struct.pack("256s", iface.encode()))[16:20])[0]
    finally:
        sock.close()
