#!/usr/bin/env python3
"""libbpf ctypes 封装 (v0.4.1, CO-RE 迁移)

自研加载层: 直接封装 libbpf.so.1 (本机 1.8.0) 的 19 个导出 API。
覆盖: 对象加载 / tracepoint attach / map 操作 / ringbuf 消费 / XDP attach。

设计要点:
- 全部函数设置 argtypes/restypes, 防 ABI 错 (ctypes 默认 64 位指针会截断)
- map 操作走底层 fd 版 API (bpf_map_lookup_elem 等, libbpf.so 导出;
  bpf_map__lookup_elem 等封装函数是 header 内 static inline, 无导出符号)
- 版本化符号 (@@LIBBPF_0.x) ctypes 自动解析, 无需特殊处理
"""

import ctypes

# libbpf.so.1 = 1.8.0 (/usr/lib64); libbpf.so.0 = 0.5.0 (系统老版, 勿用)
_lib = ctypes.CDLL("libbpf.so.1", use_errno=True)

# ================================================================
# 对象加载
# ================================================================
bpf_object__open_file = _lib.bpf_object__open_file
bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
bpf_object__open_file.restype = ctypes.c_void_p

bpf_object__load = _lib.bpf_object__load
bpf_object__load.argtypes = [ctypes.c_void_p]
bpf_object__load.restype = ctypes.c_int

bpf_object__close = _lib.bpf_object__close
bpf_object__close.argtypes = [ctypes.c_void_p]
bpf_object__close.restype = None

bpf_object__find_program_by_name = _lib.bpf_object__find_program_by_name
bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
bpf_object__find_program_by_name.restype = ctypes.c_void_p

bpf_object__find_map_by_name = _lib.bpf_object__find_map_by_name
bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
bpf_object__find_map_by_name.restype = ctypes.c_void_p

bpf_program__fd = _lib.bpf_program__fd
bpf_program__fd.argtypes = [ctypes.c_void_p]
bpf_program__fd.restype = ctypes.c_int

# ================================================================
# Tracepoint attach
# ================================================================
bpf_program__attach_tracepoint = _lib.bpf_program__attach_tracepoint
bpf_program__attach_tracepoint.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
bpf_program__attach_tracepoint.restype = ctypes.c_void_p

bpf_link__destroy = _lib.bpf_link__destroy
bpf_link__destroy.argtypes = [ctypes.c_void_p]
bpf_link__destroy.restype = ctypes.c_int

# ================================================================
# Map (fd 版)
# ================================================================
bpf_map__fd = _lib.bpf_map__fd
bpf_map__fd.argtypes = [ctypes.c_void_p]
bpf_map__fd.restype = ctypes.c_int

bpf_map__max_entries = _lib.bpf_map__max_entries
bpf_map__max_entries.argtypes = [ctypes.c_void_p]
bpf_map__max_entries.restype = ctypes.c_uint

bpf_map_lookup_elem = _lib.bpf_map_lookup_elem
bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                ctypes.c_void_p, ctypes.c_uint64]
bpf_map_lookup_elem.restype = ctypes.c_int

bpf_map_update_elem = _lib.bpf_map_update_elem
bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                ctypes.c_void_p, ctypes.c_uint64]
bpf_map_update_elem.restype = ctypes.c_int

bpf_map_delete_elem = _lib.bpf_map_delete_elem
bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
bpf_map_delete_elem.restype = ctypes.c_int

bpf_map_get_next_key = _lib.bpf_map_get_next_key
bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                 ctypes.c_void_p]
bpf_map_get_next_key.restype = ctypes.c_int

# ================================================================
# Ring buffer
# ================================================================
# sample_cb(void *ctx, void *data, size_t size) -> int
RingBufCallback = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64)

ring_buffer__new = _lib.ring_buffer__new
ring_buffer__new.argtypes = [ctypes.c_int, RingBufCallback,
                             ctypes.c_void_p, ctypes.c_void_p]
ring_buffer__new.restype = ctypes.c_void_p

ring_buffer__poll = _lib.ring_buffer__poll
ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
ring_buffer__poll.restype = ctypes.c_int

ring_buffer__free = _lib.ring_buffer__free
ring_buffer__free.argtypes = [ctypes.c_void_p]
ring_buffer__free.restype = None

# ================================================================
# XDP
# ================================================================
bpf_xdp_attach = _lib.bpf_xdp_attach
bpf_xdp_attach.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
bpf_xdp_attach.restype = ctypes.c_int

bpf_xdp_detach = _lib.bpf_xdp_detach
bpf_xdp_detach.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p]
bpf_xdp_detach.restype = ctypes.c_int

# ================================================================
# 高层封装
# ================================================================
class LibbpfError(Exception):
    pass


class BpfObject:
    """CO-RE 对象: 打开 → 加载 → attach/prog/map 访问。"""

    def __init__(self, obj_path):
        self.obj = None
        self.links = []
        path = obj_path.encode()
        self.obj = bpf_object__open_file(path, None)
        if not self.obj:
            raise LibbpfError(
                f"bpf_object__open_file({obj_path}) 失败: "
                f"errno={ctypes.get_errno()}")
        if bpf_object__load(self.obj) != 0:
            errno = ctypes.get_errno()
            bpf_object__close(self.obj)
            self.obj = None
            raise LibbpfError(f"bpf_object__load 失败: errno={errno}")

    def program(self, name):
        prog = bpf_object__find_program_by_name(self.obj, name.encode())
        if not prog:
            raise LibbpfError(f"找不到程序 {name}")
        return prog

    def attach_tracepoint(self, name, category, tp_name):
        """attach 并持有 link; 返回 prog fd"""
        prog = self.program(name)
        link = bpf_program__attach_tracepoint(
            prog, category.encode(), tp_name.encode())
        if not link:
            raise LibbpfError(f"attach {category}/{tp_name} 失败: "
                              f"errno={ctypes.get_errno()}")
        self.links.append(link)
        return bpf_program__fd(prog)

    def map(self, name):
        m = bpf_object__find_map_by_name(self.obj, name.encode())
        if not m:
            raise LibbpfError(f"找不到 map {name}")
        return BpfMap(m)

    def close(self):
        for link in self.links:
            bpf_link__destroy(link)
        self.links = []
        if self.obj:
            bpf_object__close(self.obj)
            self.obj = None

    def __del__(self):
        self.close()


class BpfMap:
    """map 操作封装 (fd 版)。key/value 由调用方传 ctypes 对象, 用 byref() 传入。"""

    def __init__(self, bpf_map):
        self.bpf_map = bpf_map
        self.fd = bpf_map__fd(bpf_map)
        self.max_entries = bpf_map__max_entries(bpf_map)

    def lookup(self, key, value):
        """key/value 为 ctypes 对象; 命中返回 True (value 被填充)"""
        return (bpf_map_lookup_elem(self.fd, ctypes.byref(key),
                                    ctypes.byref(value), 0) == 0)

    def update(self, key, value, flags=0):
        return bpf_map_update_elem(self.fd, ctypes.byref(key),
                                   ctypes.byref(value), flags) == 0

    def delete(self, key):
        return bpf_map_delete_elem(self.fd, ctypes.byref(key)) == 0

    def first_key(self, key_type):
        k = key_type()
        if bpf_map_get_next_key(self.fd, None, ctypes.byref(k)) != 0:
            return None
        return k

    def next_key(self, key, key_type):
        k = key_type()
        if bpf_map_get_next_key(self.fd, ctypes.byref(key),
                                ctypes.byref(k)) != 0:
            return None
        return k

    def keys(self, key_type):
        keys = []
        k = self.first_key(key_type)
        while k is not None:
            keys.append(k)
            k = self.next_key(k, key_type)
        return keys


class RingBuffer:
    """ringbuf 消费封装。回调注册表防 CFUNCTYPE 被 GC。"""

    _callbacks = []

    def __init__(self, map_fd, handler):
        """handler(data: bytes) 在 sample 回调中调用 (BCC 兼容签名)"""
        def _cb(ctx, data, size):
            buf = ctypes.string_at(data, size)
            handler(buf)
            return 0
        self._cb = RingBufCallback(_cb)
        RingBuffer._callbacks.append(self._cb)
        self.rb = ring_buffer__new(map_fd, self._cb, None, None)
        if not self.rb:
            raise LibbpfError(f"ring_buffer__new 失败: "
                              f"errno={ctypes.get_errno()}")

    def poll(self, timeout_ms=100):
        """返回消费的事件数 (>=0); <0 为错误"""
        return ring_buffer__poll(self.rb, timeout_ms)

    def close(self):
        if self.rb:
            ring_buffer__free(self.rb)
            self.rb = None
