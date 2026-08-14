#!/usr/bin/env python3
"""
XDP network blocking backend (v0.3.9, v0.4.1 CO-RE).

eBPF XDP program drops blocked packets at the NIC driver level —
microsecond latency, pure kernel space. Compatible interface with
NetBlocker (iptables backend): block / unblock / list_blocks / cleanup.

Requires root; loads .build/xdp-block.bpf.o via BpfRuntime (libbpf CO-RE,
自研 ctypes 加载层) and attaches to the given interface (default: docker0).
"""

import ctypes as ct
import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional

from core.bpf_runtime import BpfRuntime, BlockIpKey, BlockIpPortKey
from core.netblock import ip_int_to_str

XDP_OBJ = Path(__file__).parent.parent.parent / ".build" / "xdp-block.bpf.o"


class CompositeNetBlocker:
    """Mixed backend (v0.3.9): XDP for inbound + iptables for outbound.

    XDP only sees ingress (packets entering an interface) — it blocks
    inbound attack traffic to containers. iptables FORWARD handles
    outbound forwarding (C2 / reverse shell). block() writes to both.
    """

    def __init__(self, xdp: "XDPNetBlocker", iptables):
        self.xdp = xdp
        self.iptables = iptables

    @property
    def enabled(self) -> bool:
        return self.xdp.enabled or True  # iptables always available

    def block(self, ip: str, port: int) -> bool:
        r1 = self.xdp.block(ip, port) if self.xdp.enabled else False
        r2 = self.iptables.block(ip, port)
        return r1 or r2

    def unblock(self, ip: str, port: int) -> bool:
        r1 = self.xdp.unblock(ip, port) if self.xdp.enabled else False
        r2 = self.iptables.unblock(ip, port)
        return r1 or r2

    def cleanup_expired(self) -> int:
        n1 = self.xdp.cleanup_expired() if self.xdp.enabled else 0
        n2 = self.iptables.cleanup_expired()
        return n1 + n2

    def is_blocked(self, ip: str, port: int) -> bool:
        return (self.xdp.is_blocked(ip, port) if self.xdp.enabled else False) \
            or self.iptables.is_blocked(ip, port)

    def list_blocks(self) -> list:
        return self.iptables.list_blocks()

    def list_iptables(self) -> list:
        return self.iptables.list_iptables()

    def detach(self):
        if self.xdp:
            self.xdp.detach()


class XDPNetBlocker:
    """XDP-based traffic blocking (kernel-level DROP)."""

    def __init__(self, iface: str = "docker0", ttl: int = 3600):
        self.iface = iface
        self.ttl = ttl
        self.blocked: Dict[str, float] = {}  # "ip:port" -> ts
        self.bpf: Optional[BpfRuntime] = None
        self._load()

    def _load(self):
        """Load CO-RE XDP program, attach to interface."""
        if not XDP_OBJ.exists():
            print(f"  [!] XDP object not found: {XDP_OBJ}", file=sys.stderr)
            self.bpf = None
            return
        try:
            self.bpf = BpfRuntime(str(XDP_OBJ), auto_build=False,
                                  attach_tracepoints=False)
            if not self.bpf.attach_xdp(self.iface, "xdp_block"):
                self.bpf.close()
                self.bpf = None
                return
            print(f"  [XDP] attached to {self.iface} "
                  f"(kernel-level packet blocking)")
        except Exception as e:
            print(f"  [!] XDP load failed ({e}) — "
                  f"falling back to iptables", file=sys.stderr)
            self.bpf = None

    @property
    def enabled(self) -> bool:
        return self.bpf is not None

    # -----------------------------------------------------------
    # Public API (compatible with NetBlocker)
    # -----------------------------------------------------------

    def block(self, ip: str, port: int) -> bool:
        """Block traffic to ip:port. Returns True if rule added."""
        if not self.enabled or port <= 0:
            return False
        key = f"{ip}:{port}"
        if key in self.blocked:
            return False

        ip_be = self._ip_to_be(ip)
        try:
            if port == 0:
                # 整 IP 阻断
                k = BlockIpKey(ip=ip_be)
                self.bpf["block_ip_map"][k] = ct.c_uint32(1)
            else:
                k = BlockIpPortKey(ip=ip_be, port=self._port_to_be(port))
                self.bpf["block_port_map"][k] = ct.c_uint32(1)
            self.blocked[key] = time.time()
            return True
        except Exception as e:
            print(f"  [!] XDP block failed ({ip}:{port}): {e}",
                  file=sys.stderr)
            return False

    def unblock(self, ip: str, port: int) -> bool:
        """Remove block rule for ip:port."""
        if not self.enabled:
            return False
        key = f"{ip}:{port}"
        ip_be = self._ip_to_be(ip)
        try:
            if port == 0:
                del self.bpf["block_ip_map"][BlockIpKey(ip=ip_be)]
            else:
                del self.bpf["block_port_map"][
                    BlockIpPortKey(ip=ip_be, port=self._port_to_be(port))]
            self.blocked.pop(key, None)
            return True
        except Exception:
            return False

    def cleanup_expired(self) -> int:
        """Remove expired block rules. Returns count removed."""
        removed = 0
        now = time.time()
        for key, ts in list(self.blocked.items()):
            if now - ts > self.ttl:
                ip, port = key.rsplit(':', 1)
                if self.unblock(ip, int(port)):
                    removed += 1
        return removed

    def is_blocked(self, ip: str, port: int) -> bool:
        return f"{ip}:{port}" in self.blocked

    def list_blocks(self) -> list:
        return [(k.rsplit(':', 1)[0], int(k.rsplit(':', 1)[1]), ts)
                for k, ts in self.blocked.items()]

    def list_iptables(self) -> list:
        """XDP backend has no iptables rules — return []."""
        return []

    def detach(self):
        """Detach XDP program from interface."""
        if self.bpf:
            try:
                self.bpf.remove_xdp()
                self.bpf.close()
            except Exception:
                pass

    # -----------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------

    @staticmethod
    def _ip_to_be(ip: str) -> int:
        """Dotted-quad → network-byte-order int (as stored in iphdr.daddr)."""
        parts = [int(x) for x in ip.split('.')]
        return ((parts[0] << 24) | (parts[1] << 16) |
                (parts[2] << 8) | parts[3]) & 0xFFFFFFFF

    @staticmethod
    def _port_to_be(port: int) -> int:
        """Host port → network byte order (as stored in tcp->dest)."""
        return ((port & 0xFF) << 8) | (port >> 8)
