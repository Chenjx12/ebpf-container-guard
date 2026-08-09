#!/usr/bin/env python3
"""
Network traffic blocking — iptables FORWARD chain DROP for malicious targets.

Reversible, fine-grained response: only the malicious destination is blocked,
business traffic to other destinations is unaffected. Rules expire via TTL.

Requires root (guard runs as root).
"""

import subprocess
import time
from typing import Dict, Tuple


class NetBlocker:
    """iptables-based traffic blocking for malicious IP:port targets."""

    # iptables rule for container traffic (goes through docker0/bridge FORWARD)
    RULE_TEMPLATE = "iptables -I FORWARD 1 -d {ip} -p tcp --dport {port} -j DROP"

    def __init__(self, ttl: int = 3600):
        """ttl: seconds before a block rule auto-expires (default 1h)."""
        self.ttl = ttl
        self.blocked: Dict[str, float] = {}  # "ip:port" -> block timestamp
        self._cleanup_runs = 0

    # -----------------------------------------------------------
    # Public API
    # -----------------------------------------------------------

    def block(self, ip: str, port: int) -> bool:
        """Block traffic to ip:port. Returns True if rule added."""
        if port <= 0:
            return False
        key = f"{ip}:{port}"
        if key in self.blocked:
            return False  # already blocked

        rule = self.RULE_TEMPLATE.format(ip=ip, port=port)
        try:
            subprocess.run(rule.split(), check=True,
                           capture_output=True, timeout=5)
            self.blocked[key] = time.time()
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"  [!] NetBlock failed ({rule}): {e}", file=sys.stderr)
            return False

    def unblock(self, ip: str, port: int) -> bool:
        """Remove block rule for ip:port. Returns True if removed."""
        key = f"{ip}:{port}"
        rule = self.RULE_TEMPLATE.format(ip=ip, port=port).replace(
            "-I FORWARD 1", "-D FORWARD")
        try:
            subprocess.run(rule.split(), check=True,
                           capture_output=True, timeout=5)
            self.blocked.pop(key, None)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
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
        """Current active blocks as [(ip, port, since_timestamp), ...]."""
        return [(k.rsplit(':', 1)[0], int(k.rsplit(':', 1)[1]), ts)
                for k, ts in self.blocked.items()]

    def list_iptables(self) -> list:
        """Query actual iptables FORWARD chain (for verification)."""
        try:
            out = subprocess.run(
                ["iptables", "-L", "FORWARD", "-n", "--line-numbers"],
                check=True, capture_output=True, timeout=5, text=True)
            return [l for l in out.stdout.split('\n') if 'DROP' in l]
        except Exception:
            return []


def ip_int_to_str(ip_int: int) -> str:
    """Convert u32 daddr from eBPF event to dotted-quad string."""
    return (f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}."
            f"{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}")
