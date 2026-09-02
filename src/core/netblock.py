#!/usr/bin/env python3
"""
Network traffic blocking — iptables FORWARD chain DROP for malicious targets.

Reversible, fine-grained response: only the malicious destination is blocked,
business traffic to other destinations is unaffected. Rules expire via TTL.

Requires root (guard runs as root).
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Tuple


class NetBlocker:
    """iptables-based traffic blocking for malicious IP:port targets."""

    # iptables rule for container traffic (goes through docker0/bridge FORWARD)
    RULE_TEMPLATE = "iptables -I FORWARD 1 -d {ip} -p tcp --dport {port} -j DROP"

    def __init__(self, ttl: int = 3600, persist_path=None):
        """ttl: seconds before a block rule auto-expires (default 1h).
        persist_path (v0.6.3): 阻断规则快照文件 (JSON); block/unblock 同步落盘,
        replay() 在 guard 启动时重放 iptables FORWARD DROP (重启恢复)。"""
        self.ttl = ttl
        self.blocked: Dict[str, float] = {}  # "ip:port" -> block timestamp
        self._persist_path = Path(persist_path) if persist_path else None
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
            self._persist()
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                OSError) as e:
            # OSError(FileNotFoundError): 镜像缺 iptables — v0.6.3 起 Dockerfile
            # 已安装; 此处兜底: 不炸事件管线, 告警照常落日志 (网络阻断降级为
            # 仅记录, 见 v0.6.3 已知限制)
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
            self._persist()
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                OSError):
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

    # -----------------------------------------------------------
    # v0.6.3 (ADR-050 顺风车): 阻断规则持久化 + 重启重放
    # -----------------------------------------------------------

    def _persist(self):
        """原子快照 blocked 表到 persist_path (JSON, tmp+rename)。"""
        if not self._persist_path:
            return
        import json as _json
        import tempfile as _tmp
        payload = {"version": 1, "blocks": self.blocked}
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = _tmp.mkstemp(dir=str(self._persist_path.parent),
                                   prefix="netblock-", suffix=".tmp")
            try:
                with os.fdopen(fd, 'w') as f:
                    _json.dump(payload, f)
                os.replace(tmp, self._persist_path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError as e:
            print(f"  [!] NetBlock 快照失败: {e}", file=sys.stderr)

    def load_persisted(self) -> int:
        """从快照恢复 blocked 表 (不重放规则)。返回恢复条数。"""
        if not self._persist_path or not self._persist_path.exists():
            return 0
        import json as _json
        try:
            with open(self._persist_path, 'r') as f:
                data = _json.load(f)
            blocks = data.get('blocks', {}) if isinstance(data, dict) else {}
            self.blocked = {k: float(v) for k, v in blocks.items()}
            print(f"  [NetBlock] 快照已恢复: {len(self.blocked)} 条阻断规则 "
                  f"({self._persist_path})")
            return len(self.blocked)
        except (OSError, ValueError, TypeError) as e:
            print(f"  [!] NetBlock 快照读取失败: {e}", file=sys.stderr)
            return 0

    def replay(self) -> int:
        """启动重放: 快照 → blocked 表 + iptables FORWARD DROP 重建。
        返回重放成功条数。XDP 层不在镜像内 (bpftool 缺失, 已知限制),
        重放覆盖实际生效的 iptables 层。"""
        count = self.load_persisted()
        ok = 0
        for key, ts in list(self.blocked.items()):
            try:
                ip, port = key.rsplit(':', 1)
                port_num = int(port)
                if port_num <= 0:
                    continue
                rule = ("iptables -I FORWARD 1 -d {ip} -p tcp "
                        "--dport {port} -j DROP").format(ip=ip, port=port_num)
                check = ("iptables -C FORWARD -d {ip} -p tcp "
                         "--dport {port} -j DROP").format(ip=ip, port=port_num)
                if subprocess.run(check.split(), capture_output=True,
                                  timeout=5).returncode == 0:
                    print(f"  [NetBlock] ⟳ DROP {ip}:{port_num} 已存在, 跳过 "
                          f"(快照 {time.strftime('%m-%d %H:%M', time.localtime(ts))})")
                    ok += 1
                    continue
                subprocess.run(rule.split(), check=True,
                               capture_output=True, timeout=5)
                ok += 1
                print(f"  [NetBlock] ⏪ 重放 DROP {ip}:{port_num} "
                      f"(快照 {time.strftime('%m-%d %H:%M', time.localtime(ts))})")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                ValueError, OSError) as e:
                print(f"  [!] NetBlock 重放失败 ({key}): {e}", file=sys.stderr)
        if count:
            print(f"  [NetBlock] 重启恢复: {ok}/{count} 条重放成功")
        return ok


def ip_int_to_str(ip_int: int) -> str:
    """Convert u32 daddr from eBPF event to dotted-quad string."""
    return (f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}."
            f"{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}")
