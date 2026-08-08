#!/usr/bin/env python3
"""
Container identity resolution — PID map, cgroup map, background refresh.

3-tier fallback for container ID resolution:
  Tier 1 — BPF PID→container_id map (kernel-space lookup)
  Tier 2 — cgroup inode→container_id map (userspace cache, race-free)
  Tier 3 — /proc/<pid>/cgroup filesystem fallback
"""

import os
import sys
import ctypes as ct
import threading

import docker


class ContainerIdentity:
    """Resolves process identity to Docker container ID.

    Maintains two maps synchronized via background thread:
      - BPF container_map: PID → container_short_id (kernel-space)
      - cgroup_map: cgroup_inode → container_short_id (userspace cache)
    """

    def __init__(self, bpf, docker_client=None):
        self.bpf = bpf
        self.docker_client = docker_client or docker.from_env()
        self.cgroup_map = {}

        self._stop_refresh = threading.Event()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, daemon=True)

    def start(self):
        """Start background map refresh thread."""
        self._refresh_all()
        self._refresh_thread.start()

    def stop(self):
        """Stop background refresh thread."""
        self._stop_refresh.set()

    def resolve(self, pid: int, cgroup_id: int, bpf_tag: str) -> str:
        """Resolve container ID with 3-tier fallback.

        Args:
            pid: Process PID (host namespace).
            cgroup_id: Cgroup inode captured atomically in kernel space.
            bpf_tag: container_id field from eBPF event struct.

        Returns:
            Container short ID (12 chars), or 'host'.
        """
        if bpf_tag not in ('host', '', 'unknown'):
            return bpf_tag

        # Tier 1: cgroup inode map (race-free)
        if cgroup_id in self.cgroup_map:
            return self.cgroup_map[cgroup_id]

        # Tier 2: /proc/<pid>/cgroup
        if pid > 0:
            return self._resolve_via_proc(pid)

        return 'host'

    # -----------------------------------------------------------
    # Internal: map management
    # -----------------------------------------------------------

    def _refresh_all(self):
        """Refresh both BPF PID map and userspace cgroup map."""
        self.cgroup_map = getattr(self, 'cgroup_map', {})
        self._build_cgroup_map()
        self._update_pid_map()

    def _refresh_loop(self):
        """Background thread: periodically refresh both maps."""
        while not self._stop_refresh.is_set():
            self._stop_refresh.wait(timeout=5)
            if not self._stop_refresh.is_set():
                self._refresh_all()

    def _update_pid_map(self):
        """Populate BPF container_map: pid → container_short_id."""
        try:
            containers = self.docker_client.containers.list()
            mapped = 0
            for c in containers:
                try:
                    top_result = c.top()
                except Exception:
                    continue
                for process in top_result['Processes']:
                    pid_str = process[1].strip()
                    if not pid_str.isdigit():
                        continue
                    pid = int(pid_str)
                    cid = c.id[:12]

                    ContainerId = self.bpf['container_map'].Leaf
                    entry = ContainerId()
                    entry.id = cid.encode('utf-8')
                    self.bpf['container_map'][ct.c_uint32(pid)] = entry
                    mapped += 1
            print(f"  [Map] PID map: {mapped} processes "
                  f"across {len(containers)} containers")
        except Exception as e:
            print(f"  [!] PID map update failed: {e}", file=sys.stderr)

    def _build_cgroup_map(self):
        """Build cgroup_inode → container_short_id mapping."""
        self.cgroup_map = {}
        try:
            for c in self.docker_client.containers.list():
                cgroup_path = (
                    f"/sys/fs/cgroup/system.slice/docker-{c.id}.scope"
                )
                if os.path.exists(cgroup_path):
                    inode = os.stat(cgroup_path).st_ino
                    self.cgroup_map[inode] = c.id[:12]
        except Exception as e:
            print(f"  [!] cgroup map build failed: {e}", file=sys.stderr)

    @staticmethod
    def _resolve_via_proc(pid: int) -> str:
        """Last-resort: read /proc/<pid>/cgroup."""
        try:
            with open(f"/proc/{pid}/cgroup", 'r') as f:
                for line in f:
                    if 'docker-' in line and '.scope' in line:
                        start = line.index('docker-') + 7
                        end = line.index('.scope', start)
                        return line[start:end][:12]
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        return 'host'
