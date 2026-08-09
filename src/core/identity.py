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

    Dual-channel map synchronization:
      - Event-driven (primary): Docker events (start/die) → instant update
      - Polling (fallback): 5s full scan, catches missed events / reconnects
    """

    def __init__(self, bpf, docker_client=None):
        self.bpf = bpf
        self.docker_client = docker_client or docker.from_env()
        self.cgroup_map = {}          # inode -> (short_id, name)
        self._id_to_name = {}         # short_id -> container name
        self._id_to_image = {}        # short_id -> image tag

        self._stop_refresh = threading.Event()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, daemon=True)
        self._events_thread = threading.Thread(
            target=self._events_loop, daemon=True)

    def start(self):
        """Start both refresh channels."""
        self._refresh_all()
        self._refresh_thread.start()
        self._events_thread.start()

    def stop(self):
        """Stop both refresh channels."""
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
            return self.cgroup_map[cgroup_id][0]

        # Tier 2: /proc/<pid>/cgroup
        if pid > 0:
            return self._resolve_via_proc(pid)

        return 'host'

    def get_name(self, container_id: str) -> str:
        """Look up container name by short ID ('' if unknown).

        Cold path: if the background refresh hasn't seen this container yet
        (e.g. just started), query Docker directly and cache. The container
        ID set is bounded, so this runs at most once per container.
        """
        if not container_id or container_id in ('host', 'unknown'):
            return ''
        name = self._id_to_name.get(container_id)
        if name:
            return name
        try:
            c = self.docker_client.containers.get(container_id)
            name = c.name
            self._id_to_name[container_id] = name
            return name
        except Exception:
            return ''

    def get_image(self, container_id: str) -> str:
        """Look up container image by short ID ('' if unknown).

        Same cold-path pattern as get_name: cache hit → return; miss →
        query Docker directly and cache. Bounded by container ID set.
        """
        if not container_id or container_id in ('host', 'unknown'):
            return ''
        image = self._id_to_image.get(container_id) \
            if hasattr(self, '_id_to_image') else None
        if image:
            return image
        try:
            c = self.docker_client.containers.get(container_id)
            image = c.image.tags[0] if c.image.tags else \
                (c.image.short_id or 'unknown')
            if not hasattr(self, '_id_to_image'):
                self._id_to_image = {}
            self._id_to_image[container_id] = image
            return image
        except Exception:
            return ''

    # -----------------------------------------------------------
    # Internal: map management
    # -----------------------------------------------------------

    def _refresh_all(self):
        """Refresh both BPF PID map and userspace cgroup map."""
        self.cgroup_map = getattr(self, 'cgroup_map', {})
        self._build_cgroup_map()
        self._update_pid_map()

    def _refresh_loop(self):
        """Fallback channel: periodically refresh both maps (every 5s).

        Catches containers missed by the event stream (e.g. containers
        running before guard started, or dropped events during reconnect).
        """
        while not self._stop_refresh.is_set():
            self._stop_refresh.wait(timeout=5)
            if not self._stop_refresh.is_set():
                self._refresh_all()

    def _events_loop(self):
        """Primary channel: listen to Docker events for instant map updates.

        Container start/die events update the maps in real-time, eliminating
        the cold-path window between container creation and the next poll.
        """
        while not self._stop_refresh.is_set():
            try:
                for event in self.docker_client.events(decode=True):
                    if self._stop_refresh.is_set():
                        return
                    self._handle_docker_event(event)
            except Exception as e:
                # Event stream broken → back off, then reconnect
                print(f"  [!] Docker event stream error: {e}, "
                      f"reconnecting in 2s", file=sys.stderr)
                self._stop_refresh.wait(2)

    # -----------------------------------------------------------
    # Docker event handlers
    # -----------------------------------------------------------

    def _handle_docker_event(self, event):
        """Route a Docker event to the appropriate map update."""
        if event.get('Type') != 'container':
            return
        # docker-py compatibility: 'status' (newer) vs 'Action' (older)
        status = event.get('status') or event.get('Action')
        if not status:
            return
        actor = event.get('Actor', {})
        cid = actor.get('ID', '')
        attrs = actor.get('Attributes', {})
        name = attrs.get('name', '')

        if status in ('start', 'restart'):
            self._on_container_start(cid, name)
        elif status in ('die', 'destroy', 'stop'):
            self._on_container_stop(cid, name)

    def _on_container_start(self, cid, name):
        """Container started — add to cgroup map + name index + BPF PID map.

        The cgroup directory may not exist immediately after start,
        so retry briefly; the polling thread catches anything missed.
        """
        short_id = cid[:12]
        cgroup_path = f"/sys/fs/cgroup/system.slice/docker-{cid}.scope"

        for _ in range(10):  # retry up to 5s
            if self._stop_refresh.is_set():
                return
            if os.path.exists(cgroup_path):
                inode = os.stat(cgroup_path).st_ino
                self.cgroup_map[inode] = (short_id, name)
                self._id_to_name[short_id] = name
                break
            self._stop_refresh.wait(0.5)

        # Update BPF PID map for this container (may fail if process not
        # ready yet — polling thread picks it up)
        try:
            c = self.docker_client.containers.get(cid)
            top = c.top()
            ContainerId = self.bpf['container_map'].Leaf
            for process in top['Processes']:
                pid_str = process[1].strip()
                if pid_str.isdigit():
                    entry = ContainerId()
                    entry.id = short_id.encode('utf-8')
                    self.bpf['container_map'][ct.c_uint32(int(pid_str))] = entry
        except Exception:
            pass  # not ready yet — polling will handle

    def _on_container_stop(self, cid, name):
        """Container stopped — remove from all maps.

        Note: on 'die', the cgroup directory may already be deleted by the
        kernel, so we must match by ID (not stat the path) when deleting.
        """
        short_id = cid[:12]

        # Remove from cgroup map (match by stored short_id)
        for inode, (sid, _) in list(self.cgroup_map.items()):
            if sid == short_id:
                del self.cgroup_map[inode]
                break

        self._id_to_name.pop(short_id, None)

        # Remove from BPF PID map (match by stored value)
        try:
            for key in list(self.bpf['container_map'].keys()):
                val = self.bpf['container_map'].get(key)
                if val is None:
                    continue
                try:
                    val_id = bytes(val.id).split(b'\x00')[0].decode('utf-8')
                except Exception:
                    continue
                if val_id == short_id:
                    del self.bpf['container_map'][key]
        except Exception:
            pass

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
        """Build cgroup_inode → (short_id, name) mapping."""
        self.cgroup_map = {}
        self._id_to_name = {}
        try:
            for c in self.docker_client.containers.list():
                cgroup_path = (
                    f"/sys/fs/cgroup/system.slice/docker-{c.id}.scope"
                )
                if os.path.exists(cgroup_path):
                    inode = os.stat(cgroup_path).st_ino
                    short_id = c.id[:12]
                    self.cgroup_map[inode] = (short_id, c.name)
                    self._id_to_name[short_id] = c.name
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
