#!/usr/bin/env python3
"""
eBPF Container Guard - Main Entry Point

Real-time container escape detection and response system based on eBPF.
Copyright (c) 2026 chenjx12
Licensed under the MIT License. See LICENSE for details.
"""

import argparse
import sys
import os
import time
import threading
from pathlib import Path

from bcc import BPF
import ctypes as ct
import docker

# Add src to path for module imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from detector.engine import EscapeDetector, print_alert
from responder.docker_responder import ResponseEngine


# ============================================================
# ptrace request constant mapping table
# ============================================================
PTRACE_MAP = {
    0: "PTRACE_TRACEME",
    1: "PTRACE_PEEKTEXT",
    2: "PTRACE_PEEKDATA",
    3: "PTRACE_PEEKUSER",
    4: "PTRACE_POKETEXT",
    5: "PTRACE_POKEDATA",
    6: "PTRACE_POKEUSER",
    7: "PTRACE_CONT",
    8: "PTRACE_KILL",
    9: "PTRACE_SINGLESTEP",
    12: "PTRACE_GETREGS",
    13: "PTRACE_SETREGS",
    14: "PTRACE_GETFPREGS",
    15: "PTRACE_SETFPREGS",
    16: "PTRACE_ATTACH",
    17: "PTRACE_DETACH",
    24: "PTRACE_SYSCALL",
    0x4200: "PTRACE_SECCOMP_GET_FILTER",
    0x4201: "PTRACE_SECCOMP_GET_METADATA",
    0x4206: "PTRACE_SECCOMP_GET_METADATA",
    0x420e: "PTRACE_GET_SYSCALL_INFO",
    0x1000: "PTRACE_SEIZE",
    0x1001: "PTRACE_INTERRUPT",
    0x1002: "PTRACE_LISTEN",
}


class ContainerEscapeMonitor:
    """Container escape detection and active defense system"""

    def __init__(self, rules_file="config/rules.yaml",
                 responses_file="config/responses.yaml",
                 verbose=False):
        self.verbose = verbose

        # Resolve paths relative to this script
        script_dir = Path(__file__).parent.resolve()
        ebpf_c_file = str(script_dir / "src" / "ebpf" / "escape-detect.bpf.c")

        # 1. Compile and load eBPF program
        print("[1/5] Compiling and loading eBPF program...")
        self.bpf = BPF(src_file=ebpf_c_file)

        # 2. Load detection rules
        print("[2/5] Loading detection rules...")
        self.detector = EscapeDetector(rules_file)

        # 3. Load response strategies
        print("[3/5] Loading response strategies...")
        self.responder = ResponseEngine(responses_file)

        # 4. Connect to Docker daemon
        print("[4/5] Connecting to Docker daemon...")
        try:
            self.docker_client = docker.from_env()
        except docker.errors.DockerException as e:
            print(f"[!] Docker connection failed: {e}", file=sys.stderr)
            print("[!] Hint: ensure Docker is running (systemctl start docker)",
                  file=sys.stderr)
            sys.exit(1)

        # 5. Initialize container identity maps
        print("[5/5] Initializing container identity maps...")
        self._refresh_all_maps()

        # Start background map refresh thread (every 15s)
        self._stop_refresh = threading.Event()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, daemon=True)
        self._refresh_thread.start()

        print("\n========================================")
        print("  eBPF Container Guard v0.1.1")
        print("  Real-time container escape detection")
        print("  Press Ctrl+C to stop")
        print("========================================\n")

    # ================================================================
    # Container identity mapping (background-refreshed)
    # ================================================================

    def _refresh_all_maps(self):
        """Refresh both PID map (kernel) and cgroup map (userspace)."""
        self.cgroup_map = getattr(self, 'cgroup_map', {})
        self._build_cgroup_map()
        self.update_container_map()

    def _refresh_loop(self):
        """Background thread: periodically refresh container maps."""
        while not self._stop_refresh.is_set():
            self._stop_refresh.wait(timeout=5)  # refresh every 5s
            if not self._stop_refresh.is_set():
                self._refresh_all_maps()

    def update_container_map(self):
        """Populate BPF container_map: pid -> container_short_id"""
        try:
            containers = self.docker_client.containers.list()
            mapped = 0
            for container in containers:
                try:
                    top_result = container.top()
                except Exception:
                    continue
                for process in top_result['Processes']:
                    pid_str = process[1].strip()
                    if not pid_str.isdigit():
                        continue
                    pid = int(pid_str)
                    cid = container.id[:12]

                    # BCC map Leaf type
                    ContainerId = self.bpf['container_map'].Leaf
                    c_id = ContainerId()
                    c_id.id = cid.encode('utf-8')
                    self.bpf['container_map'][ct.c_uint32(pid)] = c_id
                    mapped += 1
            print(f"  [Map] PID map: {mapped} processes "
                  f"across {len(containers)} containers")
        except Exception as e:
            print(f"  [!] PID map update failed: {e}", file=sys.stderr)

    def _build_cgroup_map(self):
        """Build cgroup_inode -> container_short_id mapping.

        Used as fallback when the BPF pid->container_id map misses
        (e.g., process started between map syncs). The cgroup_id is
        captured atomically in kernel space, avoiding /proc TOCTOU races.
        """
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

    def _resolve_by_cgroup_fs(self, pid):
        """Last-resort fallback: read /proc/<pid>/cgroup for container ID."""
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

    # ================================================================
    # Event processing pipeline
    # ================================================================

    def handle_event(self, cpu, data, size):
        """Ring buffer callback: parse -> detect -> respond"""
        try:
            event = self.bpf['events'].event(data)

            # Map numeric event type to string
            event_type_map = {1: 'mount', 2: 'ptrace', 3: 'openat'}

            # Resolve container identity (3-tier fallback)
            raw_cid = event.container_id.decode(
                'utf-8', errors='replace').rstrip('\x00')
            event_pid = event.pid
            event_cgid = event.cgroup_id

            if raw_cid in ('host', '', 'unknown'):
                # Tier 1: cgroup_inode map (race-free, kernel-captured)
                # Refreshed every 15s by background thread
                if event_cgid in getattr(self, 'cgroup_map', {}):
                    raw_cid = self.cgroup_map[event_cgid]
                elif event_pid > 0:
                    # Tier 2: /proc/<pid>/cgroup (process still alive)
                    raw_cid = self._resolve_by_cgroup_fs(event_pid)

            # Build event dict for rule engine
            event_dict = {
                'event_type': event_type_map.get(event.event_type, 'unknown'),
                'pid': event_pid,
                'uid': event.uid,
                'comm': event.comm.decode('utf-8', errors='replace'),
                'container_id': raw_cid,
                'timestamp': time.time()
            }

            # Add event-type-specific fields
            if event.event_type == 1:  # MOUNT
                event_dict['fstype'] = event.fstype.decode(
                    'utf-8', errors='replace').rstrip('\x00')
                event_dict['target_path'] = event.target_path.decode(
                    'utf-8', errors='replace').rstrip('\x00')
            elif event.event_type == 2:  # PTRACE
                event_dict['target_pid'] = event.target_pid
                request_val = event.request_raw
                mapped_req = PTRACE_MAP.get(
                    request_val,
                    PTRACE_MAP.get(request_val & 0xFFFFFFFF)
                )
                event_dict['request'] = (
                    mapped_req if mapped_req
                    else f"UNKNOWN(0x{request_val:x})"
                )
            elif event.event_type == 3:  # OPENAT
                event_dict['target_path'] = event.target_path.decode(
                    'utf-8', errors='replace').rstrip('\x00')

            # === Detection + Response Pipeline ===
            matched_rules = self.detector.check_event(event_dict)
            if matched_rules:
                for rule in matched_rules:
                    alert = self.detector.generate_alert(rule, event_dict)
                    print_alert(alert)
                    # Auto-execute response action
                    self.responder.handle_alert(alert)
            else:
                # Normal event — green output
                if self.verbose:
                    if event_dict['event_type'] == 'ptrace':
                        print(f"\033[92m[INFO] ptrace - "
                              f"PID:{event_dict['pid']} "
                              f"Comm:{event_dict['comm']} "
                              f"CID:{event_dict['container_id']} "
                              f"Req:{event_dict['request']} "
                              f"Target:{event_dict['target_pid']}\033[0m")
                    elif event_dict['event_type'] == 'mount':
                        print(f"\033[92m[INFO] mount - "
                              f"PID:{event_dict['pid']} "
                              f"Comm:{event_dict['comm']} "
                              f"CID:{event_dict['container_id']} "
                              f"FS:{event_dict['fstype']} "
                              f"Path:{event_dict['target_path']}\033[0m")
                    # openat is high-frequency; only print on alert

        except Exception as e:
            print(f"[ERROR] Event processing failed: {e}", file=sys.stderr)
            if self.verbose:
                import traceback
                traceback.print_exc()

    # ================================================================
    # Main loop
    # ================================================================

    def run(self):
        """Start monitoring loop"""
        self.bpf['events'].open_ring_buffer(self.handle_event)

        try:
            while True:
                self.bpf.ring_buffer_poll()
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[i] Shutting down...")
            print("👋 eBPF Container Guard stopped.")


# ================================================================
# CLI entry point
# ================================================================

def main():
    parser = argparse.ArgumentParser(
        description='🛡️  eBPF Container Guard - '
                    'Real-time container escape detection and response'
    )
    parser.add_argument(
        '--rules',
        default='config/rules.yaml',
        help='Path to detection rules YAML (default: config/rules.yaml)'
    )
    parser.add_argument(
        '--responses',
        default='config/responses.yaml',
        help='Path to response strategies YAML (default: config/responses.yaml)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging (print all normal events)'
    )

    args = parser.parse_args()

    # Resolve config paths relative to project root
    script_dir = Path(__file__).parent.resolve()
    rules_path = script_dir / args.rules
    responses_path = script_dir / args.responses

    if not rules_path.exists():
        print(f"❌ Error: Rules file not found: {rules_path}")
        sys.exit(1)

    if not responses_path.exists():
        print(f"❌ Error: Responses file not found: {responses_path}")
        sys.exit(1)

    # Start monitor
    monitor = ContainerEscapeMonitor(
        rules_file=str(rules_path),
        responses_file=str(responses_path),
        verbose=args.verbose
    )
    monitor.run()


if __name__ == '__main__':
    main()
