#!/usr/bin/env python3
"""
Decision executor — closes the human-in-the-loop loop (v0.3.1).

The dashboard writes human verdicts to decisions.log; this module watches
that file and EXECUTES the verdicts against Docker:

  confirmed → kill container (irreversible action, human-approved)
  dismissed → release isolation (unpause / reconnect network)

Execution result is written back to decisions.log (executed field).
"""

import json
import os
import threading
import time
from typing import Optional

import docker


class DecisionExecutor:
    """Watches decisions.log and executes human verdicts on Docker."""

    POLL_INTERVAL = 2  # seconds

    def __init__(self, decisions_path: str = "decisions.log",
                 docker_client=None):
        self.decisions_path = decisions_path
        self.docker_client = docker_client or docker.from_env()
        self._processed = set()  # container_id + decision timestamp dedup
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        """Start watching decisions.log in background."""
        # Mark existing entries as processed (don't re-execute old verdicts)
        self._seed_processed()
        self._thread.start()
        print(f"  [Executor] watching {self.decisions_path} "
              f"({self.POLL_INTERVAL}s)")

    def stop(self):
        self._stop.set()

    # -----------------------------------------------------------
    # Main loop
    # -----------------------------------------------------------

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._process_new_decisions()
            except Exception as e:
                print(f"  [!] Decision executor error: {e}", file=sys.stderr)
            self._stop.wait(self.POLL_INTERVAL)

    def _seed_processed(self):
        """Mark existing decisions as already processed at startup."""
        if not os.path.exists(self.decisions_path):
            return
        try:
            with open(self.decisions_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    key = (entry.get('container_id', ''),
                           entry.get('timestamp', ''))
                    self._processed.add(key)
        except Exception:
            pass

    def _process_new_decisions(self):
        """Read new entries from decisions.log and execute them."""
        if not os.path.exists(self.decisions_path):
            return
        with open(self.decisions_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                cid = entry.get('container_id', '')
                decision = entry.get('decision', '')
                ts = entry.get('timestamp', '')
                # skip entries we've already processed (or already executed)
                if entry.get('executed'):
                    continue
                key = (cid, ts)
                if key in self._processed:
                    continue

                self._processed.add(key)
                if not cid or decision not in ('confirmed', 'dismissed'):
                    continue

                result = self._execute(cid, decision)
                self._mark_executed(entry, result)

    # -----------------------------------------------------------
    # Execution
    # -----------------------------------------------------------

    def _execute(self, container_id: str, decision: str) -> bool:
        """Execute a verdict on the container. Returns success."""
        try:
            container = self.docker_client.containers.get(container_id)
        except docker.errors.NotFound:
            print(f"  [Executor] 容器 {container_id} 已不存在 "
                  f"(判决无需执行)")
            return True  # nothing to do
        except Exception as e:
            print(f"  [Executor] 查询容器失败: {e}", file=sys.stderr)
            return False

        if decision == 'confirmed':
            # Human approved → kill the container (irreversible, human-authorized)
            try:
                container.kill()
                print(f"  🔥 [EXECUTOR] 人工确认处置: 容器 {container_id} "
                      f"已 KILL")
                return True
            except docker.errors.APIError as e:
                print(f"  [Executor] kill 失败: {e}", file=sys.stderr)
                return False

        elif decision == 'dismissed':
            # Human dismissed → release isolation (unpause / reconnect)
            ok = True
            try:
                if container.status == 'paused':
                    container.unpause()
                    print(f"  ✅ [EXECUTOR] 人工驳回: 容器 {container_id} "
                          f"已恢复 (unpause)")
            except docker.errors.APIError as e:
                print(f"  [Executor] unpause 失败: {e}", file=sys.stderr)
                ok = False

            # Reconnect default networks that were disconnected by isolation
            try:
                networks = container.attrs.get(
                    'NetworkSettings', {}).get('Networks', {})
                for net_name in list(networks.keys()):
                    if net_name == 'none':
                        continue
                    try:
                        network = self.docker_client.networks.get(net_name)
                        network.connect(container)
                        print(f"  ✅ [EXECUTOR] 容器 {container_id} "
                              f"重新连接 {net_name}")
                    except docker.errors.APIError:
                        pass  # already connected or network gone
            except Exception:
                pass
            return ok

        return False

    def _mark_executed(self, entry: dict, success: bool):
        """Append execution result to decisions.log."""
        entry['executed'] = success
        entry['executed_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        with open(self.decisions_path, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
