#!/usr/bin/env python3
"""
K8s decision executor — human-in-the-loop on K8s (v0.5.2).

同 DecisionExecutor 的 decisions.log 协议, 执行换成 K8s 动作:
  confirmed → delete pod (Deployment/RS 先 scale 0, 防控制器重建)
  dismissed → 恢复 (cgroup.freeze=0 + iptables -D Pod IP + 清 annotation)

container_id 语义: 'ns/pod' (ADR-040 格式)。
"""
import json
import os
import threading

from kubernetes import client, config


class K8sDecisionExecutor:
    """Watches decisions.log and executes human verdicts on K8s."""

    POLL_INTERVAL = 2

    def __init__(self, decisions_path="decisions.log",
                 kubeconfig="/etc/rancher/k3s/k3s.yaml"):
        self.decisions_path = decisions_path
        config.load_kube_config(config_file=kubeconfig)
        self._client = client.CoreV1Api()
        self._apps = client.AppsV1Api()
        self._processed = set()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._seed_processed()
        self._thread.start()
        print(f"  [K8sExecutor] watching {self.decisions_path} "
              f"({self.POLL_INTERVAL}s)")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._process_new_decisions()
            except Exception as e:
                print(f"  [!] K8s executor error: {e}", file=sys.stderr)
            self._stop.wait(self.POLL_INTERVAL)

    def _seed_processed(self):
        if not os.path.exists(self.decisions_path):
            return
        try:
            with open(self.decisions_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    self._processed.add((entry.get('container_id', ''),
                                         entry.get('timestamp', '')))
        except Exception:
            pass

    def _process_new_decisions(self):
        if not os.path.exists(self.decisions_path):
            return
        with open(self.decisions_path) as f:
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

    def _mark_executed(self, entry, result):
        """回写 executed 字段到 decisions.log"""
        try:
            with open(self.decisions_path, 'a') as f:
                f.write(json.dumps({**entry, 'executed': bool(result)},
                                   ensure_ascii=False) + '\n')
        except Exception:
            pass

    # -----------------------------------------------------------
    # Execution
    # -----------------------------------------------------------

    @staticmethod
    def _parse_ns_pod(container_id):
        parts = container_id.split('/')
        if len(parts) == 2 and parts[0] and parts[1]:
            return parts[0], parts[1]
        return None, None

    def _owner_controller(self, ns, pod):
        try:
            p = self._client.read_namespaced_pod(pod, ns)
            for ref in (p.metadata.owner_references or []):
                if ref.kind == 'ReplicaSet':
                    try:
                        rs = self._apps.read_namespaced_replica_set(
                            ref.name, ns)
                        for rref in (rs.metadata.owner_references or []):
                            if rref.kind == 'Deployment':
                                return 'Deployment', rref.name
                    except Exception:
                        pass
                    return 'ReplicaSet', ref.name
                if ref.kind in ('Deployment', 'StatefulSet'):
                    return ref.kind, ref.name
            return None, None
        except Exception:
            return None, None

    def _pod_cgroup_path(self, ns, pod):
        """pod → 宿主 cgroup scope 路径 (从 pod 主容器 PID 反查)"""
        # 简化: 遍历 /proc 找属于该 pod 的 cgroup (按 pod uid)
        try:
            p = self._client.read_namespaced_pod(pod, ns)
            pod_uid = p.metadata.uid.replace('-', '_')
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid_dir}/cgroup") as f:
                        content = f.read()
                    if f'pod{pod_uid}' in content and \
                            'cri-containerd-' in content:
                        path = content.strip().split('::', 1)[-1]
                        return f"/sys/fs/cgroup{path}"
                except (FileNotFoundError, PermissionError):
                    continue
        except Exception:
            pass
        return None

    def _set_freeze(self, cgroup_path, freeze):
        if not cgroup_path or not os.path.exists(cgroup_path):
            return False
        try:
            with open(os.path.join(cgroup_path, 'cgroup.freeze'), 'w') as f:
                f.write('1' if freeze else '0')
            return True
        except (PermissionError, FileNotFoundError):
            return False

    def _pod_ip(self, ns, pod):
        try:
            p = self._client.read_namespaced_pod(pod, ns)
            return p.status.pod_ip
        except Exception:
            return None

    def _iptables_unblock(self, pod_ip):
        if pod_ip:
            os.system(f"iptables -D FORWARD -s {pod_ip} -j DROP 2>/dev/null")

    def _clear_annotation(self, ns, pod, key):
        try:
            body = {"metadata": {"annotations": {key: None}}}
            self._client.patch_namespaced_pod(pod, ns, body)
        except Exception:
            pass

    def _execute(self, container_id, decision):
        ns, pod = self._parse_ns_pod(container_id)
        if not ns or not pod:
            print(f"  [K8sExecutor] 无法解析 {container_id}")
            return False

        if decision == 'confirmed':
            # 人工确认 → delete pod (不可逆, 人工授权)
            kind, name = self._owner_controller(ns, pod)
            if kind in ('Deployment', 'StatefulSet'):
                try:
                    body = {"spec": {"replicas": 0}}
                    if kind == 'Deployment':
                        self._apps.patch_namespaced_deployment(name, ns, body)
                    else:
                        self._apps.patch_namespaced_stateful_set(name, ns,
                                                                 body)
                    print(f"  ⏸️  控制器 {kind} {name} scale 0")
                except Exception as e:
                    print(f"  [!] scale 失败: {e}", file=sys.stderr)
            try:
                self._client.delete_namespaced_pod(pod, ns)
                print(f"  🔥 [K8sExecutor] 人工确认处置: Pod {container_id} "
                      f"已删除")
                return True
            except Exception as e:
                print(f"  [K8sExecutor] 删除失败: {e}", file=sys.stderr)
                return False

        elif decision == 'dismissed':
            # 人工驳回 → 恢复 (解冻 + 解除隔离 + 清 annotation)
            ok = True
            cg = self._pod_cgroup_path(ns, pod)
            if self._set_freeze(cg, False):
                print(f"  ✅ [K8sExecutor] {container_id} 已解冻")
            pod_ip = self._pod_ip(ns, pod)
            self._iptables_unblock(pod_ip)
            print(f"  ✅ [K8sExecutor] {container_id} 已解除隔离")
            self._clear_annotation(ns, pod, 'guard/frozen')
            self._clear_annotation(ns, pod, 'guard/isolated')
            return ok

        return False
