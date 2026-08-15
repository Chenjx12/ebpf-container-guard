#!/usr/bin/env python3
"""
K8s 主动防御响应引擎 (v0.5.2) — 与 docker_responder 同接口, 双轨并行。

动作映射 (决策 #41):
  pause_container  → cgroup.freeze (内核 v2 freezer, 与 docker pause 同机制)
                     + patch annotation guard/frozen=true
  isolate_network  → iptables FORWARD DROP Pod IP (断 C2/横移)
                     + patch annotation guard/isolated=true
  kill_process     → 原样保留 (宿主 PID os.kill, 与运行时无关)
  kill_container   → delete pod (Deployment/RS 先 scale 0 防控制器重建)
  log_only         → 保留
  block_image      → 仅记录 + 人工队列 (admission webhook 留 v0.5.3)

IRREVERSIBLE_ACTIONS 判定原样保留 (ADR-014 分级自动化)。
"""
import json
import os
import signal
import sys
import time
from datetime import datetime

import yaml
from kubernetes import client, config


class K8sResponseEngine:
    """K8s 响应引擎 — 同 ResponseEngine 接口。"""

    IRREVERSIBLE_ACTIONS = ('kill_container', 'block_image')

    def __init__(self, responses_file='responses.yaml',
                 kubeconfig="/etc/rancher/k3s/k3s.yaml"):
        with open(responses_file, 'r') as f:
            self.config = yaml.safe_load(f).get('responses', [])

        self.policy = {}
        for rule in self.config:
            self.policy[rule['threat_level']] = rule['action']

        from core.kube_utils import load_kubeconfig
        load_kubeconfig(kubeconfig)
        self._client = client.CoreV1Api()
        self._apps = client.AppsV1Api()
        print(f"[K8sResponseEngine] 已加载 {len(self.policy)} 条响应策略")

        self.cooldown = {}
        self.cooldown_period = 600

    # -----------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------

    def _parse_ns_pod(self, container_id):
        """'ns/pod' → (ns, pod); 短 ID → 反查 ns/pod (身份冷启动兜底)"""
        if not container_id or container_id in ('host', 'unknown'):
            return None, None
        parts = container_id.split('/')
        if len(parts) == 2 and parts[0] and parts[1]:
            return parts[0], parts[1]
        # 短 ID (12位 hex) → glob scope → 反查 pod
        if len(container_id) == 12 and container_id.isalnum():
            return self._short_id_to_ns_pod(container_id)
        return None, None

    def _short_id_to_ns_pod(self, short_id):
        """短 ID → (ns, pod): cgroup scope 反查 pod uid → k8s 查名。

        scope 创建可能有延迟 — 重试一次 (2s)。
        field_selector 不支持 metadata.uid (400) — list 后内存匹配。
        """
        import glob
        import re
        import time
        for attempt in range(2):
            matches = glob.glob(
                f"/sys/fs/cgroup/kubepods.slice/**/cri-containerd-{short_id}*.scope",
                recursive=True)
            for m in matches:
                mm = re.search(r'-pod([0-9a-f_]+)\.slice', m)
                if not mm:
                    continue
                uid = mm.group(1).replace('_', '-')
                try:
                    pods = self._client.list_pod_for_all_namespaces()
                    for p in pods.items:
                        if p.metadata.uid == uid:
                            return p.metadata.namespace, p.metadata.name
                except Exception:
                    continue
            if attempt == 0:
                time.sleep(2)
        return None, None

    @staticmethod
    def _pod_cgroup_path(pid):
        """event pid → 宿主 cgroup scope 路径 (v2, kubepods.slice)"""
        try:
            with open(f"/proc/{pid}/cgroup") as f:
                for line in f:
                    if 'cri-containerd-' in line and '.scope' in line:
                        # 0::/kubepods.slice/.../cri-containerd-<id>.scope
                        path = line.strip().split('::', 1)[-1]
                        return f"/sys/fs/cgroup{path}"
        except (FileNotFoundError, PermissionError):
            pass
        return None

    def _set_freeze(self, pid, freeze, ns=None, pod=None, container_id=None):
        """写 cgroup.freeze (1=冻结, 0=解冻)。

        三级定位 (v0.5.5): event pid cgroup → pod 主容器 ID → 短 ID glob。
        container_id 可能本身是短 ID (身份冷启动) — 直接用它 glob。
        防自毁: 解析出的 scope 若是 guard 自身容器则拒绝。
        """
        path = self._pod_cgroup_path(pid)
        if path is None and ns and pod:
            path = self._pod_cgroup_path_by_uid(ns, pod)
        if path is None:
            # 短 ID 直接 glob (身份冷启动窗口内 container_id 可能是短 ID)
            path = self._pod_cgroup_path_by_shortid(ns, pod, container_id)
        if not path or not os.path.exists(path):
            return False
        # 防自毁: 自身 cgroup 的容器 ID
        try:
            with open('/proc/self/cgroup') as f:
                self_cg = f.read()
            self_cid = ''
            if 'cri-containerd-' in self_cg:
                start = self_cg.index('cri-containerd-') + 15
                self_cid = self_cg[start:start + 12]
            if self_cid and self_cid in path:
                print(f"⚠️ 防自毁: freeze 目标 {path} 是 guard 自身, 拒绝")
                return False
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        freeze_file = os.path.join(path, 'cgroup.freeze')
        try:
            with open(freeze_file, 'w') as f:
                f.write('1' if freeze else '0')
            return True
        except (PermissionError, FileNotFoundError):
            return False

    def _pod_cgroup_path_by_shortid(self, ns, pod, container_id=None):
        """短 ID → scope (身份冷启动兜底)。

        container_id 优先 (可能是短 ID 或完整 ID); 否则 pod 名查 k8s。
        """
        import glob
        candidates = []
        # container_id 本身可能是短 ID (12位) 或完整 ID
        if container_id and container_id not in ('host', 'unknown'):
            candidates.append(container_id)
        if ns and pod:
            # 尝试 ns/pod 名 → 查 k8s 拿容器 ID
            try:
                p = self._client.read_namespaced_pod(pod, ns)
                cid = (p.status.container_statuses[0].container_id
                       if p.status.container_statuses else '')
                full_id = cid.split('//')[-1]
                if full_id:
                    candidates.append(full_id)
            except Exception:
                pass
        # 短 ID 直试 (pod 参数本身是短 ID)
        if pod and len(pod) == 12 and pod.isalnum():
            candidates.append(pod)
        for cid in candidates:
            matches = glob.glob(
                f"/sys/fs/cgroup/kubepods.slice/**/cri-containerd-{cid[:12]}*.scope",
                recursive=True)
            if matches:
                return matches[0]
        return None

    def _pod_cgroup_path_by_uid(self, ns, pod):
        """按 pod 主容器 ID 定位 cgroup (精确, 非扫 /proc 碰运气)。

        之前扫 /proc 会匹配到 exec 辅助进程的 scope (短暂存在),
        冻结错目标。改为从 k8s API 拿主容器 ID 直接定位。
        """
        try:
            p = self._client.read_namespaced_pod(pod, ns)
            cid = (p.status.container_statuses[0].container_id
                   if p.status.container_statuses else '')
            # containerID 格式: containerd://<64位ID>
            full_id = cid.split('//')[-1]
            if not full_id:
                return None
            import glob
            matches = glob.glob(
                f"/sys/fs/cgroup/kubepods.slice/**/cri-containerd-{full_id}.scope",
                recursive=True)
            return matches[0] if matches else None
        except Exception:
            return None

    def _pod_ip(self, ns, pod):
        try:
            p = self._client.read_namespaced_pod(pod, ns)
            return p.status.pod_ip
        except Exception:
            return None

    def _patch_annotation(self, ns, pod, key, value):
        body = {"metadata": {"annotations": {key: value}}}
        try:
            self._client.patch_namespaced_pod(pod, ns, body)
            return True
        except Exception:
            return False

    def _iptables_available(self):
        """iptables 是否可用。

        容器化: nsenter 进宿主 netns 执行宿主 iptables (宿主 glibc 兼容);
        宿主机: 直接 iptables (PATH)。
        """
        import shutil
        return shutil.which('nsenter') is not None or \
            shutil.which('iptables') is not None

    def _iptables_cmd(self):
        """返回 iptables 命令前缀。

        K8s 容器化: nsenter -t 1 -n (进宿主 netns, 宿主 iptables);
        宿主机: 直接 iptables。
        """
        if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
            # 容器内 (有 serviceaccount = in_cluster):
            # nsenter -m -n 进宿主 mount+netns, 用宿主的 iptables (glibc 兼容)
            return 'nsenter -t 1 -m -n iptables'
        return 'iptables'

    def _iptables_block(self, pod_ip):
        """iptables FORWARD DROP 源=Pod IP (断出向 C2/横移)"""
        if not pod_ip:
            return False
        ipt = self._iptables_cmd()
        os.system(f"{ipt} -C FORWARD -s {pod_ip} -j DROP 2>/dev/null "
                  f"|| {ipt} -I FORWARD 1 -s {pod_ip} -j DROP")
        return True

    def _iptables_unblock(self, pod_ip):
        if not pod_ip:
            return False
        ipt = self._iptables_cmd()
        os.system(f"{ipt} -D FORWARD -s {pod_ip} -j DROP 2>/dev/null")
        return True

    def _owner_controller(self, ns, pod):
        """pod → 控制器 (Deployment/StatefulSet/RS); 裸 pod 返回 None"""
        try:
            p = self._client.read_namespaced_pod(pod, ns)
            for ref in (p.metadata.owner_references or []):
                kind = ref.kind
                name = ref.name
                if kind == 'ReplicaSet':
                    # RS → Deployment (ownerRef 链)
                    try:
                        rs = self._apps.read_namespaced_replica_set(name, ns)
                        for rref in (rs.metadata.owner_references or []):
                            if rref.kind == 'Deployment':
                                return 'Deployment', rref.name
                    except Exception:
                        pass
                    return 'ReplicaSet', name
                if kind in ('Deployment', 'StatefulSet'):
                    return kind, name
            return None, None
        except Exception:
            return None, None

    # -----------------------------------------------------------
    # 主入口 (同 ResponseEngine 接口)
    # -----------------------------------------------------------

    def handle_alert(self, alert, forced_action=None, ai_confidence=None):
        severity = alert.get('severity', 'LOW').lower()
        container_id = alert['event'].get('container_id', '')
        event_pid = alert['event'].get('pid', 0)

        # 跳过宿主机进程
        if container_id in ['', 'host', 'unknown']:
            print(f"[INFO] 跳过宿主机事件(PID={event_pid}),不执行响应")
            return 'skipped_host'

        # 确定响应动作: forced_action 优先, 否则按 severity 查策略
        if forced_action and forced_action != 'log_only':
            action = forced_action
        else:
            action = self.policy.get(severity, 'log_only')

        # ADR-014: 不可逆动作永远进人工队列
        if action in self.IRREVERSIBLE_ACTIONS:
            print(f"\n⏳ [QUEUE] {action} 需要人工确认 "
                  f"(AI置信度={ai_confidence or 'N/A'})")
            return 'queued_human'

        # 冷却检查
        now = time.time()
        if container_id in self.cooldown:
            if now - self.cooldown[container_id] < self.cooldown_period:
                remaining = int(self.cooldown_period
                                - (now - self.cooldown[container_id]))
                print(f"[SKIP] {container_id} 在冷却期内 (剩余{remaining}秒)")
                return 'skipped_cooldown'

        print(f"\n🛡️  [RESPONSE] 触发自动防御: {severity.upper()} → {action}")
        ns, pod = self._parse_ns_pod(container_id)

        try:
            success = True
            if action == 'pause_container':
                success = self._set_freeze(event_pid, True, ns, pod,
                                           container_id)
                if success:
                    self._patch_annotation(
                        ns, pod, 'guard/frozen',
                        datetime.now().isoformat())
                    print(f"✅ Pod {container_id} FROZEN (cgroup.freeze)")
            elif action == 'isolate_network':
                # ns/pod 可能因短 ID 解析失败 — 重解析 (短 ID 反查)
                if not ns or not pod:
                    ns, pod = self._parse_ns_pod(container_id)
                pod_ip = self._pod_ip(ns, pod)
                if self._iptables_available():
                    success = self._iptables_block(pod_ip)
                    if success:
                        self._patch_annotation(
                            ns, pod, 'guard/isolated',
                            datetime.now().isoformat())
                        print(f"✅ Pod {container_id} ISOLATED "
                              f"(iptables DROP {pod_ip})")
                else:
                    # 兜底 (v0.5.4 hostNetwork 下容器内 iptables 可用,
                    # 此处仅在未来 kube-router 接管等异常时触发)
                    self._patch_annotation(
                        ns, pod, 'guard/isolated',
                        datetime.now().isoformat())
                    print(f"⚠️ Pod {container_id} 降级 annotation-only "
                          f"(iptables 不可用)")
                    success = True
            elif action == 'kill_process':
                self.kill_process(container_id, event_pid)
            elif action == 'kill_container':
                self.kill_container(container_id)
            elif action == 'log_only':
                self.log_only(alert)

            self.cooldown[container_id] = now
            return 'executed' if success else 'error'
        except Exception as e:
            print(f"[ERROR] 响应执行失败: {e}", file=sys.stderr)
            return 'error'

    # -----------------------------------------------------------
    # 动作实现
    # -----------------------------------------------------------

    def kill_process(self, container_id, pid):
        """终止可疑进程 (宿主 PID, 与 Docker 版一致)"""
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
                print(f"🔥 Process {pid} FORCE KILLED (SIGKILL)")
            except ProcessLookupError:
                print(f"✅ Process {pid} TERMINATED (SIGTERM)")
            self._audit_log(container_id, "KILL_PROCESS",
                            f"Process {pid} terminated")
        except (ProcessLookupError, PermissionError) as e:
            print(f"⚠️  Process {pid} 终止失败: {e}")

    def kill_container(self, container_id):
        """删除 Pod (裸 pod 直接删; Deployment/RS 先 scale 0)"""
        ns, pod = self._parse_ns_pod(container_id)
        if not ns or not pod:
            return
        kind, name = self._owner_controller(ns, pod)
        if kind in ('Deployment', 'StatefulSet'):
            # 先 scale 0 防控制器秒级重建 (恢复由人工处理)
            body = {"spec": {"replicas": 0}}
            try:
                if kind == 'Deployment':
                    self._apps.patch_namespaced_deployment(name, ns, body)
                else:
                    self._apps.patch_namespaced_stateful_set(name, ns, body)
                print(f"⏸️  控制器 {kind} {name} scale 0 (防重建)")
            except Exception as e:
                print(f"⚠️  scale 失败: {e}", file=sys.stderr)
        self._client.delete_namespaced_pod(pod, ns)
        print(f"🔥 Pod {container_id} DELETED")
        self._audit_log(container_id, "KILL_CONTAINER", "Pod deleted")

    def log_only(self, alert):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'severity': alert['severity'],
            'rule': alert['rule_name'],
            'description': alert['description'],
            'container': alert['event'].get('container_id', 'unknown'),
            'process': alert['event'].get('comm', 'unknown'),
            'pid': alert['event'].get('pid', 'unknown')
        }
        with open('audit.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        print(f"📝 AUDIT LOG written to audit.log")

    def _audit_log(self, container_id, action, details):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'container_id': container_id,
            'action': action,
            'details': details
        }
        with open('response_audit.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
