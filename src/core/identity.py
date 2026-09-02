#!/usr/bin/env python3
"""
Container identity resolution — PID map, cgroup map, background refresh.
(v0.5.1: RuntimeBackend 双轨抽象 — Docker / K8s 平行实现, 自动检测)

3-tier fallback for container ID resolution:
  Tier 1 — BPF PID→container_id map (kernel-space lookup)
  Tier 2 — cgroup inode→container_id map (userspace cache, race-free)
  Tier 3 — /proc/<pid>/cgroup filesystem fallback
"""

import glob
import os
import sys
import ctypes as ct
import threading

import docker


class RuntimeBackend:
    """容器运行时后端接口 (v0.5.1)。

    Docker / K8s 平行实现, ContainerIdentity 只依赖此接口——
    eBPF PID map / cgroup map / 3-tier 回退逻辑与运行时无关。
    """

    def list_containers(self):
        """→ [(cid, {name, image})]; cid 为短 ID (12 位)"""
        raise NotImplementedError

    def events_loop(self, handler, stop_event):
        """容器启停事件流; handler(cid, name, status) status ∈ start|stop"""
        raise NotImplementedError

    def cgroup_path(self, cid):
        """短 ID → cgroup scope 路径 (None 若不存在)"""
        raise NotImplementedError

    def get_meta(self, cid):
        """短 ID → {name, image} (冷路径查询)"""
        raise NotImplementedError


class DockerBackend(RuntimeBackend):
    """Docker 后端 (现码平移, 零逻辑改动)。"""

    def __init__(self, docker_client=None):
        self.docker_client = docker_client or docker.from_env()

    def list_containers(self):
        out = []
        for c in self.docker_client.containers.list():
            out.append((c.id[:12], {
                'name': c.name,
                'image': c.image.tags[0] if c.image.tags
                else (c.image.short_id or 'unknown'),
            }))
        return out

    def events_loop(self, handler, stop_event):
        while not stop_event.is_set():
            try:
                for event in self.docker_client.events(decode=True):
                    if stop_event.is_set():
                        return
                    if event.get('Type') != 'container':
                        continue
                    status = event.get('status') or event.get('Action')
                    if not status:
                        continue
                    actor = event.get('Actor', {})
                    cid = actor.get('ID', '')
                    name = actor.get('Actor', {}).get(
                        'Attributes', {}).get('name', '')
                    if status in ('start', 'restart'):
                        handler(cid, name, 'start')
                    elif status in ('die', 'destroy', 'stop'):
                        handler(cid, name, 'stop')
            except Exception as e:
                print(f"  [!] Docker event stream error: {e}, "
                      f"reconnecting in 2s", file=sys.stderr)
                stop_event.wait(2)

    def cgroup_path(self, cid):
        # Docker v2: 完整 64 位 ID (短 ID 拼不出路径, 用 glob 通配前缀)
        import glob as _glob
        matches = _glob.glob(
            f"/sys/fs/cgroup/system.slice/docker-{cid}*.scope")
        return matches[0] if matches else None

    def get_meta(self, cid):
        try:
            c = self.docker_client.containers.get(cid)
            return {'name': c.name,
                    'image': c.image.tags[0] if c.image.tags
                    else (c.image.short_id or 'unknown')}
        except Exception:
            return {}


class K8sBackend(RuntimeBackend):
    """K8s 后端 (v0.5.1)。

    - 容器发现: kubernetes client watch pods (ns/pod/container 信息全)
    - cgroup 映射: glob /sys/fs/cgroup/kubepods.slice/**/cri-containerd-*.scope
      (QoS 类变化中间 slice, 通配覆盖; scope 名取 ID 前 12 位)
    - container_id (eBPF map value) 填 'ns/pod/container' 三件套
    """

    def __init__(self, kubeconfig="/etc/rancher/k3s/k3s.yaml"):
        from kubernetes import client
        from core.kube_utils import load_kubeconfig
        load_kubeconfig(kubeconfig)
        self._client = client.CoreV1Api()
        self._pod_by_uid = {}   # pod uid -> pod 对象缓存
        self._refresh_pods()

    def _refresh_pods(self):
        try:
            pods = self._client.list_pod_for_all_namespaces(watch=False)
            self._pod_by_uid = {}
            for p in pods.items:
                self._pod_by_uid[p.metadata.uid] = p
        except Exception as e:
            print(f"  [!] K8s pod refresh failed: {e}", file=sys.stderr)

    def list_containers(self):
        out = []
        # 从 cgroup 扫描容器 (无 API 依赖兜底), 再补 pod 元数据
        for scope in glob.glob(
                "/sys/fs/cgroup/kubepods.slice/**/cri-containerd-*.scope",
                recursive=True):
            cid = os.path.basename(scope).split('-')[-1].split('.')[0][:12]
            meta = self._meta_for_scope(scope)
            out.append((cid, meta))
        return out

    def _meta_for_scope(self, scope):
        """从 cgroup scope 路径提取 pod uid → 查 pod 名/镜像"""
        # 路径含 -pod<uid>.slice, uid 用 _ 替 -
        import re
        m = re.search(r'-pod([0-9a-f_]+)\.slice', scope)
        if not m:
            return {'name': 'unknown', 'image': 'unknown'}
        uid = m.group(1).replace('_', '-')
        pod = self._pod_by_uid.get(uid)
        if not pod:
            # v0.5.6: 缓存只在启动时快照, 之后新增 pod 查不到 → 元数据
            # (image/name) 恒为 unknown → escalation 升级链失效。实时
            # 刷新一次再查 (节流 10s, 冷路径频率低)。
            self._maybe_refresh_pods()
            pod = self._pod_by_uid.get(uid)
        if not pod:
            return {'name': 'unknown', 'image': 'unknown'}
        ns = pod.metadata.namespace
        name = pod.metadata.name
        image = (pod.spec.containers[0].image if pod.spec.containers
                 else 'unknown')
        # display = ns/container名 (pod 名含 hash 后缀且长, 重复浪费 64B)
        return {'name': f"{ns}/{name}", 'image': image,
                'display': f"{ns}/{name}"}

    def _maybe_refresh_pods(self):
        """节流刷新 pod 缓存 (未命中时触发, 10s 内不重复 list)。"""
        import time as _t
        now = _t.time()
        if now - getattr(self, '_last_pod_refresh', 0) < 10:
            return
        self._last_pod_refresh = now
        self._refresh_pods()

    def events_loop(self, handler, stop_event):
        """k8s watch pods (start=pod Running, stop=pod 删除)"""
        from kubernetes import watch
        w = watch.Watch()
        while not stop_event.is_set():
            try:
                for event in w.stream(
                        self._client.list_pod_for_all_namespaces,
                        timeout_seconds=30):
                    if stop_event.is_set():
                        return
                    pod = event['object']
                    cid = pod.metadata.uid[:12]
                    name = f"{pod.metadata.namespace}/{pod.metadata.name}"
                    if event['type'] == 'ADDED':
                        handler(cid, name, 'start')
                    elif event['type'] == 'DELETED':
                        handler(cid, name, 'stop')
                    # MODIFIED: 忽略 (状态变化不重建映射)
            except Exception as e:
                print(f"  [!] K8s watch error: {e}, reconnecting in 2s",
                      file=sys.stderr)
                stop_event.wait(2)

    def cgroup_path(self, cid):
        """短 ID → scope 路径 (通配找)"""
        matches = glob.glob(
            f"/sys/fs/cgroup/kubepods.slice/**/cri-containerd-{cid}*.scope",
            recursive=True)
        return matches[0] if matches else None

    def get_meta(self, cid):
        """短 ID → pod 元数据 (冷路径)"""
        for scope in glob.glob(
                f"/sys/fs/cgroup/kubepods.slice/**/cri-containerd-{cid}*.scope",
                recursive=True):
            return self._meta_for_scope(scope)
        return {}


class RuntimeDetector:
    """自动探测容器运行时 (v0.5.1)。

    docker.sock 可连 → DockerBackend; containerd.sock + kubepods.slice
    存在 → K8sBackend; 显式 --runtime 覆盖。
    """

    @staticmethod
    def detect(prefer=None):
        if prefer == 'docker':
            return DockerBackend()
        if prefer == 'k8s':
            return K8sBackend()
        # auto: Docker 优先 (现有场景), K8s 兜底
        try:
            docker.from_env().ping()
            return DockerBackend()
        except Exception:
            pass
        if os.path.exists('/sys/fs/cgroup/kubepods.slice'):
            return K8sBackend()
        return DockerBackend()


class ContainerIdentity:
    """Resolves process identity to container (Docker/K8s).

    Dual-channel map synchronization:
      - Event-driven (primary): runtime events (start/die) → instant update
      - Polling (fallback): 5s full scan, catches missed events / reconnects
    """

    def __init__(self, bpf, backend=None):
        self.bpf = bpf
        self.backend = backend or RuntimeDetector.detect()
        self.cgroup_map = {}          # inode -> (display_id, name)
        self._id_to_name = {}         # short_id/display -> container name
        self._id_to_image = {}        # short_id -> image tag
        self._short_to_display_map = {}  # short_id -> display (K8s: ns/pod)
        self._host_cgroup_cache = set()  # 已确认宿主 cgroup_id (避免重复 stat)

        self._stop_refresh = threading.Event()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, daemon=True)
        self._events_thread = threading.Thread(
            target=self._events_loop, daemon=True)

    def resolve_by_cgroup(self, cgroup_id: int) -> str:
        """cgroup_id(inode) → 容器 display — 事件原子捕获值, 不依赖进程存活。

        v0.5.5: 秒退进程(exec 的 mount/cat/echo)在用户态处理时 /proc 已
        不可读 → resolve 兜底失败标 host → 规则跳过。cgroup_id 是内核侧
        捕获的 scope inode, 与 os.stat(scope).st_ino 一致 (cgroup v2 kernfs)。
        冷窗口 cgroup_map 未建时现场遍历 scope 补 map。
        """
        if not cgroup_id or cgroup_id in self._host_cgroup_cache:
            return 'host'
        hit = self.cgroup_map.get(cgroup_id)
        if hit:
            return hit[0]
        import glob
        for scope in glob.glob(
                "/sys/fs/cgroup/kubepods.slice/**/cri-containerd-*.scope",
                recursive=True):
            try:
                if os.stat(scope).st_ino != cgroup_id:
                    continue
            except OSError:
                continue
            short = os.path.basename(scope).split('-')[-1].split('.')[0][:12]
            meta = self.backend.get_meta(short)
            display = meta.get('display', short)
            name = meta.get('name', short)
            self.cgroup_map[cgroup_id] = (display, name)
            self._id_to_name[display] = name
            self._short_to_display_map[short] = display
            return display
        self._host_cgroup_cache.add(cgroup_id)
        return 'host'

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
            short_id = self._resolve_via_proc(pid)
            # K8s: 短 ID → display (ns/pod); Docker: 短 ID 即最终值
            return self._short_to_display(short_id)

        return 'host'

    def _short_to_display(self, short_id):
        """短 ID → display (K8s: ns/pod; Docker: 短 ID)。

        map 未命中时查 backend 兜底 (新 pod 冷启动窗口)。
        """
        if short_id in ('host', 'unknown'):
            return short_id
        display = self._short_to_display_map.get(short_id)
        if display:
            return display
        try:
            meta = self.backend.get_meta(short_id)
            display = meta.get('display')
            if display:
                self._short_to_display_map[short_id] = display
                return display
        except Exception:
            pass
        return short_id

    def get_name(self, container_id: str) -> str:
        """Look up container name by short ID or display ('' if unknown)."""
        if not container_id or container_id in ('host', 'unknown'):
            return ''
        short = self._display_to_short(container_id)
        name = self._id_to_name.get(short)
        if name:
            return name
        meta = self.backend.get_meta(short)
        name = meta.get('name', '')
        if name:
            self._id_to_name[short] = name
        return name

    def _display_to_short(self, container_id: str) -> str:
        """display (ns/pod) → 短 ID 反查 (v0.5.6)。

        k8s 模式 raw_cid 可能是 display, backend.get_meta 需短 ID —
        不反查则 image/name 恒空 → escalation 升级链失效。
        """
        for sid, disp in self._short_to_display_map.items():
            if disp == container_id:
                return sid
        return container_id

    def get_image(self, container_id: str) -> str:
        """Look up container image by short ID or display ('' if unknown)."""
        if not container_id or container_id in ('host', 'unknown'):
            return ''
        short = self._display_to_short(container_id)
        image = self._id_to_image.get(short)
        if image:
            return image
        meta = self.backend.get_meta(short)
        image = meta.get('image', '')
        if image:
            self._id_to_image[container_id] = image
        return image

    # -----------------------------------------------------------
    # Internal: map management
    # -----------------------------------------------------------

    def _refresh_all(self):
        """Refresh both BPF PID map and userspace cgroup map."""
        self.cgroup_map = getattr(self, 'cgroup_map', {})
        self._build_cgroup_map()
        self._update_pid_map()

    def _refresh_loop(self):
        """Fallback channel: periodically refresh both maps (every 5s)."""
        while not self._stop_refresh.is_set():
            self._stop_refresh.wait(timeout=5)
            if not self._stop_refresh.is_set():
                self._refresh_all()

    def _events_loop(self):
        """Primary channel: listen to runtime events for instant updates."""
        self.backend.events_loop(self._handle_event, self._stop_refresh)

    def _handle_event(self, cid, name, status):
        """Route a runtime event to the appropriate map update."""
        if status == 'start':
            self._on_container_start(cid, name)
        elif status == 'stop':
            self._on_container_stop(cid, name)

    def _on_container_start(self, cid, name):
        """Container started — add to cgroup map + name index + BPF PID map."""
        short_id = cid[:12]
        cgroup_path = self.backend.cgroup_path(short_id)

        if cgroup_path and os.path.exists(cgroup_path):
            inode = os.stat(cgroup_path).st_ino
            self.cgroup_map[inode] = (short_id, name)
            self._id_to_name[short_id] = name

        # Update BPF PID map (may fail if process not ready — polling handles)
        try:
            meta = self.backend.get_meta(short_id)
            # K8s: display = ns/pod/container; Docker: 短 ID
            display = meta.get('display', short_id)
            ContainerId = self.bpf['container_map'].Leaf
            entry = ContainerId()
            entry.id = display.encode('utf-8')
            # 找不到精确 PID 时靠轮询 — 这里用全局扫描的简化 (轮询兜底)
        except Exception:
            pass  # not ready yet — polling will handle

    def _on_container_stop(self, cid, name):
        """Container stopped — remove from all maps."""
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
        """Populate BPF container_map: pid → container display id."""
        try:
            containers = self.backend.list_containers()
            mapped = 0
            for cid, meta in containers:
                try:
                    # 全扫 /proc 找容器进程 (K8s/Docker 通用: cgroup 匹配)
                    pids = self._pids_in_cgroup(self.backend.cgroup_path(cid))
                except Exception:
                    continue
                display = meta.get('display', cid[:12])
                ContainerId = self.bpf['container_map'].Leaf
                entry = ContainerId()
                entry.id = display.encode('utf-8')
                for pid in pids:
                    self.bpf['container_map'][ct.c_uint32(pid)] = entry
                    mapped += 1
            # v0.6.3 (ADR-050 顺风车, 日志可读性): 只在启动首轮打印 —
            # 每 5s 刷新重复打印会把初始账号密码行等启动输出淹没
            # (v0.6.2.1 白屏排查实测: 148 行日志中 120+ 行是 PID map 刷屏)
            if not getattr(self, '_pid_map_first_print', False):
                print(f"  [Map] PID map: {mapped} processes "
                      f"across {len(containers)} containers")
                self._pid_map_first_print = True
        except Exception as e:
            print(f"  [!] PID map update failed: {e}", file=sys.stderr)

    @staticmethod
    def _pids_in_cgroup(cgroup_path):
        """cgroup scope 路径 → 容器内全部 PID (扫描 cgroup.procs / 子任务)。

        v0.5.5 修复: 之前忽略 cgroup_path 参数, 只要 /proc/<pid>/cgroup 含
        任意 cri-containerd/docker scope 就归入当前容器 → 每个容器分到全量
        容器进程, PID map 张冠李戴 (exec 进程标成别的容器/直接标 host)。
        现在按本容器的 scope 名精确匹配。
        """
        if not cgroup_path or not os.path.exists(cgroup_path):
            return []
        import re
        scope_name = os.path.basename(cgroup_path.rstrip('/'))
        if not re.match(r'(cri-containerd|docker)-[0-9a-f]{6,}\.scope',
                        scope_name):
            return []
        pids = []
        for pid_dir in os.listdir('/proc'):
            if not pid_dir.isdigit():
                continue
            try:
                with open(f"/proc/{pid_dir}/cgroup") as f:
                    content = f.read()
                if scope_name in content:
                    pids.append(int(pid_dir))
            except (FileNotFoundError, PermissionError):
                continue
        return pids

    def _build_cgroup_map(self):
        """Build cgroup_inode → (display_id, name) mapping.

        display_id: K8s 下是 ns/pod (可读), Docker 下是短 ID (兼容)。
        v0.5.5: 先建新表再原子换入 — 旧实现清空后重建, 事件回调并发读
        会看到空表, tier-1 cgroup 兜底失效 → 短命进程事件丢失。
        """
        new_map = {}
        new_id_to_name = {}
        new_short_to_display = {}
        try:
            for cid, meta in self.backend.list_containers():
                cgroup_path = self.backend.cgroup_path(cid)
                if cgroup_path and os.path.exists(cgroup_path):
                    inode = os.stat(cgroup_path).st_ino
                    short_id = cid[:12]
                    display = meta.get('display', short_id)
                    new_map[inode] = (display,
                                      meta.get('name', short_id))
                    new_id_to_name[display] = meta.get('name', short_id)
                    new_id_to_name[short_id] = meta.get('name', short_id)
                    new_short_to_display[short_id] = display
        except Exception as e:
            print(f"  [!] cgroup map build failed: {e}", file=sys.stderr)
        self.cgroup_map = new_map
        self._id_to_name = new_id_to_name
        self._short_to_display_map = new_short_to_display

    @staticmethod
    def _resolve_via_proc(pid: int) -> str:
        """Last-resort: read /proc/<pid>/cgroup."""
        try:
            with open(f"/proc/{pid}/cgroup", 'r') as f:
                for line in f:
                    # Docker: docker-<64id>.scope; K8s: cri-containerd-<64id>.scope
                    for prefix in ('docker-', 'cri-containerd-'):
                        if prefix in line and '.scope' in line:
                            start = line.index(prefix) + len(prefix)
                            end = line.index('.scope', start)
                            return line[start:end][:12]
        except (FileNotFoundError, PermissionError, ValueError,
                ProcessLookupError):
            pass
        return 'host'
