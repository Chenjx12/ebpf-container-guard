#!/usr/bin/env python3
"""
主动防御响应引擎 - 基于Docker SDK
对应笔记: Nine、主动防御:从检测到自动响应
"""
import docker
import yaml
import sys
import os
import signal
import time
import json
from datetime import datetime


class ResponseEngine:
    """主动防御响应引擎"""
    
    def __init__(self, responses_file='responses.yaml'):
        # 加载响应策略配置
        with open(responses_file, 'r') as f:
            self.config = yaml.safe_load(f).get('responses', [])
        
        # 建立威胁等级 → 动作映射表
        self.policy = {}
        for rule in self.config:
            self.policy[rule['threat_level']] = rule['action']
        
        # 初始化Docker客户端
        try:
            self.docker_client = docker.from_env()
            print(f"[ResponseEngine] 已加载 {len(self.policy)} 条响应策略")
        except docker.errors.DockerException as e:
            print(f"[!] Docker连接失败: {e}", file=sys.stderr)
            sys.exit(1)
        
        # 冷却时间机制（防止重复响应）
        self.cooldown = {}  # container_id → last_response_time
        self.cooldown_period = 600  # 10分钟冷却
    
    def _resolve_container_id(self, container_id, pid):
        """当 PID 映射表未命中时，通过 /proc/<pid>/cgroup 反查容器 ID"""
        if container_id not in ['', 'host', 'unknown']:
            return container_id

        cgroup_path = f"/proc/{pid}/cgroup"
        try:
            with open(cgroup_path, 'r') as f:
                for line in f:
                    # Docker 容器 cgroup 路径格式:
                    # 0::/system.slice/docker-<64-char-id>.scope/...
                    if 'docker-' in line and '.scope' in line:
                        start = line.index('docker-') + 7
                        end = line.index('.scope', start)
                        full_id = line[start:end]
                        return full_id[:12]  # 返回短ID
        except (FileNotFoundError, PermissionError):
            pass
        return container_id  # 无法解析，返回原值

    def handle_alert(self, alert):
        """处理告警事件,执行自动响应"""
        severity = alert.get('severity', 'LOW').lower()
        container_id = alert['event'].get('container_id', '')
        event_pid = alert['event'].get('pid', 0)

        # 尝试通过 cgroup 反查容器 ID（处理 PID 映射表过期的边界情况）
        container_id = self._resolve_container_id(container_id, event_pid)

        # 跳过宿主机进程
        if container_id in ['', 'host', 'unknown']:
            print(f"[INFO] 跳过宿主机事件(PID={event_pid}),不执行响应")
            return
        
        # 检查冷却时间
        now = time.time()
        if container_id in self.cooldown:
            last_time = self.cooldown[container_id]
            if now - last_time < self.cooldown_period:
                remaining = int(self.cooldown_period - (now - last_time))
                print(f"[SKIP] 容器 {container_id[:12]} 在冷却期内 (剩余{remaining}秒)")
                return
        
        # 获取对应的响应动作
        action = self.policy.get(severity, 'log_only')
        
        print(f"\n🛡️  [RESPONSE] 触发自动防御: {severity.upper()} → {action}")
        
        # 执行响应动作
        try:
            if action == 'pause_container':
                self.pause_container(container_id)
            elif action == 'isolate_network':
                self.isolate_network(container_id)
            elif action == 'kill_process':
                self.kill_process(container_id, alert['event']['pid'])
            elif action == 'kill_container':
                self.kill_container(container_id)
            elif action == 'log_only':
                self.log_only(alert)
            
            # 记录冷却时间
            self.cooldown[container_id] = now
            
        except Exception as e:
            print(f"[ERROR] 响应执行失败: {e}", file=sys.stderr)
    
    def pause_container(self, container_id):
        """冻结容器(推荐用于CRITICAL级别,保留取证现场)"""
        try:
            container = self.docker_client.containers.get(container_id)
            container.pause()
            print(f"✅ Container {container_id[:12]} PAUSED - 已冻结,等待人工取证")
            
            # 写入审计日志
            self._audit_log(container_id, "PAUSE", "Container frozen for forensics")
        except docker.errors.APIError as e:
            print(f"❌ 冻结容器失败: {e}")
    
    def isolate_network(self, container_id):
        """断网隔离(阻止C2回连或横向移动)"""
        try:
            container = self.docker_client.containers.get(container_id)
            networks = container.attrs['NetworkSettings']['Networks']
            disconnected = []
            failed = []

            for network_name in list(networks.keys()):
                if network_name == 'none':
                    continue
                try:
                    container.disconnect(network_name)
                    disconnected.append(network_name)
                    print(f"✅ Container {container_id[:12]} DISCONNECTED from {network_name}")
                except docker.errors.APIError as e:
                    failed.append(f"{network_name}: {e}")

            if disconnected:
                self._audit_log(container_id, "ISOLATE", f"Disconnected: {disconnected}")
            if failed:
                print(f"⚠️  部分网络断开失败: {'; '.join(failed)}")
                # 即使部分失败也算完成，至少尝试过了
        except docker.errors.APIError as e:
            print(f"❌ 断网隔离失败: {e}")
    
    def kill_process(self, container_id, pid):
        """终止可疑进程(中等威胁级别)

        注意: eBPF 捕获的 pid 是宿主机 PID。
        由于本系统运行在宿主机上，直接用 os.kill() 发信号即可，
        避免 docker exec 在容器 PID namespace 中找不到进程的问题。
        """
        try:
            # 先尝试优雅终止(SIGTERM)，1秒后强制 SIGKILL
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            try:
                os.kill(pid, 0)  # 检查进程是否还活着
                os.kill(pid, signal.SIGKILL)  # 还在，强制干掉
                print(f"🔥 Process {pid} FORCE KILLED (SIGKILL)")
            except ProcessLookupError:
                print(f"✅ Process {pid} TERMINATED (SIGTERM)")

            self._audit_log(container_id, "KILL_PROCESS", f"Process {pid} terminated")
        except ProcessLookupError:
            print(f"⚠️  Process {pid} 不存在或已退出")
        except PermissionError as e:
            print(f"❌ 权限不足，无法终止进程 {pid}: {e}")
    
    def kill_container(self, container_id):
        """杀死整个容器(最高威胁级别)"""
        try:
            container = self.docker_client.containers.get(container_id)
            container.kill()
            print(f"🔥 Container {container_id[:12]} KILLED - 容器已终止")
            
            # 写入审计日志
            self._audit_log(container_id, "KILL_CONTAINER", "Container killed")
        except docker.errors.APIError as e:
            print(f"❌ 杀死容器失败: {e}")
    
    def log_only(self, alert):
        """仅记录审计日志"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'severity': alert['severity'],
            'rule': alert['rule_name'],
            'description': alert['description'],
            'container': alert['event'].get('container_id', 'unknown'),
            'process': alert['event'].get('comm', 'unknown'),
            'pid': alert['event'].get('pid', 'unknown')
        }
        
        # 追加到审计日志文件
        with open('audit.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        print(f"📝 AUDIT LOG written to audit.log")
    
    def _audit_log(self, container_id, action, details):
        """写入结构化审计日志"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'container_id': container_id,
            'action': action,
            'details': details
        }
        
        with open('response_audit.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')


def print_response_banner(severity, action):
    """打印响应横幅(视觉效果)"""
    colors = {
        'critical': '\033[101m',  # 红色背景
        'high': '\033[91m',       # 红色前景
        'medium': '\033[93m',     # 黄色
        'low': '\033[94m'         # 蓝色
    }
    RESET = '\033[0m'
    color = colors.get(severity.lower(), RESET)
    
    print(f"\n{color}{'═' * 60}")
    print(f"🛡️  自动防御激活: {severity.upper()} → {action}")
    print(f"{'═' * 60}{RESET}\n")
