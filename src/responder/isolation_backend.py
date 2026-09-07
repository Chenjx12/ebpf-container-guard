#!/usr/bin/env python3
"""网络隔离后端接口与实现 (v0.6.0) — ADR-043 蓝图落地。

IsolationBackend (ABC):
    isolate(ns, pod, pod_ip) -> bool   # 断该 pod 流量
    unisolate(ns, pod, pod_ip) -> bool  # 恢复

两个实现:
  - NsenterIptablesBackend: nsenter + 宿主 iptables FORWARD DROP (当前)
  - NetworkPolicyBackend: K8s NetworkPolicy deny-all (声明式, 见 k8s_network_policy.py)

v0.6.4 (审查修复 H2): os.system 裸调用 → subprocess.run(shell=False) 列表参数,
返回真实执行状态 — 不再"iptables 失败仍报隔离成功"的静默失败。
"""
import os
import subprocess
import sys
from abc import ABC, abstractmethod


class IsolationBackend(ABC):
    """网络隔离后端接口。"""

    @abstractmethod
    def isolate(self, ns: str, pod: str, pod_ip: str) -> bool:
        ...

    @abstractmethod
    def unisolate(self, ns: str, pod: str, pod_ip: str) -> bool:
        ...


class NsenterIptablesBackend(IsolationBackend):
    """nsenter + 宿主 iptables FORWARD DROP (当前实现, v0.5.4)。

    容器内 (in_cluster): nsenter -t 1 -m -n iptables (宿主 glibc 兼容);
    宿主机: 直接 iptables (PATH)。
    """

    def __init__(self):
        self._in_cluster = os.path.exists(
            '/var/run/secrets/kubernetes.io/serviceaccount')

    def _argv(self, *args) -> list:
        """构建 iptables argv — 容器内加 nsenter 前缀, 全部列表化 (无 shell)。"""
        if self._in_cluster:
            return ['nsenter', '-t', '1', '-m', '-n', 'iptables', *args]
        return ['iptables', *args]

    def _run(self, argv: list) -> bool:
        """执行 iptables argv。返回真实执行结果; 失败向 stderr 输出可操作告警。"""
        try:
            subprocess.run(argv, check=True, capture_output=True, timeout=10)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                OSError) as e:
            print(f"  [!] Isolation 命令失败: {' '.join(argv)} — {e}",
                  file=sys.stderr)
            return False

    def _rule_exists(self, pod_ip: str) -> bool:
        """-C 探测 FORWARD DROP 规则是否已存在 (幂等判断)。"""
        return self._run(self._argv('-C', 'FORWARD', '-s', pod_ip,
                                    '-j', 'DROP'))

    def isolate(self, ns: str, pod: str, pod_ip: str) -> bool:
        """断该 pod 流量。返回 True 仅当规则确认生效 (已存在或新插入)。"""
        if not pod_ip:
            return False
        if self._rule_exists(pod_ip):
            return True  # 已隔离 (幂等)
        return self._run(self._argv('-I', 'FORWARD', '1', '-s', pod_ip,
                                    '-j', 'DROP'))

    def unisolate(self, ns: str, pod: str, pod_ip: str) -> bool:
        """恢复流量。规则不存在视为已恢复 (幂等)。"""
        if not pod_ip:
            return False
        if not self._rule_exists(pod_ip):
            return True  # 已恢复 (幂等)
        return self._run(self._argv('-D', 'FORWARD', '-s', pod_ip,
                                    '-j', 'DROP'))
