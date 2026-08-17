#!/usr/bin/env python3
"""网络隔离后端接口与实现 (v0.6.0) — ADR-043 蓝图落地。

IsolationBackend (ABC):
    isolate(ns, pod, pod_ip) -> bool   # 断该 pod 流量
    unisolate(ns, pod, pod_ip) -> bool  # 恢复

两个实现:
  - NsenterIptablesBackend: nsenter + 宿主 iptables FORWARD DROP (当前)
  - NetworkPolicyBackend: K8s NetworkPolicy deny-all (声明式, 见 k8s_network_policy.py)
"""
import os
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

    def _iptables_cmd(self) -> str:
        if self._in_cluster:
            return 'nsenter -t 1 -m -n iptables'
        return 'iptables'

    def isolate(self, ns: str, pod: str, pod_ip: str) -> bool:
        if not pod_ip:
            return False
        ipt = self._iptables_cmd()
        os.system(f"{ipt} -C FORWARD -s {pod_ip} -j DROP 2>/dev/null "
                  f"|| {ipt} -I FORWARD 1 -s {pod_ip} -j DROP")
        return True

    def unisolate(self, ns: str, pod: str, pod_ip: str) -> bool:
        if not pod_ip:
            return False
        ipt = self._iptables_cmd()
        os.system(f"{ipt} -D FORWARD -s {pod_ip} -j DROP 2>/dev/null")
        return True