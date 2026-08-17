#!/usr/bin/env python3
"""网络模式自主适配 (v0.6.0) — ADR-043 蓝图落地。

探测 K8s CNI 类型 → 自主选择隔离实现:
  flannel/unused  → NsenterIptablesBackend (nsenter 宿主 iptables, 当前实现)
  kube-router     → NetworkPolicyBackend (声明式, K8s API)
  calico          → NetworkPolicyBackend (声明式, K8s API)
  cilium          → NetworkPolicyBackend (声明式, K8s API)

detect_cni() 使用多信号表决:
  1. /etc/cni/net.d/ 配置文件名 (10-flannel.conflist / 10-calico.conflist)
  2. 宿主接口 (flannel.1 / tunl0 / cilium_host)
  3. iptables 链 (KUBE-ROUTER-FORWARD 存在 → kube-router)
"""
import os
import subprocess
from enum import Enum
from typing import Optional


class CNIMode(Enum):
    FLANNEL = "flannel"
    CALICO = "calico"
    KUBE_ROUTER = "kube-router"
    CILIUM = "cilium"
    UNKNOWN = "unknown"


def _check_cni_config() -> Optional[CNIMode]:
    """/etc/cni/net.d/ 配置文件名 → CNI 类型。"""
    conf_dir = "/etc/cni/net.d"
    if not os.path.isdir(conf_dir):
        return None
    try:
        for f in sorted(os.listdir(conf_dir)):
            low = f.lower()
            if "flannel" in low:
                return CNIMode.FLANNEL
            if "calico" in low:
                return CNIMode.CALICO
            if "cilium" in low:
                return CNIMode.CILIUM
    except PermissionError:
        pass
    return None


def _check_host_interfaces() -> Optional[CNIMode]:
    """宿主网络接口 → CNI 类型。"""
    try:
        with open("/proc/net/dev") as f:
            data = f.read()
    except (FileNotFoundError, PermissionError):
        return None
    if "flannel." in data:
        return CNIMode.FLANNEL
    if "tunl0" in data:  # calico IPIP
        return CNIMode.CALICO
    if "cilium_" in data:
        return CNIMode.CILIUM
    return None


def _check_iptables_chain() -> Optional[CNIMode]:
    """iptables 链 → kube-router (KUBE-ROUTER-FORWARD 唯一身份)。"""
    try:
        result = subprocess.run(
            ["iptables", "-L", "KUBE-ROUTER-FORWARD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return CNIMode.KUBE_ROUTER
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        pass
    return None


def detect_cni() -> CNIMode:
    """多信号表决: 配置文件名 + 接口 + iptables 链。"""
    # iptables 链是最高置信度信号 (kube-router 独有)
    mode = _check_iptables_chain()
    if mode:
        return mode

    # 配置文件 + 接口交叉验证
    conf_mode = _check_cni_config()
    iface_mode = _check_host_interfaces()

    if conf_mode and iface_mode:
        # 一致 → 返回; 矛盾 → 低置信度接口优先
        return conf_mode if conf_mode == iface_mode else iface_mode
    if conf_mode:
        return conf_mode
    if iface_mode:
        return iface_mode

    return CNIMode.UNKNOWN


def get_isolation_backend(cni_mode: Optional[CNIMode] = None):
    """根据 CNI 模式返回隔离后端。

    不传 cni_mode 时自动探测。
    """
    if cni_mode is None:
        cni_mode = detect_cni()

    if cni_mode in (CNIMode.CALICO, CNIMode.CILIUM, CNIMode.KUBE_ROUTER):
        from responder.k8s_network_policy import NetworkPolicyBackend
        return NetworkPolicyBackend()
    # FLANNEL / UNKNOWN → iptables
    from responder.isolation_backend import NsenterIptablesBackend
    return NsenterIptablesBackend()