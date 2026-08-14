#!/usr/bin/env python3
"""kubeconfig 加载工具 (v0.5.3)。

DaemonSet 容器内: in_cluster (serviceaccount token);
宿主机调试: 回退 kubeconfig 文件。
"""
from kubernetes import config


def load_kubeconfig(kubeconfig="/etc/rancher/k3s/k3s.yaml"):
    """in_cluster 优先, 失败回退 kubeconfig 文件。"""
    try:
        config.load_incluster_config()
        return 'in_cluster'
    except Exception:
        config.load_kube_config(config_file=kubeconfig)
        return 'kubeconfig'
