#!/usr/bin/env python3
"""K8s NetworkPolicy 隔离后端 (v0.6.0) — ADR-043 蓝图落地。

NetworkPolicyBackend:
  - isolate: 创建 deny-all NetworkPolicy (Ingress+Egress 空列表 = 拒绝全部)
  - unisolate: 删除 NetworkPolicy

异常降级: API 失败 → fallback NsenterIptablesBackend。
"""
from datetime import datetime
from kubernetes import client

from core.kube_utils import load_kubeconfig
from responder.isolation_backend import IsolationBackend, NsenterIptablesBackend


class NetworkPolicyBackend(IsolationBackend):
    """基于 K8s NetworkPolicy 的声明式持久化隔离。"""

    def __init__(self, kubeconfig="/etc/rancher/k3s/k3s.yaml"):
        load_kubeconfig(kubeconfig)
        self._networking_v1 = client.NetworkingV1Api()
        self._fallback = NsenterIptablesBackend()
        self._isolated: set = set()  # {(ns, pod)} 去重

    def isolate(self, ns: str, pod: str, pod_ip: str) -> bool:
        key = (ns, pod)
        if key in self._isolated:
            return True  # 已隔离

        policy_name = f"guard-isolate-{pod[:63]}"
        policy = client.NetworkingV1NetworkPolicy(
            api_version="networking.k8s.io/v1",
            kind="NetworkPolicy",
            metadata=client.V1ObjectMeta(
                name=policy_name[:253],  # K8s 名称上限 253
                labels={
                    "managed-by": "ebpf-container-guard",
                    "guard/action": "isolate",
                    "guard/version": "0.6.0",
                },
                annotations={
                    "guard/created-at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%SZ"),
                    "guard/restore-hint":
                        f"kubectl delete networkpolicy {policy_name[:253]} -n {ns}",
                }
            ),
            spec=client.NetworkingV1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(
                    match_labels={"app": pod}  # 精确匹配目标 pod
                ),
                policy_types=["Ingress", "Egress"],
                ingress=[],   # 空列表 = 拒绝所有入站
                egress=[],    # 空列表 = 拒绝所有出站
            )
        )
        try:
            self._networking_v1.create_namespaced_network_policy(
                namespace=ns, body=policy)
            self._isolated.add(key)
            return True
        except client.rest.ApiException as e:
            print(f"[NetworkPolicy] 创建失败 ({e.status}): "
                  f"降级到 iptables")
            return self._fallback.isolate(ns, pod, pod_ip)

    def unisolate(self, ns: str, pod: str, pod_ip: str) -> bool:
        key = (ns, pod)
        policy_name = f"guard-isolate-{pod[:63]}"
        try:
            self._networking_v1.delete_namespaced_network_policy(
                name=policy_name[:253], namespace=ns)
            self._isolated.discard(key)
            return True
        except client.rest.ApiException as e:
            if e.status == 404:
                self._isolated.discard(key)
                return True  # 已不存在
            return self._fallback.unisolate(ns, pod, pod_ip)