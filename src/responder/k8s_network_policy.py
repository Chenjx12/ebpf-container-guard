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
        self._core_v1 = client.CoreV1Api()
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
                    # v0.6.3 (ADR-050): 完整 pod 名入库 — 策略名仅取 pod[:63]
                    # 会截断 (pod 名可 >63), 清扫器靠注解精确判定 pod 是否仍存在
                    "guard/pod": pod,
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

    def sweep_orphaned(self) -> int:
        """v0.6.3 (ADR-050 顺风车 2): 回收已销毁 pod 的 guard 隔离 netpol。

        泄漏场景: 容器在隔离状态下被销毁（无 unisolate 调用）— deny-all
        netpol 残留, 该命名空间下同名 pod 名段持续被拒。清扫按
        managed-by 标签 + guard/pod 注解精确判定, 30s 周期由 responder 调用。
        """
        deleted = 0
        try:
            policies = self._networking_v1 \
                .list_network_policy_for_all_namespaces(
                    label_selector="managed-by=ebpf-container-guard").items
        except Exception as e:
            print(f"  [NetPolSweep] 列表失败: {e}", file=__import__('sys').stderr)
            return 0
        for p in policies:
            ns = p.metadata.namespace
            pod = (p.metadata.annotations or {}).get("guard/pod")
            if not pod:
                # 旧版本策略无注解 — 从名字前缀推断 (可能截断, 尽力而为)
                name = p.metadata.name or ""
                if name.startswith("guard-isolate-"):
                    pod = name[len("guard-isolate-"):]
                else:
                    continue
            # pod 仍在 → 跳过; pod 已不存在 (404) → 回收
            try:
                self._core_v1.read_namespaced_pod(name=pod, namespace=ns)
                continue
            except client.rest.ApiException as e:
                if e.status != 404:
                    continue
            except Exception:
                continue
            try:
                self._networking_v1.delete_namespaced_network_policy(
                    name=p.metadata.name, namespace=ns)
                self._isolated.discard((ns, pod))
                deleted += 1
                print(f"  [NetPolSweep] 回收孤儿隔离策略 {ns}/{p.metadata.name} "
                      f"(pod {pod} 已销毁)")
            except Exception as e:
                print(f"  [NetPolSweep] 删除失败 {ns}/{p.metadata.name}: {e}",
                      file=__import__('sys').stderr)
        return deleted