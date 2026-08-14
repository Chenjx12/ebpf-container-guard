#!/usr/bin/env python3
"""网络模式自主适配蓝图 (v0.5.4 设计, 不实现 B)。

探测 K8s CNI 类型 → 自主选择隔离实现:
  flannel     → guard 用 nsenter 插宿主 iptables (当前实现, v0.5.4)
  kube-router → NetworkPolicy (声明式, controller 执行)
  calico      → NetworkPolicy (声明式, controller 执行)

未来 v0.5.5+ 实现: 隔离后端 (IsolationBackend) 按此探测结果切换。

设计:
  IsolationBackend (接口):
    isolate(ns, pod, pod_ip) -> bool   # 断该 pod 流量
    unisolate(ns, pod, pod_ip) -> bool # 恢复

  NsenterIptablesBackend (当前, v0.5.4):
    cmd = "nsenter -t 1 -m -n iptables"  # 宿主 netns + mount
    isolate: -I FORWARD 1 -s <pod_ip> -j DROP

  NetworkPolicyBackend (未来, kube-router/calico):
    create NamespacedNetworkPolicy(deny-all + 白名单) # 声明式

  detect_cni() -> "flannel" | "kube-router" | "calico" | "unknown":
    1. /etc/cni/net.d/ 配置文件名 (10-flannel.conflist / 10-calico.conflist)
    2. 宿主接口 (flannel.1 / tunl0)
    3. iptables 链 (KUBE-ROUTER-FORWARD 存在 → kube-router)
"""
