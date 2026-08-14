# ADR-043: 网络阻断补全——nsenter 宿主 iptables + 网络模式适配蓝图

## 状态
Accepted (v0.5.4)

## 背景
v0.5.3 容器化 guard 的 isolate 降级为 annotation-only（容器内无 iptables + netns 隔离）。用户追问"完全没办法控制网络流量吗"——实际有解法，需补全真实阻断。

## 验证过程
- **容器内跑宿主 iptables 二进制失败**：glibc 不兼容（宿主 2.38 vs 容器 python 镜像）——挂载宿主 /usr/sbin 或 /lib 会覆盖容器 libc（python 起不来）或动态链接失败
- **nsenter -t 1 -m -n 验证成功**：进宿主 mount+netns 用宿主的 iptables，容器内能看到宿主 FORWARD 链（KUBE-ROUTER 规则可见）
- **隔离真实生效**：`ISOLATED (iptables DROP 10.42.x)` 规则真插进宿主 FORWARD 链
- k3s flannel 无 NetworkPolicy controller；换 kube-router 需重启集群（动生产，留未来）

## 备选方案
- **A（选中）**：hostNetwork: true + nsenter -t 1 -m -n iptables——容器共享宿主 netns，用宿主环境执行宿主 iptables
- C：挂载宿主 iptables 二进制到容器——glibc 不兼容失败
- B：NetworkPolicy（kube-router）——声明式正统，但需重启集群 + 会接管 iptables 清 guard 规则，留未来

## 决策
采用 A：daemonset `hostNetwork: true`；k8s_responder 与 netblocker 统一用 `nsenter -t 1 -m -n iptables`（容器内检测 serviceaccount 存在则用 nsenter，宿主机直接 iptables）。**B 作为蓝图**（`src/core/netpol_detect.py` 设计）：探测 CNI → flannel 用 iptables / kube-router/calico 用 NetworkPolicy，未来以 IsolationBackend 接口切换。

## 后果
- ✅ 容器化 guard 的 isolate 真实断网（iptables DROP 进宿主链）
- ✅ 蓝图设计：自主发现网络模式、自主适配隔离实现（毕设答辩点）
- ❌ hostNetwork 让 guard 暴露宿主网络（特权监控工具可接受）
- ❌ kube-router 未来接管会清 guard 规则（降级路径保留）
- 📝 宿主二进制容器化 = glibc 兼容坑，nsenter -m 用宿主环境规避

## 关联
- [ADR-041](041-k8s-responder.md)：isolate 动作（本决策补全其容器化实现）
- [ADR-042](042-daemonset-deployment.md)：容器化部署（isolate 降级的背景）
- [ADR-024](024-xdp-ingress-limit.md)：XDP 语义限制（K8s 下用 iptables 的原因）
