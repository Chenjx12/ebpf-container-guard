# 3 VM 多节点演示环境搭建指南（v0.5.7）

本指南搭建 3 台虚拟机（Debian / Ubuntu / Kali）组成的**多节点 k3s 集群**，
用于演示 eBPF Container Guard 的**容器化部署跑在任何环境**能力：
- manager 节点运行 guard DaemonSet（自动铺满所有节点）
- Kali 作为攻击者在宿主机发起攻击 → 跨节点产生告警
- 资产管理页面按**节点/物理机**展示资产分组

## 1. 3 台 VM 准备

| VM | 系统 | 角色 | IP（示例） |
|----|------|------|-----------|
| vm1 | Debian 12 | k3s manager（control-plane）| 192.168.56.11 |
| vm2 | Ubuntu 22.04 | k3s worker | 192.168.56.12 |
| vm3 | Kali Linux | k3s worker + 攻击者 | 192.168.56.13 |

每台 VM 要求：
- 2 CPU / 2GB 内存 / 20GB 磁盘（k3s 轻量，够用）
- 网络互通（VMware NAT 或 host-only 网段）
- 能访问外网（装 k3s + 拉镜像；内网环境可离线导入，见第 4 节）

## 2. k3s 多节点集群

### manager 节点（vm1）

```bash
curl -sfL https://get.k3s.io | sh -
# 拿 join 信息
sudo cat /var/lib/rancher/k3s/server/node-token
sudo cat /etc/rancher/k3s/k3s.yaml
```

### worker 节点（vm2 / vm3）

```bash
# TOKEN = manager 的 node-token; SERVER = https://192.168.56.11:6443
curl -sfL https://get.k3s.io | K3S_URL="$SERVER" K3S_TOKEN="$TOKEN" sh -
```

### 验证

```bash
# manager 上
kubectl get nodes
# 期望 3 个节点 Ready (vm1 control-plane, vm2/vm3 worker)
kubectl get pods -A   # coredns/traefik/metrics-server 等系统组件
```

## 3. 部署 guard（DaemonSet）

### 构建镜像（任一台有 docker 的机器）

```bash
cd ebpf-container-guard
make build                    # 编译 CO-RE eBPF 对象
docker build --network host -f deploy/Dockerfile.guard -t ebpf-guard:v0.5.7 .
```

### 导入镜像到每个节点

k3s 用 containerd，每台节点都要有镜像：

```bash
# 方法 A: 每节点手动导入
docker save ebpf-guard:v0.5.7 -o /tmp/guard.tar
scp /tmp/guard.tar vm1:/tmp/ && ssh vm1 'sudo k3s ctr images import /tmp/guard.tar'
# 重复到 vm2/vm3

# 方法 B: 私有 registry (镜像多时推荐)
docker tag ebpf-guard:v0.5.7 registry.local:5000/ebpf-guard:v0.5.7 && docker push ...
# 各节点 k3s 配置 containerd 信任该 registry (或 /etc/rancher/k3s/registries.yaml)
```

### 部署清单

```bash
# manager 上, 先配 kubeconfig
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl apply -f deploy/k8s/
```

- **configmap.yaml**：规则/响应/监控配置 + AI 配置模板
- **rbac.yaml**：ServiceAccount + ClusterRole（pods 读删等）
- **daemonset.yaml**：guard 容器（hostPID + hostNetwork + privileged + /sys 挂载）
  - 注意：daemonset 里 image tag 需改为 `ebpf-guard:v0.5.7`（默认是开发 tag）
- **Secret（AI key，可选）**：
  ```bash
  kubectl create secret generic ebpf-guard-ai \
    --from-literal=api_key="sk-你的DeepSeekKey" -n kube-system
  # daemonset 已配 secretKeyRef 注入 AI_API_KEY
  ```

### 验证

```bash
kubectl get pods -n kube-system -l app=ebpf-guard -o wide
# 期望每节点 1 个 guard pod (共 3 个, 分布在 vm1/vm2/vm3)
kubectl logs -n kube-system ds/ebpf-guard --tail=5
# 期望 "6 probes | 12 rules" + "API key configured" (配了 Secret 时)
```

## 4. 部署面板（连集群）

面板（server/）可跑在任一节点或单独机器，只需能连集群 API：

```bash
# 拷贝集群 kubeconfig 到面板运行用户 (面板进程需可读 + 有 list pods/services 权限)
ssh vm1 'sudo cat /etc/rancher/k3s/k3s.yaml' > ~/.kube/config
# 改 server 地址为 manager IP (k3s.yaml 默认 127.0.0.1)
sed -i 's/127.0.0.1/192.168.56.11/' ~/.kube/config

# 启动面板 (单 worker, 内存 session)
cd ebpf-container-guard
pip install -r requirements.txt
GUARD_LOGS_DIR=/var/lib/ebpf-guard \
  python3 -m uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 1
# → 浏览器 http://<面板机IP>:8000, admin/初始密码见终端
```

> GUARD_LOGS_DIR 指向 guard 写日志的 hostPath 目录：若面板和 guard 同机（如跑在 vm1），
> 直接指向 /var/lib/ebpf-guard；若面板在单独机器，需共享该目录（NFS/挂载）或
> 只读事件展示（判决联动需写权限）。

## 5. 演示验证

1. **资产管理页**：侧边栏 → 资产管理 → 显示 **3 个节点分组**（vm1/vm2/vm3），
   每组是该节点的 pod 列表 + 服务暴露表
2. **Kali 攻击**：vm3（Kali）上对集群/业务发起攻击
   （如尝试逃逸：`kubectl run esc --image=... --privileged` 或容器内读 /etc/shadow）
3. **告警**：guard 检测 → 面板告警流出现事件（容器画像显示该 pod 在 vm3）
4. **AI 研判**：配置了 Secret 后，事件详情弹窗显示 DeepSeek 研判结果
5. **跨节点**：攻击 pod 调度到不同节点，资产页对应分组出现

## 6. k3s → 标准 k8s 兼容性

本系统**兼容标准 k8s（kubeadm/k3s/任意发行版）**，k3s 特定适配仅：

| 项 | k3s | 标准 k8s (kubeadm) | 处理 |
|----|-----|---------------------|------|
| kubeconfig 路径 | `/etc/rancher/k3s/k3s.yaml` | `/etc/kubernetes/admin.conf` | `load_kubeconfig` 已支持传参 / `KUBECONFIG` env |
| 镜像导入 | `k3s ctr images import` | `crictl images import` / registry | 文档命令替换 |
| cgroup 路径 | `kubepods.slice/cri-containerd-*.scope` | 相同（containerd 标准）| 无需改 |
| 网络隔离 | nsenter iptables（flannel）| Calico/kube-router 时换实现 | 属网络适配蓝图（netpol_detect）|

**结论**：guard DaemonSet / RBAC / configmap / 面板 / 资产页面全部复用，无需改代码；
仅 kubeconfig 路径与网络隔离后端需小适配。

## 7. 常见问题

- **worker 加入失败**：检查 6443 端口互通（`nc -vz <manager> 6443`）+ token 正确
- **guard 镜像拉不到**：k3s imagePullPolicy=Never（daemonset 已设），确认每节点已导入
- **面板连不上集群**：kubeconfig server 地址是否改为 manager 对外 IP；~/.kube/config 权限 600
- **资产页只有 1 节点**：确认 3 个节点都 Ready（`kubectl get nodes`），DaemonSet 跑满
