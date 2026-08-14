# ADR-042: DaemonSet 容器化部署——in_cluster + 降级

## 状态
Accepted (v0.5.3)

## 背景
K8s 适配三件套最后一环——guard 容器化成 DaemonSet 上 k3s。容器环境与宿主机差异：无 docker.sock、无 iptables（netns 隔离）、无 k3s.yaml（kubeconfig）。

## 验证过程
- DaemonSet pod Running；in_cluster 生效（K8sBackend k8s_mode=True）
- **容器化 E2E**：esc-deploy pod 挂 procfs → procfs_mount_escape → FROZEN + `cannot exec in a paused container`（真冻结，与宿主机一致）→ 解冻恢复
- 降级生效：`[NetBlock] (no-op) 容器内无 iptables`
- 发现：容器内 kubectl exec 的 /bin/sh 进程 cgroup 与主容器不同 scope（freeze 按主容器 ID 定位的延续）

## 备选方案
- **in_cluster**：serviceaccount 优先 + kubeconfig 回退（统一 kube_utils.py）vs 只 in_cluster（宿主机调试崩）→ 前者
- **iptables**：容器内 COPY iptables + nsenter 进宿主 netns vs 降级 annotation-only/no-op → **降级**（COPY 链脆弱 + netns 语义复杂，符合 ADR-041 降级路径）
- **日志**：/app/logs hostPath 持久化 vs emptyDir vs subPath 文件挂载 → **目录挂载**（subPath 文件挂载有"文件变目录"坑）

## 决策
采用：in_cluster kubeconfig（kube_utils.py 统一）；iptables 降级（isolate→annotation-only、netblock→no-op，C2 阻断由部署者处理）；日志 /app/logs → hostPath /var/lib/ebpf-guard；Docker responder 延迟到 runtime 探测后初始化（容器内无 docker.sock 会 sys.exit）。

## 后果
- ✅ guard 完整容器化部署到 k3s（检测→响应闭环在容器内工作）
- ✅ 双轨不破坏（宿主机 kubeconfig 回退仍可调试）；日志宿主机可见（毕设演示）
- ❌ 容器化 isolate 降级（iptables 实际阻断需部署者/未来 v0.5.4）
- ❌ k3s 部署流程依赖 docker build --network host + ctr import（网络受限环境）
- 📝 密钥红线重申：configmap 曾误含 AI key 已移除（Secret 或省略）

## 关联
- [ADR-040](040-k8s-runtime-backend.md)：RuntimeBackend 双轨（容器化的检测基础）
- [ADR-041](041-k8s-responder.md)：动作映射与降级路径（isolate 降级的依据）
- [ADR-039](039-single-instance-lock.md)：部署形态互斥（DaemonSet 是集群形态）
