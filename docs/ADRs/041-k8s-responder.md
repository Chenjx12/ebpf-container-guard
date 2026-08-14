# ADR-041: K8s responder——动作映射与降级

## 状态
Accepted (v0.5.2)

## 背景
v0.5.1 K8s 模式检测→响应闭环缺失（响应 no-op）。K8s 没有 Docker 的 pause/disconnect 直接等价，需要设计动作映射，同时守住 ADR-040 承诺（Docker 6 E2E 零改动）。

## 验证过程
- **cgroup.freeze 写入验证成功**（内核 v2 freezer 可写，与 docker pause 同机制）
- **esc-test2 pod 读 /etc/shadow** → sensitive_file_access → isolate_network → **iptables FORWARD DROP 10.42.0.41 + annotation guard/isolated 生效**
- **身份冷启动窗口发现**：新 pod 事件用短 ID → responder 无法解析 ns/pod → `_short_to_display` 加 backend 兜底
- **Docker mount 场景回归通过**（双轨不破坏）

## 备选方案
- **pause 等价**：cgroup.freeze（与 docker pause 同机制，可逆）vs SIGSTOP（需枚举 pid，脆）vs scale 0（丢现场）→ **cgroup.freeze**
- **isolate 等价**：iptables FORWARD DROP Pod IP（现可用）vs NetworkPolicy deny-all（需 kube-router 未启用）→ **iptables 先行，NetPolicy 留待启用后**
- **架构**：双轨并行（k8s_responder 同接口）vs main.py 分支（动作方法变长）→ **双轨**

## 决策
采用双轨并行。动作映射：pause→cgroup.freeze + annotation；isolate→iptables FORWARD DROP Pod IP + annotation；kill_process→原样保留（宿主 os.kill）；kill_container→delete pod（Deployment/RS 先 scale 0 防控制器秒级重建）；block_image 仅记录+队列（admission webhook 留 v0.5.3）。IRREVERSIBLE_ACTIONS 判定保留（ADR-014）。**XDP 在 K8s 禁用**（docker0 不存在 + -s Pod IP 语义不符）→ 强制 iptables。

## 后果
- ✅ K8s 检测→响应闭环（isolate 实测生效）；Docker 6 E2E 零改动
- ✅ 可逆/不可逆区分保留（人工队列）
- ❌ NetworkPolicy 未启用（kube-router 需重启）；kube-router 启用后 iptables 规则可能被清（降级 annotation-only + 提示）
- ❌ block_image 在 K8s 仅记录（镜像拉黑需 admission webhook，v0.5.3）
- 📝 K8s 无 pause 的洞察：cgroup.freeze 是与 docker pause 同机制的优雅替代（同走 v2 freezer）

## 关联
- [ADR-040](040-k8s-runtime-backend.md)：RuntimeBackend 双轨（本决策的容器发现基础）
- [ADR-014](014-graded-automation.md)：分级自动化（可逆自动/不可逆人工）
- [ADR-024](024-xdp-ingress-limit.md)：XDP 语义限制（K8s 下禁用原因）
