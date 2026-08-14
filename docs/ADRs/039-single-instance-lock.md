# ADR-039: 单实例锁——部署形态互斥的基础

## 状态
Accepted (v0.5.0)

## 背景
v0.4.3 systemd 部署发布后，发现 systemd 与未来 K8s DaemonSet 是**互斥部署形态**——同时跑会互相打架（XDP 同网卡排他、日志同路径交错、iptables 覆盖、eBPF 事件重复）。且存量有双启动隐患：run.sh 用 pkill（不可靠）、systemd Type=simple 同服务双 start 需验证、手动/systemd 跨方式互撞。

## 验证过程
- 第一实例持锁运行，第二实例拒绝（exit 0）
- **systemd 同服务双 start 是 no-op**（Type=simple 已在 active 不再启动）——systemd 层面自身防同服务双启动
- **跨方式互斥**：systemd guard 在跑时手动起第二个 → 被拒（单实例锁的核心价值）
- systemctl stop 后锁释放（flock 语义），可重启
- 发现：flock 锁文件由 systemd 进程持有时 ps 看不到进程但锁有效（cgroup 隔离）

## 备选方案
- **方案 A（选中）**：`fcntl.flock` 抢 `/var/run/ebpf-guard.pid`——**不判断部署形态**（任何 guard 在跑就拒绝），run.sh/systemd/DaemonSet 统一互斥
- 方案 B：启动时检测"是否 systemd 环境"再决定互斥逻辑——复杂且脆弱（判断部署形态本身不可靠）
- 方案 C：各启动方式各自防（run.sh pkill + systemd 依赖 + K8s 单例）——分散且漏跨方式

## 决策
采用方案 A。抢锁失败打印"另一实例已在运行"并 **exit 0**——不触发 systemd `Restart=on-failure` 死循环（若 exit 非 0，systemd 会反复重启抢锁失败的实例，死循环）。锁随进程退出自动释放。

## 后果
- ✅ 三种启动方式统一互斥；防 run.sh pkill 不可靠、systemd 双启动、systemd/DaemonSet 跨方式互撞
- ✅ K8s DaemonSet 部署时是"部署形态互斥"的基础机制（同节点残留 systemd guard 被锁挡住）
- ❌ 锁文件需 /var/run 可写（root 权限已有）；锁文件残留无害（flock 持锁不依赖文件内容）
- 📝 螺旋式上升：新功能（部署形态互斥基础）+ 顺手修复存量坑

## 关联
- [ADR-036](036-systemd-deployment.md)：systemd 部署形态（本决策的互斥对象之一）
- [ADR-033](033-libbpf-core.md)：CO-RE 迁移，XDP attach 机制（双实例冲突点之一）
- [ADR-014](014-graded-automation.md)：部署可靠性设计的一致性
