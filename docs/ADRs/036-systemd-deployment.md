# ADR-036: systemd 部署形态与干净退出

## 状态
Accepted (v0.4.3)

## 背景
毕设"生产化部署"需要两种形态——集群内用 DaemonSet（v0.4.4 规划），但**政企隔离内网 / 边缘单机无 K8s 集群**（网信办/银行驻场场景），systemd 是唯一合理部署。systemd 化发现三个真实缺口：
- **XDP pin 不随进程退出自动 detach**：`bpftool prog load` 钉到 `/sys/fs/bpf/guard_xdp_block` + `net attach pinned`，pin 引用 + netdev 挂载独立于进程——进程退出后 XDP 阻断残留（tracepoint 走 libbpf fd 随退出自动卸载，XDP 不会）
- **cleanup_expired() 无调用方**：iptables 阻断"10min 过期自愈"实际不存在——停机必须主动 unblock
- main.py 原本只有 KeyboardInterrupt（SIGINT）清理，systemd stop 发 SIGTERM 完全不清理

## 验证过程
- systemctl start/stop×3 循环：stop 后 journald 显示 "Deactivated successfully"、`bpftool net show dev docker0` 为空、pin 文件消失、iptables FORWARD 无 guard 残留
- 首次 stop 循环出现瞬时 "failed" 状态——是 stop 后 2s 查询时服务仍在退出过程，最终日志 Deactivated successfully（瞬时状态误读，非 bug）

## 备选方案
- **方案 A**：SIGTERM handler 复用 SIGINT 路径（`signal.raise_signal(SIGINT)`）——零重复清理代码
- 方案 B：独立 SIGTERM handler 写全套清理——与 KeyboardInterrupt 重复
- 方案 C：ExecStop= 单独命令清理——绕过应用内清理，XDP/iptables 逻辑散落 service 文件

## 决策
选择方案 A + `_shutdown()`（幂等：identity/executor/ai stop + netblocker.detach + 全量 unblock + bpf.close）。systemd service `Type=simple / User=root / WorkingDirectory=项目根 / journald / on-failure / TimeoutStopSec=20`。SIGKILL 强杀仍可能残留 XDP——文档注明手动 detach 命令（可选 ExecStopPost 兜底）。

## 后果
- ✅ systemctl stop 干净退出（≤200ms，主线程 poll 返回后执行 handler）
- ✅ XDP/iptables 无残留（pin 生命周期 + 自愈缺失两个坑都被覆盖）
- ❌ SIGKILL 仍可能残留 XDP（文档注明手动清理命令）
- 📝 经验：eBPF 资源清理要区分生命周期——fd 随进程、pin 不随进程；压测暴露 guard 本体 PID 是 sudo 包装进程的子进程，`ps aux` 需取后者

## 关联
- [ADR-033](033-libbpf-core.md)：CO-RE 迁移，XDP attach 走 bpftool（pin 机制来源）
- [ADR-014](014-graded-automation.md)：阻断动作的可逆性设计（停机主动 unblock 的一致性）
- [ADR-037](037-performance-benchmark.md)：压测工具暴露的 PID/IO 经验
