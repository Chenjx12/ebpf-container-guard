# ADR-003: 探针方案从 kprobe 回退到 tracepoint

## 状态
Accepted (v0.1.1) · Superseded by [ADR-033](033-libbpf-core.md) (v0.4.1, CO-RE 迁移)

## 背景
真实特权容器测试中，`docker exec ... mount -t proc proc` 的事件捕获不到，但 runc 的 mount 事件正常。怀疑 kernel 6.8 下 mount 用了新 syscall 路径。

## 验证过程
单独用 kprobe 计数器测试：
- kprobe 能触发（0 → 22）
- 但 `PT_REGS_PARM` 读到的参数全空

## 备选方案
- **方案 A**：改用 kprobe `__x64_sys_mount` + `PT_REGS_PARM`（学习笔记 17-daemonset 的写法）
- **方案 B**：回退 tracepoint（v0.1.1 已验证 mount 逃逸检测成功）

## 决策
选择方案 B。实测 `PT_REGS_PARM` 在 kernel 6.8 syscall wrapper 下失效，kprobe 方案弃用并记录在 CHANGELOG。

## 后果
- ✅ 兼容性：tracepoint 在 kernel 5.15+ 稳定可用，参数结构由内核定义
- ❌ 灵活性：tracepoint 参数固定，无法像 kprobe 那样 hook 任意内核函数
- 📝 教训：内核版本差异是第一手经验，参考代码不一定适配当前内核。v0.4.1 迁移 CO-RE 后仍保留 tracepoint（见 ADR-033），kprobe 路线被彻底放弃

## 关联
- [ADR-033](033-libbpf-core.md)：CO-RE 迁移，supersede 本决策的 BCC 实现载体
- ADR-001（双仓库策略，预留）：学习笔记与产品仓库分离，本决策来源于学习笔记实验
