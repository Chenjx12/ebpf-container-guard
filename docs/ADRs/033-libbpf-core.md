# ADR-033: BCC → libbpf CO-RE 迁移

## 状态
Accepted (v0.4.1)

## 背景
规划新探针（cgroup 写入检测、capset）时，在 BCC 里扩展受阻——
- **有界循环编译 bug**：BCC 把 C 源码内嵌内核编译（bpf2c），tracepoint 内任何有界循环（`for (int i=0; i<256; i++)`）都 fail load（报 "too large (455 insns), at most 4096"），是 BCC bpf2c 特有 bug，非 verifier 限制
- **512B 栈限制**：struct event 增至 ~420B 后 openat 探针爆栈，被迫用 per-cpu array 缓冲 hack
- **参数是 BCC 合成假名**（`args->type` 等），非内核真实结构

## 验证过程
- 本机环境确认：kernel 6.8 BTF ✓、libbpf 1.8.0（源码编译至 /usr/lib64）✓、bpftool v7.4.0 ✓、clang 14 `-target bpf` 编译验证通过
- 迁移成功判据：**6 个 E2E 逃逸场景全过 + 双后端字段对照一致**（tests/parity/：同一触发各跑 BCC 与 CO-RE，JSON 逐字段 diff，85 条事件全部一致）
- XDP 迁移中发现 libbpf 1.8 的 `bpf_xdp_attach` 只支持 native 模式（无 flags 参数），docker0 bridge 网卡必然失败 → 改用 bpftool generic 模式（subprocess）

## 备选方案
- **方案 A**：libbpf CO-RE——clang 预编译 `.bpf.o` + vmlinux.h + 内核 BTF，一次编译处处运行
- **方案 B**：Aya（Rust）——eBPF 现代框架，但项目主体是 Python（规则引擎/面板/AI 研判），需 Rust 重写用户态 + 跨语言集成，工作量远超 ctypes

## 决策
选择方案 A，Python 侧**自研 ctypes 封装 libbpf.so.1**（19 个 API，零新依赖）。配套决策：
- **迁移顺序：先 CO-RE，后 K8s**——K8s DaemonSet 部署几乎必然要求 CO-RE（集群节点不可能预装 BCC + linux-headers）；先做 K8s = 先做一个注定重写的部署
- **探针映射**：`TRACEPOINT_PROBE` → `SEC("tracepoint/syscalls/sys_enter_<名>")`，ctx 为 `struct trace_event_raw_sys_enter *`，参数从 `ctx->args[6]` 数组按下标读（mount: dir_name→args[1], type→args[2]；openat: filename→args[1], flags→args[2]；等）。**排除 raw_tp**（sys_enter_* raw_tp 参数是 regs 指针需 PT_REGS_PARM——ADR-003 已否定的脆弱路线）
- **事件缓冲**：per-cpu array hack → `bpf_ringbuf_reserve/submit`（指针直指 ringbuf 内存，天然绕开 512B 栈限制）；Ring Buffer 4096B → 1MB
- **struct event 字段序/类型逐字节保留**——ctypes 解析依赖，handle_event 零改动复用
- **纯迁移先行**：v0.4.1 只搬现有 6 探针 + XDP，新功能放 v0.4.2（有界循环在 clang+CO-RE 下正常，扩展自然解锁）

## 后果
- ✅ 运行时零编译依赖（`.bpf.o` 预编译 + BTF relocation）——K8s DaemonSet 前提成立
- ✅ BCC bpf2c 循环 bug 消失；512B 栈限制绕开；参数结构真实可查（vmlinux.h）
- ❌ 构建链引入（bpftool 生成 vmlinux.h + clang 编译）；ctypes 加载层 ~200 行需维护
- 📝 经验：(1) BCC 的 tracepoint 内循环是真实坑，扩展复杂逻辑应直接评估 CO-RE；(2) 迁移的最大风险是参数下标错位——对照测试比 E2E 更敏感；(3) 自研 ctypes 加载层虽 ~200 行，但零依赖且完全可控

## 关联
- [ADR-003](003-probe-tracepoint.md)：supersede 其 BCC 实现载体（探针仍用 tracepoint）
- [ADR-024](024-xdp-ingress-limit.md)：XDP 程序随本次迁移，attach 走 bpftool generic
- [ADR-032](032-rule-engine-conditions.md)：规则层重构与探针层迁移同期完成（v0.4.0/0.4.1）
