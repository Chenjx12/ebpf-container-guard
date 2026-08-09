# 变更日志

本项目所有重要变更均记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

[**English Version / 英文版**](CHANGELOG.md)

---

## [未发布]

### 计划中
- Streamlit 仪表盘（v0.3）
- Kubernetes 原生支持（v0.4）
- 性能压测 & systemd 部署

---

## [0.2.2] - 2026-08-09

### 变更
- **代码模块化**：`ContainerIdentity`（identity.py）和 `EventLogger`（event_log.py）拆分为 `src/core/` 独立模块，main.py 专注管线编排
- **事件日志增强**：`version` 字段、毫秒时间戳、`action_status`（executed / skipped_host / skipped_cooldown / error）、`tier1_match` 参数化
- **日志绝对路径**：无论从哪个目录运行，日志都写入项目根目录

### 修复
- **docker-py 7.x 兼容**：7.x 移除了 `Container.disconnect()`——断网隔离改用 `Network.disconnect(container)`；实测 `DISCONNECTED from bridge` 成功
- **响应静默失败**：`isolate_network` 现在返回成功/失败，`handle_alert` 返回实际执行状态（动作失败不再误报 'executed'）
- **重构引入的变量引用错误**：`event_pid → event.pid`

### 验证
- mount 逃逸 → CRITICAL → pause_container → status=executed
- 反弹 shell → HIGH → isolate_network → DISCONNECTED from bridge
- 冷却机制 → status=skipped_cooldown（剩余 592 秒）

---

## [0.2.0] - 2026-08-08

### 新增
- **三层检测管线**：规则引擎（Tier 1）→ 行为矩阵（Tier 2）→ AI 研判（Tier 3）
- **3 个新 eBPF 探针**：execve、connect、openat（内核态路径过滤）
- **行为矩阵**（`src/detector/attack_matrix.py`）：8 个攻击向量 × 6 条组合规则，10 秒时间窗口
- **AI 分析器**（`src/detector/ai_analyzer.py`）：DeepSeek API 集成（已实测），置信度分级响应（>85% 自动 / 60-85% 待确认 / <60% 仅记录），离线回退模式已验证
- **5 条新 YAML 规则**：docker_socket_mount、nsenter_escape、privileged_exec、reverse_shell、sensitive_file_access、host_directory_access
- Ring Buffer 从 256 升级到 4096 条目

### 变更
- 告警信息增强：新增 attack_vector、cve_refs、matrix_confidence 字段
- 宿主机进程事件自动过滤，仅保留容器相关规则
- 规则引擎支持 `attack_vector` 和 `cve_refs` 字段

### 验证
- 单事件命中：procfs_mount → 置信度 85%
- 组合命中：procfs_mount + sensitive_file_access → 置信度 88% → 自动响应

---

## [0.1.1] - 2026-08-08

### 修复
- **main.py 完全不可用** — 基于已验证的参考实现
  （[`escape-respond.py`](https://github.com/Chenjx12/ebpf-learning-notes/blob/main/code/09-response/escape-respond.py)）完全重写。
  原来导入的类名不存在（`DetectionEngine` → `EscapeDetector`，
  `DockerResponder` → `ResponseEngine`）。eBPF 加载、Ring Buffer 消费、
  检测-响应管线全部缺失。
- **`docker exec` 进程的容器 ID 始终为 "host"** — 添加后台线程，
  每 5 秒刷新 PID→container map 和 cgroup→container map。
- **openat 事件淹没 Ring Buffer** — openat 探针默认禁用
  （高频系统调用，256 条目 Buffer 瞬间溢出）。用户可在增大
  `RINGBUF_SIZE` 并添加内核态路径过滤后重新启用。

### 变更
- eBPF 探针策略文档化：tracepoint（`syscalls:sys_enter_*`）
  确认在 kernel 6.8 上工作正常。kprobe（`__x64_sys_*`）方案
  已测试并放弃 — `PT_REGS_PARM` 宏在 kernel 6.8 syscall wrapper
  下无法正确访问参数。

### 验证
- 端到端管线：eBPF tracepoint → Ring Buffer → 规则引擎 →
  CRITICAL 告警 → Docker `pause_container` 动作执行
- 真实特权容器验证：`mount -t proc proc /tmp/host_proc`
  正确检测并自动冻结容器

---

## [0.1.0] - 2026-08-07

### 新增
- 首个 MVP 版本
- mount/ptrace/openat 系统调用的 eBPF 内核探针
- 基于 YAML 的检测规则引擎
- Docker 响应引擎（暂停/断网）
- Ring Buffer 低延迟事件传输
- 基于 Cgroup 的容器身份识别
- 集成测试套件
- 完整文档

### 特性
- 容器逃逸实时检测
- 100ms 内自动响应
- YAML 可配置检测规则
- 规则和响应策略支持热加载
- 按严重级别分色的 CLI 输出

### 技术栈
- eBPF tracepoint（内核态）
- Python 3.8+ + BCC 框架
- Docker SDK（容器管理）
- YAML 配置文件

---

## 版本规划

- **v0.3**（2026 年 10 月）：Streamlit 仪表盘
- **v0.4**（2026 年 11 月）：Kubernetes 原生支持
- **v1.0**（2026 年 12 月）：稳定版，毕设答辩前发布

## [0.2.3] - 2026-08-09

### 新增
- **可配置监控范围**（`config/monitor.yaml`）：选择要监控的容器
  - `include`：白名单模式——只监控列表中的容器（支持 fnmatch 通配符）
  - `exclude`：黑名单模式——永不监控列表中的容器（优先于 include）
  - `match_by`：按容器名或短 ID 匹配
  - 空列表 = 监控所有（默认，行为不变）
- **ContainerScope**（`src/core/scope.py`）：独立模块，遵循模块化架构
- **冷路径名字解析**（`src/core/identity.py`）：后台刷新未赶上时，通过 Docker API 按需解析容器名并缓存

### 目的
- 为 v0.3 面板按容器筛选事件打基础
- 可只监控生产容器，或排除噪音测试容器

### 验证
- 单元测试：5/5 通过（默认、include、exclude、优先级、match_by=id）
- 端到端 exclude：`t_exc` 容器 0 告警（含冷路径——后台刷新前就触发攻击）
- 端到端 include：仅 `t_inc` 告警（4/4 来自被包含容器，未包含容器 0 告警）
- 回归：默认配置监控所有（3 条告警）
