# 变更日志

本项目所有重要变更均记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

[**English Version / 英文版**](CHANGELOG.md)

---

## [未发布]

### 计划中
- Kubernetes 原生支持（v0.4）
- 定制前端面板（CSAI 风格，决策记录 #17）
- 性能压测 & systemd 部署

---

## [0.3.4] - 2026-08-09

### 新增
- **AI 建议规则审核闭环**（面板）：AI 研判中发现未知攻击模式 → 建议新规则 → 面板人工审核 → 一键入库 rules.yaml → 热加载 3 秒内生效（v0.3.3）
- `append_rule_to_yaml()` — 将 AI 建议规则格式化为 rules.yaml 列表项（4 空格缩进，已验证）
- `record_decision(scope='suggested_rule')` — 跟踪已审核的建议（确认/拒绝）
- 补全"未知攻击发现"闭环——毕设创新点：系统通过 AI 分析 + 人工审核学习新的检测模式

### 验证
- 单元：建议规则 → rules.yaml（YAML 有效，8→9 条）→ 热加载 → 规则可匹配
- 端到端：注入 AI 建议 → 追加 rules.yaml → guard 重载（9 条）→ 攻击触发新规则（pending_review）

## [0.3.3] - 2026-08-09


### 新增
- **规则热加载**：`EscapeDetector.reload()` + mtime 监听线程——guard 运行中修改 rules.yaml，3 秒内新规则生效（无需重启）
- **测试套件扩至 15 项**：静态检查 + 三层模块 + 核心模块（identity/scope/escalation/netblock/decision_executor）+ 单元行为（规则匹配、矩阵组合、升级、监控范围、热加载、IP 转换、异步 AI 结构）

### 验证
- 端到端：guard 运行中修改 rules.yaml → 重载日志（8→9 条）→ 新规则数秒内触发
- 单元：reload 8→9→8 条，新规则可匹配
- 测试套件：15/15 通过

## [0.3.2] - 2026-08-09

### 新增
- **异步 AI 研判**（ai_analyzer.py 的 `AsyncAIAnalyzer`）：
  - AI API 调用移到后台工作线程队列——Ring Buffer 回调不再被 DeepSeek 延迟阻塞（原来要等数秒）
  - 事件立即记录，AI 结论异步回填到 `ai_results.log`
  - AI 现在是顾问而非决策者：矩阵置信度驱动可逆响应，不可逆裁决等人工（v0.3.1）
- **面板**：合并异步 AI 结果（ai_results.log）到判决队列——AI 未完成时显示"AI 研判中…"，完成后显示结论

### 修复
- `time.strftime('%f')` 不支持微秒——改用 `datetime.now().strftime()` 生成毫秒级 ISO 时间戳；event_ts 现在与 events.log 一致

### 验证
- 事件 3 秒内上屏（不再等 AI）——之前要等 API 延迟
- ai_results.log 异步回填：误报（30%）和攻击（85%）正确识别
- events.log ↔ ai_results.log 时间戳匹配 ✅

## [0.3.1] - 2026-08-09

### 新增
- **判决执行器**（`src/core/decision_executor.py`）— 补全人机协同闭环：
  - 面板判决（decisions.log）现在由 guard 真正执行
  - `confirmed` → 容器被 kill（人工授权的不可逆动作）
  - `dismissed` → 解除隔离（unpause + 网络重连）
  - 执行结果回写 decisions.log（`executed` 字段 + 时间戳）
  - 启动时标记已处理条目（不重复执行旧判决）

### 目的
- 人机协同的最后一步：人工裁决 → guard 执行
- 之前判决只落在 decisions.log 无实际效果（闭环断裂）

### 验证
- 驳回 → 容器 unpause 恢复（paused → running）✅
- 确认 → 容器 kill（paused → exited）✅
- decisions.log 显示 executed=True + executed_at ✅

## [0.3.0] - 2026-08-09

### 新增
- **Streamlit 安全面板**（`dashboard/app.py`）：概览指标、实时告警流（3 秒自动刷新，st.fragment）、容器筛选
- **容器级人工判决队列**（决策记录 #18）：判决作用于容器，该容器全部待判决事件联动标记
- **判决证据视图**（决策记录 #19）：容器画像（镜像/特权/状态/端口，Docker API）+ 行为时间线（攻击链，来自 events.log）
- 判决持久化到 `decisions.log`（scope=container）

### 修复
- **面板空白页**：自动刷新循环（sleep→rerun）导致永不渲染——改用 `st.fragment(run_every=3)`
- **判决后消息不消失**：`load_decisions` 缓存未清除——判决后调用 `load_decisions.clear()`
- **重复攻击时 kill 被自动执行**（v0.2.5 修复）：不可逆动作永远进人工队列（决策记录 #14）

### 已知问题
- AI 同步调用在 API 延迟期间阻塞 Ring Buffer 回调——计划改为异步 AI / 后台队列

### 验证
- 实时告警流：mount 逃逸 + 反弹 shell → 6 条事件上屏
- 容器级判决：4 个容器分组，判决联动（17 条事件一次点击）
- 重复攻击：容器存活（kill 排队，永不自动执行）

## [0.2.5] - 2026-08-09

### 新增
- **分级自动化**（决策记录 #14）：可逆动作自动执行（暂停/隔离/流量阻断）；不可逆动作（kill/拉黑）进人工判决队列——即使 AI 置信度 ≥ 85% 也不自动执行
- **AI 建议真正生效**：`handle_alert(forced_action, ai_confidence)` —— AI 建议的动作会执行，带护栏：kill/拉黑要求 AI 置信度 ≥ 85%，否则进队列
- **网络流量阻断**（`src/core/netblock.py`）：iptables FORWARD DROP 恶意 IP:port（可逆，TTL 1 小时自动清理，业务流量保留）
- **响应升级**（`src/core/escalation.py`）：同镜像重复攻击 → 第 1 次暂停 / 第 2 次 kill（进队列）/ 第 3 次镜像拉黑（进队列，持久化到 config/blocklist.yaml）
- **事件状态机**（决策记录 #16）：日志新增 `state` 字段——new / quarantine / pending_review / resolved；LOG_FORMAT_VERSION → 2
- 容器镜像查询：`identity.get_image()`（冷路径 + 缓存，同 get_name 模式）

### 目的
- 人机协同：可逆动作即时填补响应缺口，不可逆裁决交给面板队列（v0.3）
- 攻击循环：同镜像反复拉起将升级到镜像拉黑

### 验证
- 端到端：反弹 shell → iptables DROP 规则插入（114.47.114.97:12150），日志 netblocked=true
- 单元：升级流程 pause→kill→block + 拉黑持久化；状态机映射
- 回归：默认监控行为不变

## [0.2.4] - 2026-08-09

### 新增
- **事件驱动 map 刷新**（主通道）：监听 Docker events（start/die）实时更新容器映射——容器身份即时识别，不再等待 5 秒轮询
- **轮询兜底**（次通道）：保留 5s 全量扫描，覆盖 guard 启动前已运行的容器或重连期间丢失的事件
- **Docker 事件处理器**：`_on_container_start`（带重试地添加 cgroup map + 名字索引 + BPF PID map），`_on_container_stop`（按 ID 匹配删除——die 时 cgroup 目录可能已不存在）

### 变更
- `ContainerIdentity` 现在运行两个后台线程：事件监听 + 轮询
- 事件流异常自动重连（2s 退避）

### 目的
- 消除冷路径窗口：容器创建 1 秒内的攻击也能正确归属（之前需要按需查 Docker）
- 为高容器变更率场景提供可靠身份跟踪

### 验证
- 端到端：容器启动 1 秒后触发 mount 逃逸 → 3/3 告警正确归属容器 ID
- 单元：start 事件添加所有 map；die 事件按 ID 删除所有 map（不依赖 cgroup stat）
- 回归：默认监控行为不变

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

- **v0.4**（2026 年 11 月）：Kubernetes 原生支持
- **v1.0**（2026 年 12 月）：稳定版，毕设答辩前发布

