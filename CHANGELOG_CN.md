# 变更日志

本项目所有重要变更均记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

[**English Version / 英文版**](CHANGELOG.md)

---

## [0.4.4] - 2026-08-14

### 新增
- **BehaviorLogger IO 优化**（压测决策 #37 的可选优化落地）：
  - **buffered writer**：保持文件打开，每 0.5s flush——消除每事件 `open('a')+write+close` 的 2 次 syscall
  - **按天 + 大小轮转**（rename 方案）：跨天/超 50MB 时 `behaviors.log` → `behaviors.YYYY-MM-DD.log`，活跃文件始终是 `behaviors.log`（面板/压测零改动）
  - **保留策略**：自动清理 7 天前的历史文件（防磁盘膨胀）
  - guard 退出 flush 缓冲（`_shutdown` 调用，防丢最后事件）
  - **调试发现**：2s flush 在 10K+ ev/s 时大批量同步写阻塞 ringbuf（20K 丢 27%）→ 调 0.5s 后 40K 0 丢失——flush 粒度与吞吐的权衡写入决策 #38
- **压测工具适配**（tools/bench_openat.py）：排空 15s 匹配 buffered flush 周期；修复 rm 后 guard 不重建文件 bug（`_maybe_rotate` 检查文件存在性）

### 验证
- pytest 105/105（新增 6 个轮转/buffered 单测）
- 压测复测：**40K ev/s 0 丢失，延迟 p50 52ms**（与逐事件 open('a') 持平，正常负载消除 syscall 开销）
- guard 实跑轮转验证（跨天/大小/保留清理）

---

## [0.4.3] - 2026-08-14

### 新增
- **systemd 部署**（单机/边缘/政企内网形态）：
  - `deploy/systemd/ebpf-guard.service`——Type=simple / root / journald / on-failure 重启
  - **SIGTERM 干净退出**：`signal.raise_signal(SIGINT)` 复用清理路径 + `_shutdown()`（XDP detach + iptables unblock + bpf.close，幂等）
  - 关键修复：XDP pin 不随进程退出自动 detach（bpftool prog load + net attach pinned），systemd stop 必须显式清理；iptables 阻断无自愈调用方（cleanup_expired 无调用），停机主动 unblock
  - 实测 systemctl start/stop×3 循环，stop 后 XDP/iptables 无残留
- **性能压测工具 + 基准报告**：
  - `tools/bench_openat.py`：注入 openat('/etc/shadow')，统计丢失率/延迟分位/CPU 占用，behavior_log 开关对照组
  - `docs/performance-report.md`（**数据修正版**）：逐事件配对延迟——**零丢失至 40K ev/s**、**真实丢包阈值 ≈50K ev/s**、**延迟 p50 52-58ms**（poll 100ms 粒度主导）、CPU 增量 <1%（噪声内）。初版 1.67s 延迟为度量假象（注入分布污染），已用逐事件配对修正

### 变更
- **文档一致性清理**：README 双语 / test-guide 双语 / CONTRIBUTING 双语 / 集成测试 banner 全部同步到 v0.4.3（12 规则 / 6 探针 / 10 攻击向量 × 8 组合 / capset 探针列表）

### 验证
- systemd start/stop×3 循环通过；stop 后 journald 显示 Deactivated successfully
- pytest 99/99 + 集成测试 15/15
- 压测 3 组数据一致（0 丢失 / CPU 增量 ≈0）

---

## [0.4.2] - 2026-08-14

### 新增
- **cgroup release_agent 写入检测**（CVE-2022-0492 逃逸链补全）：
  - openat 探针内核态 basename 后缀匹配（release_agent / notify_on_release，v2 前缀 `cgroup.release_agent` 自动覆盖）+ 写标志校验（O_WRONLY/O_RDWR）
  - 规则 `cgroup_release_agent_write`（HIGH）——与既有 `mount_cgroup` 组合成完整逃逸链检测（组合置信度 92%）
- **capset 能力覆盖**（cap_sys_admin）：
  - 新增 capset 探针（第 6 个 tracepoint，EVENT_CAPSET=6），读取 data[0] 的 effective/permitted
  - 规则 `capset_cap_sys_admin`（MEDIUM）
- **bitand 操作符**（第 7 个叶子操作符）：位包含检查（`{bitand: 2097152}` = CAP_SYS_ADMIN），规则层可表达能力位检测
- **E2E +2 场景**（共 8 个）：cgroup 合成写入、capset ctypes 调用（含降权负向测试）

### 变更
- 事件 struct 尾部追加 cap_effective / cap_permitted / open_flags（ctypes 解析兼容）
- attack_matrix +2 vector（cgroup_release_agent 80% / capability_abuse 55%）+2 组合
- 修复 ring_buffer_poll 迭代崩溃（回调中首次访问 map 触发字典修改）

### 验证
- pytest 99/99；集成测试 15/15；E2E 8 场景全过（6 旧 + 2 新）
- **CVE-2022-0492 PoC 真实验证**（PaloAltoNetworks 官方，cgroup v2 主机）：release_agent 写入 ×2 + mount_cgroup 全命中——检测与 cgroup 版本无关

---

## [0.4.1] - 2026-08-14

### 新增
- **BCC → libbpf CO-RE 迁移**（[ADR-033](docs/ADRs/033-libbpf-core.md)）：
  - `escape-detect.bpf.c` / `xdp-block.bpf.c` 重写为 CO-RE 风格（`SEC("tracepoint/...")` + vmlinux.h + ringbuf reserve/submit），clang 预编译 `.bpf.o`，运行时零编译
  - **自研 ctypes 加载层**（`src/core/libbpf.py`）：封装 libbpf.so.1 的 19 个 API（对象加载 / tracepoint attach / map / ringbuf / XDP）
  - **BCC 兼容门面**（`src/core/bpf_runtime.py`）：`BpfRuntime` + `MapView` + `RingBufView`，main.py / identity.py 近乎零 diff 迁移
- **Makefile 构建链**：`bpftool btf dump` 生成 vmlinux.h（不入库，`.build/` gitignored）+ 两个 `.bpf.o` + `.BTF` 段校验
- **XDP 阻断迁移**：bpftool generic 模式 attach（libbpf 1.8 的 bpf_xdp_attach 只支持 native，bridge 网卡需 skb 模式），block/unblock/detach 全链路验证
- **双后端字段对照**（`tests/parity/`）：BCC 与 CO-RE 同时加载，同一触发事件逐字段 diff（85 条事件全部一致）——兜住 E2E 测不到的字段级错位

### 变更
- Ring Buffer 从 BCC 的 4096 字节（≈9 条事件）升级到 1MB（`1<<20`），消除溢出风险
- 移除 BCC 依赖：requirements.txt / setup.sh / README / test-guide / demo 全部改为 libbpf + clang + bpftool
- 事件解析零改动（`struct event` 字段序逐字节保留，handle_event 复用）

### 修复
- BCC 时代的 tracepoint 内有界循环编译 bug（bpf2c 限制）——CO-RE 下不复存在，为 v0.4.2 复杂探针逻辑铺路

### 验证
- 迁移成功判据：6 个 E2E 逃逸场景全过（mount/socket/ptrace/sensitive/reverse_shell/nsenter）
- pytest 92/92 + 集成测试 15/15
- 双后端对照：85 条事件逐字段一致
- eBPF 冒烟（tools/bpf_smoke.py）：CO-RE 加载 + 5 探针 attach + 事件解析

---

## [0.4.0] - 2026-08-13

### 新增
- **规则引擎重构 — Falco 风格条件树**（`src/detector/engine.py`）：
  - condition 升级为嵌套条件树：`all`（AND）/ `any`（OR）/ `not`（单节点取反），支持 `(A or B) and not C` 任意组合
  - 叶子操作符：`==`（标量精确 / 列表 OR，保持原语义）、`neq`、`startswith`、`endswith`、`contains`、`glob`（fnmatch，保留精确匹配优先）、`exists`
  - `event_type` 提为规则顶层键（做索引 + 隐式 AND），不再出现在 condition 内
- **规则 schema 校验模块**（`src/detector/rule_schema.py`）：
  - 字段注册表防拼写错误、单键节点不变量、嵌套深度 ≤5、操作符值类型检查
  - 首次加载失败即报错；热加载失败**保留现有规则集**（不再被坏规则清空）
  - `normalize_ai_rule()`：AI 建议规则自动归一化（旧式扁平 condition → 新树）
- **一次性迁移脚本**（`scripts/migrate_rules_v04.py`）：旧 rules.yaml 自动迁移，严格保语义（多字段→all、exclude→not/any、通配模式→glob 操作符）
- **pytest 单测层**（`tests/unit/`，92 用例）：操作符矩阵、组合求值、迁移等价性（10 条规则 × 合成事件池，旧实现对照逐条一致）、schema 校验、热加载保护、表单解析

### 变更
- `config/rules.yaml`：10 条规则全部迁移到新 schema（语义不变）
- 规则管理面板：条件表单改为多行（字段 + 操作符 + 值，逗号分隔 = OR 列表），event_type 独立下拉
- 规则入库门：`append_rule_to_yaml` 入库前归一化 + 校验，非法规则拒绝写入并提示
- AI 建议规则面板：整规则 YAML 展示；`ai_analyzer` prompt 附新 schema 示例（LLM 输出可控）
- `exclude` 字段移除（v0.4 破坏性变更，由 condition 内 `not` 表达）

### 验证
- 迁移等价性测试通过（新旧匹配器对全部规则 × 事件池结果一致）
- `runc:[2:INIT]` 方括号回归通过（精确匹配优先保留）
- 集成测试 15/15 通过（含热加载 Test 13 新 schema）
- E2E 逃逸场景全量通过（mount/socket/ptrace/sensitive/reverse_shell/nsenter）
- 面板 AppTest 冒烟通过（规则页新表单渲染正常）

---

## [0.3.12] - 2026-08-13

### 新增
- **run.sh** — 一键启动脚本（guard 后台 + 面板前台）；`--guard` / `--ui` / `--stop` 子命令；UI_CMD 变量集中管理前端启动命令（后续换自定义前端只需改一处）
- **setup.sh** — 幂等环境初始化：系统依赖（BCC/clang/docker）、pip 依赖、配置初始化（ai_config.yaml 从 .example 复制，不覆盖已有）；`--check` 模式仅检查

### 变更
- README/CHANGELOG：版本徽章和路线图更新到 v0.3.12

## [0.3.11] - 2026-08-13

### 新增
- **2 条新检测规则**（共 10 条）：
  - `execve_network_tools`：检测 curl/wget/nc/ncat 执行——可疑下载载荷或反弹连接（MITRE T1105）
  - `mount_cgroup`：检测 cgroup 文件系统挂载——CVE-2022-0492（cgroup release_agent 逃逸前置步骤）
- **规则扩充**：
  - `privileged_exec`：增加 `/bin/busybox` 目标路径
  - `sensitive_file_access`：增加 `/proc/self/exe`、`/proc/self/mem`、`/proc/self/cmdline`、`/run/docker.sock` 路径；增加 `runc:[2:INIT]` 排除规则减少误报
- **eBPF 内核探针扩展开**（`escape-detect.bpf.c`）：开放 `/proc/self/exe`、`/proc/self/mem`、`/proc/self/cmdline`、`/run/docker.sock` 路径过滤

### 修复
- **comm 字段 null 字节**：`event.comm` 现在去除尾部 `\x00` 字节——修复 `runc:[2:INIT]` 等内核 comm 值的排除匹配
- **_is_excluded fnmatch 字符集冲突**：`fnmatch("runc:[2:INIT]", "runc:[2:INIT]")` 因 `[2:INIT]` 被解析为字符集返回 False。增加精确匹配作为 fnmatch 回退前的优先匹配

### 验证
- 所有 Python 模块编译通过
- 10 条规则正确加载（原始 8 条 + 新增 2 条）
- `runc:[2:INIT]` 排除现在正确匹配（null 去除 + fnmatch 修复）
- CVE-2019-5736 PoC 测试：`privileged_exec` 和 `sensitive_file_access` 规则正确触发

## [未发布]

### 计划中
- Kubernetes 原生支持（v0.4，DaemonSet + NetworkPolicy）
- 新探针/规则（cgroup 文件写入补 CVE-2022-0492 检测、cap_sys_admin 覆盖）
- 定制前端面板（CSAI 风格，决策记录 #17）
- 性能压测 & systemd 部署

---

## [0.3.10] - 2026-08-11

### 新增
- **BehaviorLogger**（`src/core/behavior_logger.py`）：所有 syscall 事件（mount、ptrace、execve、connect、openat）记录到 `behaviors.log`（JSONL）——通过 `monitor.yaml` 的 `behavior_log: true|false` 开关
- **行为日志面板**（`dashboard/pages/behavior_log.py`）：只读分析页面，支持行为类型、容器 ID、进程名、时间范围（1 分钟/5 分钟/30 分钟/自定义）、容器/宿主机范围筛选——分页表格，5 秒 fragment 自动刷新
- **首次登录强制改密**（v0.3.10 RBAC 增强）：标记为 `initial` 密码的用户登录后强制跳转改密页面（两步确认），改密成功需重新登录——侧边栏改密入口移除
- **规则扩充**：
  - `nsenter_escape`：增加 `target_path: [/usr/bin/nsenter]`——nsenter 可能不以 `comm=nsenter` 出现
  - `host_directory_access`：增加 `/host_sys/block`（宿主机块设备）

### 变更
- `dashboard/common.py`：新增 `BEHAVIORS_LOG` 常量和 `load_behavior_log()` 函数
- `dashboard/app.py`：导航栏新增行为日志页面；移除侧边栏改密入口；首次登录强制改密拦截
- `dashboard/auth.py`：`create_user` 增加 `initial: true` 标记；`change_password` 清除标记；新增 `is_initial_password()` / `clear_initial_flag()` 方法

### 验证
- BehaviorLogger 启动打印 `[Behavior] enabled: true`；mount 攻击 → events.log 1 条告警，behaviors.log 22+ 条 mount 记录（共 1200+ 行，含正常 dockerd/runc 事件）
- 行为日志面板渲染正常，5s fragment 自动刷新，所有筛选条件可用
- 首次登录强制改密：初始用户跳转改密页 → 改密 → 重新登录
- 已有 `users.yaml` 用户自动标记 `initial: true`（下次加载时回填）

## [0.3.9] - 2026-08-11

### 新增
- **XDP 网络阻断**（`src/ebpf/xdp-block.bpf.c` + `src/core/netblock_xdp.py`）：
  - eBPF XDP 程序在网卡入口丢弃阻断包（微秒级，内核态）
  - 两个阻断表：整 IP 和 IP:端口（TCP/UDP）
- **混合后端**（`CompositeNetBlocker`）：XDP 入站 + iptables FORWARD 出站
  （C2/反弹 shell）——`netblock_backend: mixed`（默认）
- **场景化测试套件**（`tests/integration/scenarios/`）：6 个逃逸场景，
  预制 Docker 镜像 + 自动化断言（v0.3.9）
- **测试文档**（`tests/test-guide.md` / `tests/test-guide_CN.md`）：中英双语，
  包含测试方法、预期结果和实测验证记录

### 修复
- **build_image.sh**：路径解析重构为从镜像 tag 自动推导 Dockerfile；
  构建增加 `--network host` 解决容器 DNS
- **test_mount_escape.sh**：统一通过 `build_image.sh` 构建而非直接 `docker build`
- **docker_socket_mount 规则**：内核将 `/var/run/docker.sock` 解析为 `/run/docker.sock`
  （符号链接）——规则增加 `/run/docker.sock`

### 设计说明
- XDP 仅处理入站（进入接口的包）。容器出站流量（反弹 shell / C2）
  不经过 docker0 的 XDP——iptables FORWARD 覆盖出站，XDP 覆盖入站攻击流量。
  此分工已记录在决策文档。

### 验证
- XDP 程序加载、挂载 docker0、map 阻断/解除正常
- 混合端到端：基线 CONNECTED → 阻断 FAILED → 解除 CONNECTED
- 烟雾测试套件：15/15 通过
- 场景测试（2026-08-11）：**6/6 全部通过**——所有逃逸场景端到端验证
  （procfs 挂载、socket 挂载、ptrace、敏感文件、反弹 shell、nsenter），
  Tier 1/2/3 检测、响应动作、iptables 网络阻断均正常工作

## [0.3.8] - 2026-08-09


### 新增
- **RBAC 登录**（CSAI 式）：进入面板需用户名+密码
  - 角色：admin > 运维 > 安全员
  - 首次会话自动创建 admin，初始密码打印到终端
  - 密码哈希：pbkdf2_hmac(sha256, 10万次)；users.yaml gitignored
  - 修改自己密码（所有角色）
- **角色过滤导航**：按角色显示页面
  - 所有角色：概览 / 判决队列 / AI 建议规则 / 规则查看 / 告警流
  - admin+运维：设置（AI 配置）
  - admin：成员管理
- **成员管理**：admin 添加成员（强制密码、一成员一角色）；运维查看列表；
  admin+运维可见所有成员
- **临时授权 token**（委派访问）：
  - admin 发放 add_member / add_rule；运维发放 add_rule
  - 有效期 1-5 分钟，单次使用，用途锁定
  - 安全员可通过运维/admin 的 token 添加规则（规则**查看**对所有角色开放，
    便于更好研判）
  - 完整审计：auth_audit.log 记录谁给谁发放了什么权限、何时使用

### 验证
- 认证单元：哈希/验证/创建/改密/初始 admin（11 项）
- 登录：admin/运维/安全员会话，错误密码拒绝
- token 闭环：运维发放 add_rule → 安全员验证 → 添加规则 → token 失效 →
  审计显示 grantor=op1 / used_by=sec1
- 运维不能发放 add_member；admin 可以
- 测试套件：15/15 通过

## [0.3.7] - 2026-08-09


### 变更
- **面板重构为多页面**（`st.navigation`）：
  - 📊 概览（指标 + 容器筛选）
  - ⏳ 判决队列（容器级判决 + 证据视图）
  - 🧠 AI 建议规则（未知攻击发现审核）
  - 📜 规则管理（查看/添加/审计）
  - 📡 实时告警流（+ 流量阻断记录）
  - ⚙️ 设置（AI 配置，热加载）
- `dashboard/common.py` — 所有页面共享的数据加载/动作
- 每个页面独立 URL（可分享）；单次 `streamlit run`

### 目的
- 浏览器式侧边栏导航——迈向 CSAI 风格前端架构的第一步（决策记录 #17）
- 页面结构直接映射未来前端路由；数据模型（events/decisions/rules 日志）
  与框架无关，可复用

### 验证
- 6 个页面 URL 全部 HTTP 200
- 无导入/错误问题；guard 未改动

## [0.3.6] - 2026-08-09


### 新增
- **设置面板**：AI 配置表单
  - base_url / model / api_key / 阈值——无需手动编辑 yaml
  - API Key 掩码显示（sk-...后4位）；留空 = 保留现有 key
  - 保存 → ai_config.yaml → guard 热加载 3 秒生效（无需重启）
- **AI 配置热加载**：`AsyncAIAnalyzer.reload()` + mtime 监听
  （v0.3.3 模式）——启用 AI / 切换模型实时生效

### 验证
- 单元：reload() 从禁用→启用，model 更新
- 端到端：空 key 启动（AI 禁用）→ 保存真实 key → guard 重载
  （"config reloaded: enabled"）→ 攻击产出 5 条 AI 研判
- 测试套件：15/15 通过

## [0.3.5] - 2026-08-09


### 新增
- **规则管理面板**：
  - 查看现有规则（name/severity/description/attack_vector）
  - 表单手动添加规则（事件类型 + 条件字段）——热加载 3 秒生效
  - 规则变更审计轨迹：`rules_audit.log` 记录每次新增（时间戳/动作/规则名/来源/完整内容）——可审计、可回滚
- `append_rule_to_yaml(rule, source)` — source: 'ai_suggestion' | 'manual'
- `log_rule_audit()`、`load_rules()`、`load_rule_audit()` 面板辅助函数

### 目的
- 规则是知识资产：变更需要审批 + 审计轨迹（[ADR-014](docs/ADRs/014-graded-automation.md) 原则——影响越大越需人工）
- AI 可以离线；规则库独立运行（学习需要 AI，执行不需要）

### 验证
- 单元：手动 + AI 规则追加 → YAML 有效（8→10）→ 热加载 → 均可匹配
- 审计日志：2 条，来源归属正确
- 测试套件：15/15 通过（无回归）

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
- **重复攻击时 kill 被自动执行**（v0.2.5 修复）：不可逆动作永远进人工队列（[ADR-014](docs/ADRs/014-graded-automation.md)）

### 已知问题
- AI 同步调用在 API 延迟期间阻塞 Ring Buffer 回调——计划改为异步 AI / 后台队列

### 验证
- 实时告警流：mount 逃逸 + 反弹 shell → 6 条事件上屏
- 容器级判决：4 个容器分组，判决联动（17 条事件一次点击）
- 重复攻击：容器存活（kill 排队，永不自动执行）

## [0.2.5] - 2026-08-09

### 新增
- **分级自动化**（[ADR-014](docs/ADRs/014-graded-automation.md)）：可逆动作自动执行（暂停/隔离/流量阻断）；不可逆动作（kill/拉黑）进人工判决队列——即使 AI 置信度 ≥ 85% 也不自动执行
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

