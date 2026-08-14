# eBPF Container Guard

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.5.4-green.svg)](CHANGELOG.md)
[![eBPF](https://img.shields.io/badge/eBPF-tracepoint-orange.svg)](https://ebpf.io/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

> 🛡️ 基于 eBPF 的 AI 增强容器逃逸实时检测与防护系统
> AI-enhanced container escape detection and defense system based on eBPF

**实时检测 · 自动响应 · 云原生就绪**

[**English Version / 英文版**](README.md)

---

## 🎯 核心特性

- **三层检测管线** — 规则引擎（12 条规则，毫秒级）→ 行为矩阵（行为→CVE 映射，组合评分）→ AI 研判（DeepSeek，置信度分级响应）
- **6 个 eBPF 探针** — mount、ptrace、execve、connect、openat（内核态路径过滤）
- **全量行为日志** — 所有 syscall 事件记录到 `behaviors.log`（buffered + 按天轮转，保留 7 天），可开关——事后回溯取证、攻击链分析
- **7 页面 Streamlit 面板** — 概览、行为日志、判决队列、AI 建议规则、规则管理、实时告警流、设置——RBAC 角色权限（admin/运维/安全员）+ 临时 token 委派
- **容器身份识别** — PID Map → Cgroup Inode → /proc/cgroup 三级回退 + 后台动态刷新
- **AI 威胁研判**（已实测）— DeepSeek API 集成，支持攻击确认、手法识别、未知攻击发现；真实 API 调用已验证，能正确区分真实攻击与误报
- **分级自动化**（人机协同）— 可逆动作自动执行（暂停/隔离/流量阻断）；不可逆裁决（kill/镜像拉黑）进人工判决队列——AI 建议带置信度护栏执行
- **网络流量阻断** — iptables DROP 已确认的恶意 IP:port（可逆，TTL 自动清理，业务流量保留）
- **响应升级** — 同镜像重复攻击逐级升级：暂停 → kill（队列）→ 镜像拉黑（队列），阻止攻击循环
- **事件状态机** — 每个事件追踪 new → quarantine → pending_review → resolved（v0.3 判决面板的数据基础）
- **可配置** — 10 条检测规则 + 响应策略 + 监控范围（include/exclude 容器），YAML 定义，支持热加载

---

## 🚀 快速开始

### 环境要求

| 依赖 | 要求 |
|------|------|
| 操作系统 | Ubuntu 22.04 LTS（kernel ≥ 5.15，需 CONFIG_DEBUG_INFO_BTF） |
| Python | 3.8+ |
| 编译器 | clang（`-target bpf` 预编译 CO-RE 对象） |
| libbpf | 1.x（源码编译 → /usr/lib64/libbpf.so.1）+ bpftool |
| Docker | 已安装并运行 |
| 权限 | root / sudo（eBPF 程序加载需要） |

> v0.4.1 起从 BCC 迁移到 libbpf CO-RE：`make build` 预编译探针（vmlinux.h + clang），运行时零编译依赖。

### 一键启动（推荐）

```bash
git clone https://github.com/Chenjx12/ebpf-container-guard.git
cd ebpf-container-guard
./setup.sh                    # 环境初始化（幂等，新机器用）
./run.sh                      # guard（后台）+ 面板（前台）
```

### 单独启动

```bash
# 仅启动检测引擎（后台）
./run.sh --guard

# 仅启动面板（前台）
./run.sh --ui

# 停止所有服务
./run.sh --stop

# 自定义规则和策略
sudo python3 main.py --rules my_rules.yaml --responses my_responses.yaml
```

### systemd 部署（单机/边缘/政企内网，v0.4.3）

适合**无 K8s 集群**的环境（隔离内网/边缘单机）；集群内请用 DaemonSet（v0.4.4 规划）。

```bash
sudo make build                                    # 预编译 CO-RE 探针（首次）
sudo cp deploy/systemd/ebpf-guard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-guard             # 开机自启 + 启动
sudo journalctl -u ebpf-guard -f                   # 查看实时日志
```

- 部署前先停旧实例防双进程：`sudo pkill -f "python3 -u main.py"`
- 停止 `systemctl stop ebpf-guard` 会干净退出（SIGTERM → XDP detach + iptables 清理）
- SIGKILL 强杀可能残留 XDP 阻断：`sudo bpftool net detach xdp dev docker0 && sudo rm -f /sys/fs/bpf/guard_xdp_block`

### 使用预制 strace 镜像测试 ptrace 逃逸

```bash
docker build -f deploy/Dockerfile.test -t ebpf-test:latest .
docker run -d --privileged --pid=host --cap-add=SYS_PTRACE --name test ebpf-test:latest
docker exec test strace -p 1  # 触发 HIGH 级别告警
```


### 面板登录（RBAC）

```bash
# 终端 1：启动检测
./run.sh --guard

# 终端 2：前台启动面板
./run.sh --ui
# 或: streamlit run dashboard/app.py
# → 浏览器打开 http://localhost:8501
# → 首次启动：初始 admin 密码打印在【面板终端】中（用户名 admin）
#   登录后请立即修改密码
```

角色：admin > 运维 > 安全员。admin 管理成员；运维添加规则；
安全员处理判决/AI 研判。低权限角色的越权操作需向高权限角色索取
临时 token（设置页发放）。

### 使用预制 strace 镜像测试 ptrace 逃逸

---

## 📊 演示

### 场景 1：procfs 挂载逃逸 → CRITICAL 告警 + 容器冻结

```bash
# 终端 A：启动监控
sudo python3 main.py

# 终端 B：模拟攻击
docker run -d --privileged --name test_esc ubuntu:22.04 sleep 300
docker exec test_esc bash -c "mkdir -p /tmp/host_proc && mount -t proc proc /tmp/host_proc"
```

**实际验证输出（kernel 6.8, 2026-08-08）：**

```
🚨 安全告警 - CRITICAL 级别
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
规则: procfs_mount_escape
描述: 检测容器内挂载宿主机procfs文件系统
容器: 2287bfc722b9
进程: 27874 (mount)
文件系统: proc -> 目标: /tmp/host_proc
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️  [RESPONSE] 触发自动防御: CRITICAL → pause_container
✅ Container 2287bfc722b9 PAUSED - 已冻结,等待人工取证
```

Docker Daemon 确认冻结生效：
```bash
$ docker exec test_esc ls /
Error response from daemon: Container test_esc is paused,
unpause the container before exec
```

### 场景 2：ptrace 宿主机 PID 1 → HIGH 告警 + 断网隔离

```bash
# 终端 A：启动监控
sudo python3 main.py

# 终端 B：模拟攻击（使用预制 strace 镜像）
docker run -d --privileged --pid=host --cap-add=SYS_PTRACE --name test ebpf-test:latest
docker exec test strace -p 1
```

**实际验证输出（kernel 6.8, 2026-08-08）：**

```
🚨 安全告警 - HIGH 级别
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
规则: ptrace_host_init
描述: 检测容器内尝试ptrace宿主机1号进程(systemd/init)
容器: 504a01109cca
进程: 27901 (strace)
Ptrace请求: PTRACE_SECCOMP_GET_METADATA -> 目标PID: 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️  [RESPONSE] 触发自动防御: HIGH → isolate_network
✅ Container 504a01109cca DISCONNECTED
```

> 💡 **设计哲学**：现代 `strace` 使用了 6+ 种不同的 ptrace 操作码（`PTRACE_SECCOMP_GET_METADATA`, `PTRACE_SYSCALL`, `PTRACE_GET_SYSCALL_INFO` 等），不仅限于传统的 `PTRACE_ATTACH`。本系统通过匹配 **行为方向（target_pid=1）** 而非具体参数来检测逃逸，不会被参数级别的变化绕过。

### 场景 3：AI 威胁研判（DeepSeek，已实测）

当行为矩阵置信度落在灰色区间（60-85%）时，AI 研判模块结合上下文分析告警：

```bash
# 终端 A：启动监控（启用 AI）
cp config/ai_config.yaml.example config/ai_config.yaml
# 编辑 config/ai_config.yaml 填入你的 DeepSeek API Key
sudo python3 main.py

# 终端 B：容器初始化进程读取 /etc/passwd
docker run -d --privileged --name test ubuntu:22.04 sleep 300
```

**实测输出（DeepSeek API, 2026-08-09）：**

```
🚨 安全告警 - HIGH
规则: sensitive_file_access
攻击向量: sensitive_file_access
━━━ 行为矩阵分析 ━━━
关联CVE: CVE-2019-5736
置信度: 75% 🟡 AI研判

🤖 AI 研判报告:
   判定: ⚠️ 误报
   置信度: 30%
   分析: 该警报检测到容器内进程读取了/etc/passwd文件，但该文件是系统常规文件，
         许多合法应用都会读取它。进程名为runc:[2:INIT]，是容器初始化过程中的
         正常操作，且没有其他恶意行为。这更可能是误报，建议仅记录日志并观察。
   建议: log_only
```

AI 正确识别了这条误报——规则引擎匹配了模式，但 AI 理解了上下文（`runc` 初始化读取 `/etc/passwd` 是正常行为）。这正是三层模型的核心价值：**确定性规则兜底全覆盖，AI 从噪音中甄别真实攻击**。

**AI 也能发现规则之外的攻击：**
```
🚨 安全告警 - HIGH
规则: reverse_shell
🤖 AI 研判报告:
   判定: ✅ 攻击
   置信度: 85%
   分析: 该容器内bash进程向非标端口30255发起连接，符合反向Shell典型特征。
         且此前已有敏感文件访问行为，攻击意图明显。建议立即终止容器并隔离网络。
   建议: kill_container
```

---

## 🏗️ 系统架构

```
┌──────────────────────────────────────────────┐
│  用户态 Python                                 │
│  ┌────────────────────────────────────────┐   │
│  │  main.py — 管线主控制器                  │   │
│  │  ├─ BpfRuntime()      CO-RE 加载探针     │   │
│  │  ├─ open_ring_buffer()  事件流消费        │   │
│  │  ├─ 3-tier ID 回退      容器身份识别       │   │
│  │  └─ 后台线程 (5s 刷新)   动态刷新映射表     │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  engine.py — Tier 1 规则引擎（12 条）     │   │
│  │  ├─ mount/ptrace/execve/connect/openat   │   │
│  │  ├─ 索引匹配 + 白名单 + fnmatch 排除     │   │
│  │  └─ 告警分级: CRITICAL / HIGH           │   │
│  ├────────────────────────────────────────┤   │
│  │  attack_matrix.py — Tier 2 行为矩阵     │   │
│  │  ├─ 10 攻击向量 × 8 组合规则              │   │
│  │  ├─ 10s 窗口组合评分                      │   │
│  │  └─ 行为 → CVE 自动映射                  │   │
│  ├────────────────────────────────────────┤   │
│  │  ai_analyzer.py — Tier 3 AI 研判       │   │
│  │  ├─ DeepSeek API 置信度分级              │   │
│  │  └─ 未知攻击 → 建议新规则                  │   │
│  │  ┌────────────────────────────────────┐ │   │
│  │  │  docker_responder.py — 响应引擎     │ │   │
│  │  │  ├─ pause/isolate/kill/log          │ │   │
│  │  │  └─ 10min 冷却 + JSON 审计           │ │   │
│  │  └────────────────────────────────────┘ │   │
│  └────────────────────────────────────────┘   │
├──────────────────────────────────────────────┤
│  内核态 eBPF                                   │
│  ┌────────────────────────────────────────┐   │
│  │  Tracepoint 探针 (6 个)                  │   │
│  │  ├─ sys_enter_mount                     │   │
│  │  ├─ sys_enter_ptrace                    │   │
│  │  ├─ sys_enter_execve                    │   │
│  │  ├─ sys_enter_connect                   │   │
│  │  ├─ sys_enter_openat (路径过滤)          │   │
│  │  └─ sys_enter_capset                    │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  container_map (BPF_HASH)               │   │
│  │  PID → container_id  后台 5s 刷新        │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  Ring Buffer (4096 条目)                 │   │
│  │  events.ringbuf_output() → 用户态消费    │   │
│  └────────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
```

---

## 📁 项目结构

```
ebpf-container-guard/
├── run.sh                          # 一键启动脚本（v0.3.11）
├── setup.sh                        # 环境初始化（幂等，v0.3.11）
├── main.py                          # 主入口
├── requirements.txt                 # Python 依赖
├── LICENSE                          # MIT 许可证
├── README.md                        # 英文文档
├── README_CN.md                     # 中文文档（本文件）
├── CHANGELOG.md                     # 版本迭代记录
├── CONTRIBUTING.md                  # 贡献指南
├── Makefile                         # 构建/部署自动化
├── src/
│   ├── core/                        # 基础设施
│   │   ├── identity.py              # 容器身份管理（三级回退 + 后台刷新）
│   │   ├── event_log.py             # 结构化 JSON 事件日志
│   │   ├── behavior_logger.py       # 全量 syscall → behaviors.log (v0.3.10)
│   │   ├── scope.py                 # 监控范围（include/exclude 容器）
│   │   ├── escalation.py            # 响应升级（暂停 → kill → 镜像拉黑）
│   │   ├── netblock.py              # iptables FORWARD DROP（可逆）
│   │   ├── netblock_xdp.py          # XDP 入站阻断 + 混合后端
│   │   └── decision_executor.py     # 执行人工裁决（来自 decisions.log）
│   ├── ebpf/
│   │   ├── escape-detect.bpf.c      # eBPF 内核探针（5 个 tracepoint）
│   │   └── xdp-block.bpf.c          # XDP 包过滤程序 (v0.3.9)
│   ├── detector/
│   │   ├── __init__.py
│   │   ├── engine.py                # Tier 1: YAML 规则引擎（热加载）
│   │   ├── attack_matrix.py         # Tier 2: 行为→CVE 矩阵（8 向量）
│   │   └── ai_analyzer.py           # Tier 3: DeepSeek AI 研判（异步）
│   └── responder/
│       ├── __init__.py
│       └── docker_responder.py      # Docker 响应引擎（分级自动化）
├── config/
│   ├── rules.yaml                   # 10 条检测规则
│   ├── responses.yaml               # 4 级响应策略
│   ├── monitor.yaml                 # 监控范围 + netblock 后端 + behavior_log 开关
│   ├── ai_config.yaml.example       # DeepSeek API 密钥模板
│   ├── users.yaml.example           # RBAC 用户配置模板
│   └── blocklist.yaml               # 已拉黑镜像列表
├── dashboard/                       # Streamlit 安全面板
│   ├── app.py                       # 入口 + 导航 + 强制改密
│   ├── common.py                    # 共享数据加载工具
│   ├── auth.py                      # AuthManager + TokenManager（RBAC）
│   └── pages/                       # 7 个页面
│       ├── login.py                 # 登录页
│       ├── overview.py              # 概览指标 + 容器筛选
│       ├── behavior_log.py          # 全量 syscall 行为日志（v0.3.10）
│       ├── review_queue.py          # 人工判决队列（容器级）
│       ├── ai_rules.py              # AI 建议规则审核
│       ├── rules.py                 # 规则管理 + 审计轨迹
│       ├── alerts.py                # 实时告警流 + 阻断记录
│       ├── members.py               # 成员管理（admin）
│       └── settings.py              # AI 配置 + 临时 token 发放
├── tests/
│   ├── integration/
│   │   ├── test_escape_scenarios.sh # 烟雾测试（15 项检查）
│   │   └── scenarios/               # 6 个 E2E 场景测试
│   │       ├── lib.sh               # 共享生命周期函数
│   │       ├── build_image.sh       # 代理感知的 Docker 镜像构建
│   │       ├── run_all_scenarios.sh # 一键运行全部场景
│   │       ├── test_mount_escape.sh
│   │       ├── test_socket_mount.sh
│   │       ├── test_ptrace_escape.sh
│   │       ├── test_sensitive_file.sh
│   │       ├── test_reverse_shell.sh
│   │       └── test_nsenter.sh
│   └── images/                      # 各场景的测试 Dockerfile
```

---

## ⚙️ 配置说明

### 检测规则（`config/rules.yaml`）

规则为 **Falco 风格条件树**（v0.4.0）：`all`（AND）/ `any`（OR）/ `not`（取反）任意嵌套，叶子操作符支持 `neq` / `startswith` / `endswith` / `contains` / `glob` / `exists`。`event_type` 为顶层键（做索引），不在 condition 内。

```yaml
rules:
  - name: "procfs_mount_escape"
    description: "检测容器内挂载宿主机procfs文件系统"
    severity: "CRITICAL"
    event_type: "mount"
    condition:
      all:
        - fstype: "proc"
        - not:
            any:
              - comm:                    # 排除基础设施进程的正常挂载
                  - "dockerd"
                  - "containerd"
                  - "runc:[2:INIT]"
                  - "runc"
              - target_path:             # glob 通配排除
                  - {glob: "/proc/thread-self/fd/*"}
    action: "alert_and_log"

  - name: "ptrace_host_init"
    description: "检测容器内尝试ptrace宿主机1号进程(systemd/init)"
    severity: "HIGH"
    event_type: "ptrace"
    condition:
      target_pid: 1         # 核心：匹配行为方向，而非具体 ptrace 参数
    action: "alert_and_log"

  - name: "sensitive_file_access"
    description: "检测容器内读取宿主机敏感文件(如shadow)"
    severity: "HIGH"
    event_type: "openat"
    condition:
      target_path:
        - "/host_etc/shadow"
    action: "alert_and_log"
```

### 响应策略（`config/responses.yaml`）

```yaml
responses:
  - threat_level: critical
    action: pause_container        # 冻结容器，保留内存取证现场
  - threat_level: high
    action: isolate_network        # 断网隔离，阻止横向移动或 C2 回连
  - threat_level: medium
    action: kill_process           # 仅杀进程，不影响容器其他服务
  - threat_level: low
    action: log_only               # 仅记录审计日志，不自动处置
```

### AI 分析（`config/ai_config.yaml`）

使用你的 API Key 启用 AI 研判：

```bash
cp config/ai_config.yaml.example config/ai_config.yaml
# 编辑该文件填入你的 Key
```

```yaml
# config/ai_config.yaml（gitignored，永不提交）
api_key: "sk-your-api-key-here"
model: "deepseek-chat"

# 任意 OpenAI 兼容端点：
#   DeepSeek:  https://api.deepseek.com/v1
#   OpenAI:    https://api.openai.com/v1
#   本地 vLLM:  http://localhost:8000/v1
base_url: "https://api.deepseek.com/v1"

# 置信度分级响应阈值
auto_response_threshold: 85    # > 85% → 自动执行响应
pending_review_threshold: 60   # 60-85% → AI 研判分析
                               # < 60% → 仅记录
```

分析器采用 **OpenAI 兼容格式**：修改 `base_url` 即可切换 OpenAI 或任意自托管端点（vLLM / Ollama），实现完全离线运行。未配置 Key 时系统运行在**离线回退模式**：由矩阵置信度驱动决策（>85% 自动响应，60-85% 标记待审，<60% 静默）。

---

## 🔄 版本路线

| 版本 | 特性 | 状态 |
|------|------|------|
| v0.1 | MVP：基础检测 + Docker 响应 | ✅ 稳定版 |
| v0.2 | 三层检测 + 分级自动化（流量阻断、响应升级） | ✅ 稳定版 |
| v0.3 | 面板 + 人机协同（多页面、RBAC、XDP+iptables 阻断、异步 AI、全量行为日志） | ✅ 稳定版 |
| v0.4 | 规则引擎重构（Falco 风格条件树）+ BCC→libbpf CO-RE 迁移（自研 ctypes 加载层） | ✅ 稳定版 |
|       | ↳ v0.4.3 — 生产化准备（systemd 部署 + 性能压测） | ✅ 稳定版 |
|       | ↳ v0.4.4 — 行为日志 IO 优化（buffered + 轮转） | ✅ 稳定版 |
| v0.5 | 单实例锁（部署形态互斥）→ K8s DaemonSet 原生支持 | ✅ 当前版本 |
|       | ↳ v0.5.0 — 单实例锁 | ✅ 稳定版 |
|       | ↳ v0.5.1 — K8s 容器发现 + 身份识别 | ✅ 稳定版 |
|       | ↳ v0.5.2 — K8s responder（响应闭环） | ✅ 稳定版 |
|       | ↳ v0.5.3 — DaemonSet 部署（guard 容器化上 k3s） | ✅ 稳定版 |
|       | ↳ v0.5.4 — 网络阻断补全（nsenter 真实断网 + 适配蓝图） | ✅ 当前版本 |
| v0.4.x | K8s 原生支持（DaemonSet + NetworkPolicy） | 📋 规划中 |
| v1.0 | 稳定版，毕设答辩前发布 | 📋 12 月 |

详见 [CHANGELOG.md](CHANGELOG.md)。

---

## 🏗️ 架构决策 (ADRs)

本项目用 **ADR（Architecture Decision Records）** 记录关键架构决策——"为什么代码长这样"。
每个决策独立成篇，从内核探针选型（kprobe → tracepoint → CO-RE）到检测架构（行为矩阵）、
响应策略（可逆优先）、网络阻断（XDP 混合后端）、规则引擎（Falco 风格条件树）。

📄 [docs/ADRs/](docs/ADRs/) — 决策索引与全文

---

## 🧪 测试

```bash
# 烟雾测试（依赖检查）
bash tests/integration/test_escape_scenarios.sh

# 真实验证（需要 root + Docker + --privileged）
# 终端 A
sudo python3 main.py

# 终端 B
docker run -d --privileged --name test_esc ubuntu:22.04 sleep 300
docker exec test_esc bash -c "mkdir -p /tmp/host_proc && mount -t proc proc /tmp/host_proc"
# 预期：🚨 CRITICAL 告警 + 容器被 pause

docker rm -f test_esc
```

---

## 🔒 安全说明

- **需要 root 权限** — eBPF 程序加载和 Docker socket 访问均需要 root 权限
- **生产部署** — 部署前请充分测试，根据实际环境调整规则和阈值
- **误报处理** — 规则内用 `not` 条件树白名单排除正常基础设施进程（dockerd, containerd, runc 等），支持 glob 通配
- **性能开销** — 五个 eBPF 探针（mount + ptrace + execve + connect + openat）CPU 开销 < 2%，Ring Buffer 4096 条目约 1MB 内存
- **冷却机制** — 同一容器 10 分钟内不重复响应，避免响应风暴

---

## 👤 维护者

[@chenx12](https://github.com/Chenjx12)

---

## 📚 学习资源

想从零开始学习 eBPF？查看配套学习笔记：
- [eBPF Learning Notes](https://github.com/Chenjx12/ebpf-learning-notes) — 从 Hello World 到 K8s 部署的完整学习路线，19 个代码示例 + 4 个小节笔记 + 中文教程

---

**最后更新**: 2026-08-14

---
# Star
## Star History

<a href="https://www.star-history.com/?repos=Chenjx12%2Febpf-container-guard&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Chenjx12/ebpf-container-guard&type=date&theme=dark&legend=top-left&sealed_token=9k7OUZGHtswnc4p3F85KN7nwPccDIhPVqYRFOm27eQEkFc7qPqxehUY5H2qnuRtK2TrbB3hAaSBAt7HRbZuH2iwv_iyvGX-qYd_CK3E5CSNCnhAuv2PjpQ685pKkSOSG1wNRhq7kd4GEN6FaEIOZ7YiYDgY96MWd7pjFKNTz3qVY9fbgYk3XDq039mMQ" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Chenjx12/ebpf-container-guard&type=date&legend=top-left&sealed_token=9k7OUZGHtswnc4p3F85KN7nwPccDIhPVqYRFOm27eQEkFc7qPqxehUY5H2qnuRtK2TrbB3hAaSBAt7HRbZuH2iwv_iyvGX-qYd_CK3E5CSNCnhAuv2PjpQ685pKkSOSG1wNRhq7kd4GEN6FaEIOZ7YiYDgY96MWd7pjFKNTz3qVY9fbgYk3XDq039mMQ" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=Chenjx12/ebpf-container-guard&type=date&legend=top-left&sealed_token=9k7OUZGHtswnc4p3F85KN7nwPccDIhPVqYRFOm27eQEkFc7qPqxehUY5H2qnuRtK2TrbB3hAaSBAt7HRbZuH2iwv_iyvGX-qYd_CK3E5CSNCnhAuv2PjpQ685pKkSOSG1wNRhq7kd4GEN6FaEIOZ7YiYDgY96MWd7pjFKNTz3qVY9fbgYk3XDq039mMQ" />
 </picture>
</a>

