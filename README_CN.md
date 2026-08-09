# eBPF Container Guard

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.2-green.svg)](CHANGELOG.md)
[![eBPF](https://img.shields.io/badge/eBPF-tracepoint-orange.svg)](https://ebpf.io/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

> 🛡️ 基于 eBPF 的 AI 增强容器逃逸实时检测与防护系统
> AI-enhanced container escape detection and defense system based on eBPF

**实时检测 · 自动响应 · 云原生就绪**

[**English Version / 英文版**](README.md)

---

## 🎯 核心特性

- **三层检测管线** — 规则引擎（8 条规则，毫秒级）→ 行为矩阵（行为→CVE 映射，组合评分）→ AI 研判（DeepSeek，置信度分级响应）
- **5 个 eBPF 探针** — mount、ptrace、execve、connect、openat（内核态路径过滤）
- **容器身份识别** — PID Map → Cgroup Inode → /proc/cgroup 三级回退 + 后台动态刷新
- **AI 威胁研判**（已实测）— DeepSeek API 集成，支持攻击确认、手法识别、未知攻击发现；离线回退模式已验证，真实 API 调用待配置密钥
- **自动响应** — 容器冻结/断网/杀进程/仅记录，10 分钟冷却期 + JSON 结构化审计日志
- **可配置** — 8 条检测规则 + 4 级响应策略，YAML 文件定义，支持热加载

---

## 🚀 快速开始

### 环境要求

| 依赖 | 要求 |
|------|------|
| 操作系统 | Ubuntu 22.04 LTS（kernel ≥ 5.15） |
| Python | 3.8+ |
| BCC | `sudo apt install bpfcc-tools python3-bcc` |
| Docker | 已安装并运行 |
| 权限 | root / sudo（eBPF 程序加载需要） |

### 一键启动

```bash
git clone https://github.com/Chenjx12/ebpf-container-guard.git
cd ebpf-container-guard
pip install -r requirements.txt
sudo python3 main.py
```

### 启动选项

```bash
# 静默模式（仅输出告警，推荐生产环境）
sudo python3 main.py

# 详细模式（输出所有系统调用事件，调试用）
sudo python3 main.py --verbose

# 自定义规则和策略
sudo python3 main.py --rules my_rules.yaml --responses my_responses.yaml
```

### 使用预制 strace 镜像测试 ptrace 逃逸

```bash
docker build -f deploy/Dockerfile.test -t ebpf-test:latest .
docker run -d --privileged --pid=host --cap-add=SYS_PTRACE --name test ebpf-test:latest
docker exec test strace -p 1  # 触发 HIGH 级别告警
```

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
规则: dangerous_ptrace
描述: 检测容器内尝试ptrace宿主机1号进程(systemd/init)
容器: 504a01109cca
进程: 27901 (strace)
Ptrace请求: PTRACE_SECCOMP_GET_METADATA -> 目标PID: 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️  [RESPONSE] 触发自动防御: HIGH → isolate_network
✅ Container 504a01109cca DISCONNECTED
```

> 💡 **设计哲学**：现代 `strace` 使用了 6+ 种不同的 ptrace 操作码（`PTRACE_SECCOMP_GET_METADATA`, `PTRACE_SYSCALL`, `PTRACE_GET_SYSCALL_INFO` 等），不仅限于传统的 `PTRACE_ATTACH`。本系统通过匹配 **行为方向（target_pid=1）** 而非具体参数来检测逃逸，不会被参数级别的变化绕过。

---

## 🏗️ 系统架构

```
┌──────────────────────────────────────────────┐
│  用户态 Python                                 │
│  ┌────────────────────────────────────────┐   │
│  │  main.py — 管线主控制器                  │   │
│  │  ├─ BPF(src_file=...)   加载 eBPF 探针   │   │
│  │  ├─ open_ring_buffer()  事件流消费        │   │
│  │  ├─ 3-tier ID 回退      容器身份识别       │   │
│  │  └─ 后台线程 (5s 刷新)   动态刷新映射表     │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  engine.py — Tier 1 规则引擎（8 条）     │   │
│  │  ├─ mount/ptrace/execve/connect/openat   │   │
│  │  ├─ 索引匹配 + 白名单 + fnmatch 排除     │   │
│  │  └─ 告警分级: CRITICAL / HIGH           │   │
│  ├────────────────────────────────────────┤   │
│  │  attack_matrix.py — Tier 2 行为矩阵     │   │
│  │  ├─ 8 攻击向量 × 6 组合规则              │   │
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
│  │  Tracepoint 探针 (5 个)                  │   │
│  │  ├─ sys_enter_mount                     │   │
│  │  ├─ sys_enter_ptrace                    │   │
│  │  ├─ sys_enter_execve                    │   │
│  │  ├─ sys_enter_connect                   │   │
│  │  └─ sys_enter_openat (路径过滤)          │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  container_map (BPF_HASH)               │   │
│  │  PID → container_id  后台 5s 刷新        │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  Ring Buffer (4096 条目, v0.2.0 升级)    │   │
│  │  events.ringbuf_output() → 用户态消费    │   │
│  └────────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
```

---

## 📁 项目结构

```
ebpf-container-guard/
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
│   │   └── event_log.py             # 结构化 JSON 事件日志
│   ├── ebpf/
│   │   └── escape-detect.bpf.c      # eBPF 内核探针（5 个 tracepoint）
│   ├── detector/
│   │   ├── __init__.py
│   │   ├── engine.py                # Tier 1: YAML 规则引擎
│   │   ├── attack_matrix.py         # Tier 2: 行为→CVE 矩阵
│   │   └── ai_analyzer.py           # Tier 3: DeepSeek AI 研判
│   └── responder/
│       ├── __init__.py
│       └── docker_responder.py      # Docker 响应引擎
├── config/
│   ├── rules.yaml                   # 8 条检测规则
│   ├── responses.yaml               # 4 级响应策略
│   └── ai_config.yaml.example       # DeepSeek API 密钥模板
├── deploy/
│   └── Dockerfile.test              # 预制 strace 测试镜像
├── tests/
│   └── integration/
│       └── test_escape_scenarios.sh # 集成测试（烟雾测试）
├── demos/
│   └── demo-basic.sh                # 演示脚本
└── docs/
    └── MVP-运行验证报告.md            # v0.2.0 验证报告
```

---

## ⚙️ 配置说明

### 检测规则（`config/rules.yaml`）

```yaml
rules:
  - name: "procfs_mount_escape"
    description: "检测容器内挂载宿主机procfs文件系统"
    severity: "CRITICAL"
    condition:
      event_type: "mount"
      fstype: "proc"
    exclude:
      comm:
        - "dockerd"          # 排除 Docker 守护进程的正常挂载
        - "containerd"
        - "runc:[2:INIT]"
        - "runc"
      target_path:
        - "/proc/thread-self/fd/*"
    action: "alert_and_log"

  - name: "dangerous_ptrace"
    description: "检测容器内尝试ptrace宿主机1号进程(systemd/init)"
    severity: "HIGH"
    condition:
      event_type: "ptrace"
      target_pid: 1         # 核心：匹配行为方向，而非具体 ptrace 参数
    action: "alert_and_log"

  - name: "sensitive_file_read"
    description: "检测容器内读取宿主机敏感文件(如shadow)"
    severity: "HIGH"
    condition:
      event_type: "openat"
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

---

## 🔄 版本路线

| 版本 | 特性 | 状态 |
|------|------|------|
 | v0.1 | MVP：基础检测 + Docker 响应（v0.1.1） | ✅ 稳定版 |
| v0.2 | 三层检测：规则引擎 → 行为矩阵 → AI 研判 | ✅ 稳定版 |
|       | ↳ v0.2.2 — 当前版本（模块化，JSON 日志，docker-py 7.x 兼容） | |
| v0.3 | Streamlit 仪表盘 + 人工确认队列 | 📋 规划中 |
| v0.4 | K8s 原生支持（DaemonSet + NetworkPolicy） | 📋 规划中 |
| v1.0 | 稳定版，毕设答辩前发布 | 📋 12 月 |

详见 [CHANGELOG.md](CHANGELOG.md)。

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
- **误报处理** — 通过 `exclude` 配置白名单排除正常基础设施进程（dockerd, containerd, runc 等）
- **性能开销** — 两个 eBPF 探针（mount + ptrace）CPU 开销 < 2%，Ring Buffer 256 条目约 100KB 内存
- **冷却机制** — 同一容器 10 分钟内不重复响应，避免响应风暴

---

## 👤 维护者

[@chenx12](https://github.com/Chenjx12)

---

## 📚 学习资源

想从零开始学习 eBPF？查看配套学习笔记：
- [eBPF Learning Notes](https://github.com/Chenjx12/ebpf-learning-notes) — 从 Hello World 到 K8s 部署的完整学习路线，19 个代码示例 + 4 个小节笔记 + 中文教程

---

**最后更新**: 2026-08-08
