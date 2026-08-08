# eBPF Container Guard

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.1-green.svg)](CHANGELOG.md)
[![eBPF](https://img.shields.io/badge/eBPF-tracepoint-orange.svg)](https://ebpf.io/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

> 🛡️ 基于 eBPF 的 AI 增强容器逃逸实时检测与防护系统
> AI-enhanced container escape detection and defense system based on eBPF

**实时检测 · 自动响应 · 云原生就绪**

[**English Version / 英文版**](README.md)

---

## 🎯 核心特性

- **内核级监控** — eBPF tracepoint 零开销捕获 mount/ptrace 系统调用，不修改内核源码
- **容器身份识别** — 3 级回退策略（PID Map → Cgroup Inode → /proc/cgroup），精准关联容器
- **智能降噪** — YAML 规则引擎，支持白名单排除 + fnmatch 通配符，避免正常基础设施进程误报
- **自动响应** — 检测到逃逸后立即执行：冻结容器保留现场 / 断网隔离阻止横向移动 / 终止可疑进程，10 分钟冷却期防重复
- **可配置** — 检测规则和响应策略通过 YAML 文件定义，运维人员友好
- **云原生就绪** — Docker 单机版已验证，K8s DaemonSet 支持规划在 v0.4.0

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
│  │  engine.py — YAML 规则引擎              │   │
│  │  ├─ 按 event_type 建索引，避免全量遍历    │   │
│  │  ├─ 精确匹配 + 列表 OR + fnmatch 排除    │   │
│  │  └─ 告警分级: CRITICAL / HIGH / MEDIUM  │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  docker_responder.py — 响应引擎         │   │
│  │  ├─ pause_container    冻结容器保留现场   │   │
│  │  ├─ isolate_network    断网隔离阻止C2    │   │
│  │  ├─ kill_process       终止可疑进程       │   │
│  │  ├─ kill_container     销毁整个容器       │   │
│  │  └─ log_only           仅记录审计日志     │   │
│  │  └─ 10min 冷却期 + JSON 审计日志         │   │
│  └────────────────────────────────────────┘   │
├──────────────────────────────────────────────┤
│  内核态 eBPF                                   │
│  ┌────────────────────────────────────────┐   │
│  │  tracepoint/syscalls/sys_enter_mount    │   │
│  │  tracepoint/syscalls/sys_enter_ptrace   │   │
│  │  （openat 已注释：高频调用，256 条目不足）  │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  container_map (BPF_HASH)               │   │
│  │  PID → container_id  用户态定期填充      │   │
│  └────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────┐   │
│  │  Ring Buffer (256 条目)                  │   │
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
│   ├── ebpf/
│   │   └── escape-detect.bpf.c      # eBPF 内核探针（mount + ptrace）
│   ├── detector/
│   │   ├── __init__.py
│   │   └── engine.py                # YAML 规则引擎
│   └── responder/
│       ├── __init__.py
│       └── docker_responder.py      # Docker 响应引擎
├── config/
│   ├── rules.yaml                   # 检测规则
│   └── responses.yaml               # 响应策略
├── deploy/
│   └── Dockerfile.test              # 预制 strace 测试镜像
├── tests/
│   └── integration/
│       └── test_escape_scenarios.sh # 集成测试（烟雾测试）
├── demos/
│   └── demo-basic.sh                # 演示脚本
└── docs/
    └── MVP-运行验证报告.md            # v0.1.1 运行验证报告
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
| v0.1.0 | MVP：代码从学习仓库毕业，尚未验证 | ❌ 不可运行 |
| v0.1.1 | MVP：端到端验证通过（mount + ptrace 真实验证） | ✅ 当前版本 |
| v0.2.0 | AI 研判集成（DeepSeek API）+ 置信度分级响应 | 📋 9 月 |
| v0.3.0 | Streamlit 仪表盘 + 人工确认队列 | 📋 10 月 |
| v0.4.0 | K8s 原生支持（DaemonSet + NetworkPolicy） | 📋 11 月 |
| v1.0.0 | 稳定版，毕设答辩前发布 | 📋 12 月 |

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
