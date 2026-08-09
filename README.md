# eBPF Container Guard

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](CHANGELOG.md)
[![eBPF](https://img.shields.io/badge/eBPF-tracepoint-orange.svg)](https://ebpf.io/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

> 🛡️ AI-enhanced container escape detection system based on eBPF  
> Real-time Detection · Intelligent Analysis · Auto Response · Cloud-Native Ready

[**中文版 / Chinese Version**](README_CN.md)

---

## 🎯 Key Features

- **3-Tier Detection Pipeline**: Rule engine (8 rules, sub-ms) → Attack matrix (behavior→CVE mapping, combination scoring) → AI judge (DeepSeek, confidence-gated response)
- **5 eBPF Probes**: mount, ptrace, execve, connect, openat (kernel-space path filter)
- **Container Identity**: 3-tier fallback (PID Map → Cgroup Inode → /proc/cgroup) with background refresh
- **AI-Powered Analysis** (live-tested): DeepSeek API integration for threat confirmation, technique identification, and unknown attack discovery — verified with real API calls, correctly distinguishes true positives from false positives
- **Graded Automation** (human-in-the-loop): reversible actions auto-execute (pause/isolate/network block); irreversible verdicts (kill/image blocklist) queue for human review — AI suggestions execute with confidence guardrails
- **Network Traffic Blocking**: iptables DROP for confirmed malicious IP:port (reversible, TTL cleanup, business traffic preserved)
- **Response Escalation**: repeated attacks from the same image escalate pause → kill (queued) → image blocklist (queued), stopping attack loops
- **Event State Machine**: every event tracked as new → quarantine → pending_review → resolved (foundation for the v0.3 review dashboard)
- **Configurable**: 8 detection rules + response strategies + monitoring scope (include/exclude containers) via YAML, hot-reload support

---

## 🚀 Quick Start

### Prerequisites

- **OS**: Ubuntu 22.04 LTS (kernel ≥ 5.15)
- **Python**: 3.8+
- **Docker**: Installed and running
- **Permissions**: Root or sudo access required for eBPF

### Option 1: Local Run (30 seconds)

```bash
git clone https://github.com/chenjx12/ebpf-container-guard.git
cd ebpf-container-guard
pip install -r requirements.txt
sudo python3 main.py
```

### Option 2: Custom Configuration

```bash
sudo python3 main.py \
  --rules config/rules.yaml \
  --responses config/responses.yaml \
  --verbose
```

### Option 3: Test with pre-built strace image (ptrace escape)

```bash
docker build -f deploy/Dockerfile.test -t ebpf-test:latest .
docker run -d --privileged --pid=host --cap-add=SYS_PTRACE --name test ebpf-test:latest
docker exec test strace -p 1  # triggers HIGH alert
```

---

## 📊 Demo

### Scenario 1: Procfs Mount Escape (CRITICAL Alert + Auto Pause)

```bash
# Terminal A: start the monitor
sudo python3 main.py

# Terminal B: simulate attack
docker run -d --privileged --name test_esc ubuntu:22.04 sleep 300
docker exec test_esc bash -c "mkdir -p /tmp/host_proc && mount -t proc proc /tmp/host_proc"
```

**Verified output (kernel 6.8, 2026-08-08):**

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

### Scenario 2: Ptrace Injection (HIGH Alert + Network Isolation)

```bash
# Terminal A: start the monitor
sudo python3 main.py

# Terminal B: simulate attack (requires strace pre-installed image)
docker run -d --privileged --pid=host --cap-add=SYS_PTRACE --name test ebpf-test:latest
docker exec test strace -p 1
```

**Verified output (kernel 6.8, 2026-08-08):**

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
```

> 💡 Modern `strace` uses 6+ different ptrace request codes (not just `PTRACE_ATTACH`). Our detection matches **behavior direction (target_pid=1)** rather than specific parameters, making it resilient to parameter-level evasion.

### Scenario 3: AI Threat Analysis (DeepSeek, live-tested)

When matrix confidence falls in the gray zone (60-85%), the AI judge analyzes the alert with surrounding context:

```bash
# Terminal A: start monitor (with AI enabled)
cp config/ai_config.yaml.example config/ai_config.yaml
# edit config/ai_config.yaml with your DeepSeek API key
sudo python3 main.py

# Terminal B: container process reads /etc/passwd during init
docker run -d --privileged --name test ubuntu:22.04 sleep 300
```

**Verified output (DeepSeek API, 2026-08-09):**

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

The AI correctly identified this as a false positive — the rule engine matched the pattern, but the AI understood the context (`runc` init is expected to read `/etc/passwd`). This is the key value of the 3-tier model: **deterministic rules catch everything, AI separates real attacks from noise**.

**AI also catches what rules miss:**
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

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│   User Space (Python)                        │
│   ┌───────────────────────────────────────┐  │
│   │  Tier 1: Rule Engine (8 YAML rules)    │  │
│   │  ├─ mount, ptrace, execve, connect,    │  │
│   │  │   openat — 4 attack surfaces        │  │
│   │  ├─ Whitelist exclusion + fnmatch      │  │
│   │  └─ Severity: CRITICAL / HIGH          │  │
│   ├───────────────────────────────────────┤  │
│   │  Tier 2: Attack Matrix                 │  │
│   │  ├─ 8 vectors × 6 combo rules          │  │
│   │  ├─ 10s window combination scoring     │  │
│   │  └─ Behavior → CVE mapping             │  │
│   ├───────────────────────────────────────┤  │
│   │  Tier 3: AI Judge (DeepSeek)           │  │
│   │  ├─ Confidence-gated response          │  │
│   │  └─ Unknown attack → suggested rules   │  │
│   │  ┌───────────────────────────────────┐ │  │
│   │  │  Response Engine                   │ │  │
│   │  │  ├─ Pause / Isolate / Kill / Log   │ │  │
│   │  │  └─ 10-min cooldown + JSON audit   │ │  │
│   │  └───────────────────────────────────┘ │  │
│   └───────────────────────────────────────┘  │
├─────────────────────────────────────────────┤
│   Kernel Space (eBPF) — 4096-entry Ring Buffer │
│   ┌───────────────────────────────────────┐  │
│   │  Tracepoint Probes (5)                │  │
│   │  ├─ sys_enter_mount                   │  │
│   │  ├─ sys_enter_ptrace                  │  │
│   │  ├─ sys_enter_execve                  │  │
│   │  ├─ sys_enter_connect                 │  │
│   │  └─ sys_enter_openat (path-filtered)  │  │
│   └───────────────────────────────────────┘  │
│   ┌───────────────────────────────────────┐  │
│   │  Ring Buffer (Events)                 │  │
│   │  └─ Low-latency event transmission    │  │
│   └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
ebpf-container-guard/
├── main.py                          # Entry point
├── requirements.txt                 # Python dependencies
├── LICENSE                          # MIT License
├── README.md                        # This file (English)
├── README_CN.md                     # Chinese version / 中文版
├── CHANGELOG.md                     # Version changelog
├── CONTRIBUTING.md                  # Contribution guide
├── Makefile                         # Build/deploy automation
├── src/
│   ├── core/                        # Infrastructure
│   │   ├── identity.py              # Container identity (3-tier fallback + refresh)
│   │   └── event_log.py             # Structured JSON event logger
│   ├── ebpf/
│   │   └── escape-detect.bpf.c      # eBPF kernel probes (5 tracepoints)
│   ├── detector/
│   │   ├── __init__.py
│   │   ├── engine.py                # Tier 1: YAML rule engine
│   │   ├── attack_matrix.py         # Tier 2: behavior→CVE matrix
│   │   └── ai_analyzer.py           # Tier 3: DeepSeek AI judge
│   └── responder/
│       ├── __init__.py
│       └── docker_responder.py      # Docker response engine
├── config/
│   ├── rules.yaml                   # 8 detection rules
│   ├── responses.yaml               # 4-tier response strategies
│   └── ai_config.yaml.example       # DeepSeek API key template
├── deploy/
│   └── Dockerfile.test              # Pre-built strace test image
├── tests/
│   └── integration/
│       └── test_escape_scenarios.sh # Smoke tests
├── demos/
│   └── demo-basic.sh                # Demo script
└── docs/
    └── MVP-运行验证报告.md            # Verification report (bilingual)
```

---

## ⚙️ Configuration

### Detection Rules (`config/rules.yaml`)

```yaml
rules:
  - name: "procfs_mount_escape"
    description: "Detect procfs mount from container"
    severity: "CRITICAL"
    condition:
      event_type: "mount"
      fstype: "proc"
    exclude:
      comm:
        - "dockerd"          # Exclude Docker daemon's normal mounts
        - "containerd"
        - "runc:[2:INIT]"
        - "runc"
      target_path:
        - "/proc/thread-self/fd/*"
    action: "alert_and_log"

  - name: "dangerous_ptrace"
    description: "Detect ptrace on host PID 1 (systemd/init) from container"
    severity: "HIGH"
    condition:
      event_type: "ptrace"
      target_pid: 1         # Match behavior direction, not specific request codes
    action: "alert_and_log"

  - name: "sensitive_file_read"
    description: "Detect reading host sensitive files from container"
    severity: "HIGH"
    condition:
      event_type: "openat"
      target_path:
        - "/host_etc/shadow"
    action: "alert_and_log"
```

### Response Strategies (`config/responses.yaml`)

```yaml
responses:
  - threat_level: critical
    action: pause_container        # Freeze for forensics
  - threat_level: high
    action: isolate_network        # Block lateral movement
  - threat_level: medium
    action: kill_process           # Terminate suspicious process only
  - threat_level: low
    action: log_only               # Audit log only, no automatic action
```

### AI Analysis (`config/ai_config.yaml`)

Enable AI analysis with your API key:

```bash
cp config/ai_config.yaml.example config/ai_config.yaml
# edit the file with your key
```

```yaml
# config/ai_config.yaml (gitignored — never committed)
api_key: "sk-your-api-key-here"
model: "deepseek-chat"

# Any OpenAI-compatible endpoint:
#   DeepSeek:  https://api.deepseek.com/v1
#   OpenAI:    https://api.openai.com/v1
#   Local vLLM: http://localhost:8000/v1
base_url: "https://api.deepseek.com/v1"

# Confidence thresholds for graded response
auto_response_threshold: 85    # > 85% → auto execute response
pending_review_threshold: 60   # 60-85% → AI judge analysis
                               # < 60% → log only
```

The analyzer is **OpenAI-compatible**: swap `base_url` to use OpenAI, or any self-hosted endpoint (vLLM / Ollama) for fully offline operation. Without a key, the system runs in **offline fallback mode**: matrix confidence drives decisions (>85% auto-response, 60-85% flagged for review, <60% silent).

---

## 🔄 Version History

| Version | Features | Status |
|---------|----------|--------|
 | v0.1 | MVP: Basic detection + Docker response (v0.1.1) | ✅ Stable |
| v0.2 | 3-tier detection: rules → attack matrix → AI judge | ✅ Stable |
|       | ↳ v0.2.5 — stable (graded automation, netblock, escalation) | |

| v0.3 | Dashboard: Streamlit prototype (alert stream, container-level review queue, evidence view) | 🚧 Prototype |
|       | ↳ v0.3.2 — current (async AI, no callback blocking) | |
| v0.4 | K8s native support (DaemonSet + NetworkPolicy) | 📋 Planned |
| v1.0 | Stable release for thesis defense | 📋 Dec |

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.

---

## 🧪 Testing

```bash
# Smoke test (dependency check)
bash tests/integration/test_escape_scenarios.sh

# Real-world verification (requires root + Docker + --privileged)
# See Demo section above for step-by-step instructions
```

---

## 📖 Documentation

- [CHANGELOG.md](CHANGELOG.md) — version history and release notes
- [docs/MVP-运行验证报告.md](docs/MVP-运行验证报告.md) — verification report (bilingual)
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

### Development Setup

```bash
# Clone repository
git clone https://github.com/chenjx12/ebpf-container-guard.git
cd ebpf-container-guard

# Install dependencies
pip install -r requirements.txt

# Run in development mode
sudo python3 main.py --verbose
```

---

## 🔒 Security Considerations

- **Privileged Access**: eBPF requires root/sudo privileges
- **Production Use**: Test thoroughly before deploying to production
- **False Positives**: Tune rules based on your environment
- **Performance**: Monitor CPU/memory overhead (typically < 2%)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Maintainer

[@chenjx12](https://github.com/chenjx12)

---

## 📚 Learning Resources

If you want to learn eBPF from scratch, check out my learning notes:
- [eBPF Learning Notes](https://github.com/Chenjx12/ebpf-learning-notes) — Companion tutorial: 19 code examples + 4-part learning path from Hello World to K8s deployment (Chinese)

---

**Last Updated**: 2026-08-07
