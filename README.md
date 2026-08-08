# eBPF Container Guard

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](CHANGELOG.md)
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
- **AI-Powered Analysis** (code ready): DeepSeek API integration for threat confirmation, technique identification, and unknown attack discovery — offline fallback mode verified; real API call pending key
- **Auto Response**: Container isolation (pause/disconnect/kill) with 10-minute cooldown and structured JSON audit logs
- **Configurable**: 8 detection rules + response strategies via YAML, hot-reload support

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
    └── MVP-运行验证报告.md            # v0.2.0 — 3-tier detection
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

---

## 🔄 Version History

| Version | Features | Status |
|---------|----------|--------|
| v0.1.0 | MVP: Code graduated from learning repo, not yet validated | ❌ Broken |
| v0.1.1 | MVP: End-to-end verified (mount + ptrace) | ✅ Stable |
| v0.2.0 | 3-tier detection: rules → attack matrix → AI judge (5 probes, 8 rules) | ✅ Current |
| v0.2.0 | AI analysis integration (DeepSeek API) + confidence-gated response | 📋 Sep |
| v0.3.0 | Streamlit dashboard + human approval queue | 📋 Oct |
| v0.4.0 | K8s native support (DaemonSet + NetworkPolicy) | 📋 Nov |
| v1.0.0 | Stable release for thesis defense | 📋 Dec |

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
- [docs/MVP-运行验证报告.md](docs/MVP-运行验证报告.md) — v0.2.0 verification report
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
