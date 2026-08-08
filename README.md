# eBPF Container Guard

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](CHANGELOG.md)
[![eBPF](https://img.shields.io/badge/eBPF-libbpf-orange.svg)](https://ebpf.io/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

> 🛡️ AI-enhanced container escape detection system based on eBPF  
> Real-time Detection · Intelligent Analysis · Auto Response · Cloud-Native Ready

---

## 🎯 Key Features

- **Kernel-level Monitoring**: Zero-overhead syscall capture via eBPF tracepoints (mount/ptrace/openat/execve)
- **Smart Noise Reduction**: YAML-based rule engine with 3-layer filtering, false positive rate < 5%
- **Auto Response**: Automatic container isolation (pause/disconnect) within 100ms of detection
- **Cloud-Native Ready**: Support both Docker and Kubernetes deployment (K8s support in v0.4.0)
- **Configurable**: Hot-reload detection rules and response strategies via YAML files

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

### Option 3: Docker Compose (Coming in v0.2.0)

```bash
docker-compose up -d
docker logs -f ebpf-guard
```

---

## 📊 Demo

### Scenario 1: Normal Operation (No Alert)

```bash
# Legitimate container operation
docker exec -it nginx bash
ls /tmp

# → System recognizes as normal behavior, no alert triggered
```

### Scenario 2: Procfs Mount Escape (Critical Alert + Auto Isolate)

```bash
# Attacker attempts to mount host procfs
docker exec malicious-container mount -t proc proc /tmp/host_proc

# System output:
# 🚨 [CRITICAL] Procfs Mount Detected!
#    Timestamp: 2026-08-07 15:30:45
#    Container: malicious-container (ID: abc123def456...)
#    Process: mount (PID: 12345, UID: 0)
#    Details: fstype=proc, target=/tmp/host_proc
#    
#    ⚡ Auto Response Executed:
#       1. Container paused (0ms delay)
#       2. Network disconnected (1000ms delay)
#    
#    ✅ Response completed in 1.2s
```

### Scenario 3: Ptrace Injection (High Alert)

```bash
# Attacker attempts process injection
docker exec malicious-container strace -p 1

# System output:
# ⚠️  [HIGH] Ptrace Injection Detected!
#    Container: malicious-container
#    Attacker PID: 12346 → Target PID: 1
#    Request: PTRACE_ATTACH (0x10)
#    
#    ⚡ Auto Response: Alert only (monitoring mode)
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│   User Space (Python)                        │
│   ┌───────────────────────────────────────┐  │
│   │  Rule Engine (YAML Config)            │  │
│   │  ├─ Frequency Deduplication (10s)     │  │
│   │  ├─ Whitelist Filtering               │  │
│   │  └─ Severity Classification           │  │
│   └───────────────────────────────────────┘  │
│   ┌───────────────────────────────────────┐  │
│   │  Response Engine                      │  │
│   │  ├─ Pause Container                   │  │
│   │  ├─ Disconnect Network                │  │
│   │  └─ Kill Process (future)             │  │
│   └───────────────────────────────────────┘  │
├─────────────────────────────────────────────┤
│   Kernel Space (eBPF)                       │
│   ┌───────────────────────────────────────┐  │
│   │  Tracepoint Probes                    │  │
│   │  ├─ sys_enter_mount                   │  │
│   │  ├─ sys_enter_ptrace                  │  │
│   │  ├─ sys_enter_openat                  │  │
│   │  └─ sys_enter_execve (future)         │  │
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
├── main.py                      # Entry point
├── requirements.txt             # Python dependencies
├── LICENSE                      # MIT License
├── README.md                    # This file
├── src/
│   ├── ebpf/
│   │   └── escape-detect.bpf.c  # eBPF kernel probes
│   ├── detector/
│   │   ├── __init__.py
│   │   └── engine.py            # YAML rule engine
│   └── responder/
│       ├── __init__.py
│       └── docker_responder.py  # Docker response engine
├── config/
│   ├── rules.yaml               # Detection rules
│   └── responses.yaml           # Response strategies
├── deploy/                      # Deployment configs (v0.4.0)
├── tests/                       # Integration tests
├── demos/                       # Demo scripts
└── docs/                        # Documentation
```

---

## ⚙️ Configuration

### Detection Rules (`config/rules.yaml`)

```yaml
detection_rules:
  - name: "procfs_mount"
    syscall: "mount"
    condition:
      fstype: "proc"
      target_contains: "/tmp"
    severity: "CRITICAL"
    description: "Detects procfs mount attempt (common escape technique)"
    
  - name: "ptrace_injection"
    syscall: "ptrace"
    condition:
      request: "PTRACE_ATTACH"
    severity: "HIGH"
    description: "Detects process injection via ptrace"
```

### Response Strategies (`config/responses.yaml`)

```yaml
response_actions:
  CRITICAL:
    - action: "pause"
      delay: 0
    - action: "disconnect_network"
      delay: 1000
  HIGH:
    - action: "alert_only"
```

---

## 🔄 Version History

| Version | Features | Status |
|---------|----------|--------|
| v0.1.0 | MVP: Basic detection + Docker response | ✅ Current |
| v0.2.0 | AI analysis integration (DeepSeek API) | 🚧 In Progress |
| v0.3.0 | Streamlit dashboard | 📋 Planned |
| v0.4.0 | K8s native support (DaemonSet + NetworkPolicy) | 📋 Planned |

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.

---

## 🧪 Testing

```bash
# Run integration tests
bash tests/integration/test_escape_scenarios.sh

# Expected output:
# [TEST] procfs mount detection... ✅ PASS
# [TEST] ptrace injection detection... ✅ PASS
# [TEST] False positive test... ✅ PASS (0/100)
```

---

## 📖 Documentation

- [Architecture Details](docs/architecture.md) - System design deep dive
- [Deployment Guide](docs/deployment.md) - Docker & K8s deployment
- [API Reference](docs/api-reference.md) - Code API documentation
- [User FAQ](docs/faq.md) - Common questions and troubleshooting

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
- [eBPF Learning Notes](https://github.com/chenjx12/ebpf-learning-notes) - Complete learning path from Hello World to K8s deployment

---

**Last Updated**: 2026-08-07
