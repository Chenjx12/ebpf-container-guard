# eBPF Container Guard

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.6.3-green.svg)](CHANGELOG.md)
[![eBPF](https://img.shields.io/badge/eBPF-tracepoint-orange.svg)](https://ebpf.io/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

> ⚠️ **Development Preview**: This project is in active **preview development** (0.x).
> It may introduce **breaking / incompatible changes** at any point.
> GitHub **releases are for tracking changes only** — they do not imply a stable
> API surface or production readiness. Not yet recommended for production use.
> Test thoroughly in your environment before depending on a specific behavior.

> 🛡️ AI-enhanced container escape detection system based on eBPF  
> Real-time Detection · Intelligent Analysis · Auto Response · Cloud-Native Ready

[**中文版 / Chinese Version**](README_CN.md)

---

## 🎯 Key Features

- **3-Tier Detection Pipeline**: Rule engine (12 rules, sub-ms) → Attack matrix (10 vectors × 8 combo rules, behavior→CVE mapping, combination scoring) → AI judge (DeepSeek, confidence-gated response)
- **6 eBPF Probes**: mount, ptrace, execve, connect, capset, openat (kernel-space path filter)
- **Behavior Logger**: ALL syscall events recorded to `behaviors.log` (buffered + daily rotation, 7-day retention) with configurable toggle — full behavioral timeline for post-incident analysis and audit
- **Dashboard** (v0.6.0): 11-page FastAPI + Vue3 panel — REST API backend (nginx-ready) + zero-build SPA: Overview, **Asset Management (topology graph)**, Alerts, Review Queue, Behavior Log, Rules, AI Rules, **Attack Chain Analysis (flow chart)**, Settings, Members — role-based access + temporary token delegation (lower-privilege only); Swagger /docs disabled by default (`ENABLE_DOCS=1`)
- **Container Identity**: 3-tier fallback (PID Map → Cgroup Inode → /proc/cgroup) with background refresh
- **AI-Powered Analysis** (live-tested): DeepSeek API integration for threat confirmation, technique identification, and unknown attack discovery — **multi-profile management** (ai_profiles.yaml, fetch model list + named configs + one-click switch via sidebar quick panel); verified with real API calls, correctly distinguishes true positives from false positives
- **Graded Automation** (human-in-the-loop): reversible actions auto-execute (pause/isolate/network block); irreversible verdicts (kill/image blocklist) queue for human review — AI suggestions execute with confidence guardrails
- **Network Traffic Blocking**: iptables DROP for confirmed malicious IP:port (reversible, TTL cleanup, business traffic preserved)
- **Response Escalation**: repeated attacks from the same image escalate pause → kill (queued) → image blocklist (queued), stopping attack loops
- **Event State Machine**: every event tracked as new → quarantine → pending_review → resolved (foundation for the v0.3 review dashboard)
- **Configurable**: 12 detection rules + response strategies + monitoring scope (include/exclude containers) via YAML, hot-reload support

---

## 🚀 Quick Start

### Prerequisites

- **OS**: Ubuntu 22.04 LTS (kernel ≥ 5.15)
- **Python**: 3.8+
- **Docker**: Installed and running
- **Permissions**: Root or sudo access required for eBPF

### Option 1: One-Click Run (recommended)

```bash
git clone https://github.com/chenjx12/ebpf-container-guard.git
cd ebpf-container-guard
./setup.sh                  # 环境初始化（幂等，新机器用）
./run.sh                    # guard (background) + dashboard (foreground)
```

### Option 1b: Container Image (v0.6.1+, GHCR)

```bash
# 1) Pull
docker pull ghcr.io/chenjx12/ebpf-container-guard:v0.6.3

# 2) Run — privileged flags are REQUIRED for eBPF (not optional):
#    --privileged / --pid=host / --network host, /sys for BTF+tracefs,
#    docker.sock for container identity resolution
docker run -d --name guard \
  --privileged --pid=host --network host \
  -v /sys:/sys \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/lib/ebpf-guard:/app/logs \
  ghcr.io/chenjx12/ebpf-container-guard:v0.6.3

# 3) Open the dashboard at http://localhost:8000 — initial passwords are
#    printed to the container logs on first start (admin/test, forced
#    password change on first login):
docker logs guard 2>&1 | head -20    # look for the "初始账号已创建" line
```

> **Supply-chain evidence (v0.6.2/0.6.3, ADR-049)**: every release ships three downloadable
> assets — `sbom.<tag>.cdx.json` (CycloneDX SBOM), `trivy-report.<tag>.json`
> (image-layer scan) and `trivy-fs-report.<tag>.json` (dependency-layer scan:
> requirements.txt / Dockerfile / sources, vuln+secret). Both scan layers are
> independently gated (CRITICAL/HIGH, ignore-unfixed) before release. **Image tag
> = git tag string** (`...:v0.6.3` ↔ tag `v0.6.3`); `latest` only marks the newest
> release — pin a fixed tag for demos (v0.6.0 is the permanent safety-net
> fallback). See [docs/image-tag-policy.md](docs/image-tag-policy.md).
> The DaemonSet form still uses `deploy/k8s/daemonset.yaml` (image switchover to GHCR follows within v0.6.x).

### Option 2: Separate Terminals

```bash
# Terminal 1: start guard
sudo python3 main.py

# Terminal 2: start dashboard
./run.sh --ui
# or: make panel
```

### Option 3: Custom Configuration

```bash
sudo python3 main.py \
  --rules config/rules.yaml \
  --responses config/responses.yaml \
  --verbose
```

### Option 3b: systemd Deployment (single-host / edge / isolated networks, v0.4.3)

For environments **without a K8s cluster** (isolated intranets / edge nodes);
use DaemonSet inside clusters (v0.5.3+).

```bash
sudo make build                                    # precompile CO-RE probes (first use)
sudo cp deploy/systemd/ebpf-guard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-guard             # auto-start on boot + start now
sudo journalctl -u ebpf-guard -f                   # live logs
```

- Stop old instances before deploying to avoid double processes: `sudo pkill -f "python3 -u main.py"`
- `systemctl stop ebpf-guard` exits cleanly (SIGTERM → XDP detach + iptables cleanup)
- After SIGKILL, XDP block may remain: `sudo bpftool net detach xdp dev docker0 && sudo rm -f /sys/fs/bpf/guard_xdp_block`

### Option 4: Test with pre-built strace image (ptrace escape)

```bash
docker build -f deploy/Dockerfile.test -t ebpf-test:latest .
docker run -d --privileged --pid=host --cap-add=SYS_PTRACE --name test ebpf-test:latest
docker exec test strace -p 1  # triggers HIGH alert
```

### Option 5: Dashboard with Login (RBAC)

```bash
# Terminal 1: start guard
sudo python3 main.py

# Terminal 2: start dashboard (foreground)
python3 -m uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 1
# → open http://localhost:8000
# → FIRST launch: initial admin password is printed in THIS terminal
#   (username: admin) — change it immediately after first login
```

Roles: admin > operator > analyst. Admin manages members; operator adds rules;
analyst handles verdicts / AI review. Low-role users can request temporary
tokens from higher roles for privileged operations (settings page).

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
规则: ptrace_host_init
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
│   │  Tier 1: Rule Engine (12 YAML rules)    │  │
│   │  ├─ mount, ptrace, execve, connect,    │  │
│   │  │   openat, capset — 6 attack surfaces │  │
│   │  ├─ Whitelist exclusion + fnmatch      │  │
│   │  └─ Severity: CRITICAL / HIGH          │  │
│   ├───────────────────────────────────────┤  │
│   │  Tier 2: Attack Matrix                 │  │
│   │  ├─ 10 vectors × 8 combo rules          │  │
│   │  ├─ 10s window combination scoring     │  │
│   │  └─ Behavior → CVE mapping             │  │
│   ├───────────────────────────────────────┤  │
│   │  Tier 3: AI Judge (DeepSeek)           │  │
│   │  ├─ Confidence-gated response          │  │
│   │  └─ Unknown attack → suggested rules   │  │
│   │  ┌───────────────────────────────────┐ │  │
│   │  │  Response Engine (Docker + K8s)    │ │  │
│   │  │  ├─ Pause / Isolate / Kill / Log   │ │  │
│   │  │  ├─ 10-min cooldown + JSON audit   │ │  │
│   │  │  └─ CNI-aware: iptables / NetworkPolicy │ │  │
│   │  └───────────────────────────────────┘ │  │
│   └───────────────────────────────────────┘  │
├─────────────────────────────────────────────┤
│   Kernel Space (eBPF) — 4096-entry Ring Buffer │
│   ┌───────────────────────────────────────┐  │
│   │  Tracepoint Probes (6)                │  │
│   │  ├─ sys_enter_mount                   │  │
│   │  ├─ sys_enter_ptrace                  │  │
│   │  ├─ sys_enter_execve                  │  │
│   │  ├─ sys_enter_connect                 │  │
│   │  ├─ sys_enter_openat (path-filtered)  │  │
│   │  └─ sys_enter_capset                 │  │
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
├── run.sh                           # One-click start script (v0.3.11)
├── setup.sh                         # Environment setup (idempotent, v0.3.11)
├── main.py                          # Entry point
├── requirements.txt                 # Python dependencies
├── LICENSE                          # Apache-2.0 License
├── README.md                        # This file (English)
├── README_CN.md                     # Chinese version / 中文版
├── CHANGELOG.md                     # Version changelog
├── CONTRIBUTING.md                  # Contribution guide
├── Makefile                         # Build/deploy automation
├── src/
│   ├── core/                        # Infrastructure
│   │   ├── bpf_runtime.py           # CO-RE loader (vmlinux.h + hand-rolled ctypes)
│   │   ├── libbpf.py                # libbpf.so.1 bindings (ctypes)
│   │   ├── identity.py              # Container identity (3-tier fallback + refresh)
│   │   ├── event_log.py             # Structured JSON event logger
│   │   ├── behavior_logger.py       # ALL syscall events → behaviors.log (v0.3.10)
│   │   ├── scope.py                 # Monitoring scope (include/exclude containers)
│   │   ├── escalation.py            # Response escalation (pause → kill → blocklist)
│   │   ├── netblock.py              # iptables FORWARD DROP (reversible)
│   │   ├── netblock_xdp.py          # XDP ingress block + CompositeNetBlocker
│   │   ├── decision_executor.py     # Execute human verdicts from decisions.log
│   │   ├── k8s_decision_executor.py # K8s verdict executor (confirmed→delete / dismissed→restore)
│   │   ├── kube_utils.py            # In-cluster kubeconfig resolution (SA + fallback)
│   │   └── netpol_detect.py         # CNI auto-detect (v0.6.0, multi-signal voting)
│   ├── ebpf/
│   │   ├── escape-detect.bpf.c      # eBPF kernel probes (6 tracepoints)
│   │   └── xdp-block.bpf.c          # XDP packet filter program (v0.3.9)
│   ├── detector/
│   │   ├── __init__.py
│   │   ├── rule_schema.py           # Rule schema validator (Falco-style condition trees)
│   │   ├── engine.py                # Tier 1: YAML rule engine (hot-reload)
│   │   ├── attack_matrix.py         # Tier 2: behavior→CVE matrix (10 vectors × 8 combo)
│   │   └── ai_analyzer.py           # Tier 3: DeepSeek AI judge (async)
│   └── responder/
│       ├── __init__.py
│       ├── docker_responder.py      # Docker response engine (graded automation)
│       ├── k8s_responder.py         # K8s response engine (freeze / isolate / delete pod)
│       ├── isolation_backend.py     # IsolationBackend interface + NsenterIptablesBackend
│       └── k8s_network_policy.py    # NetworkPolicyBackend (deny-all, CNI-aware, v0.6.0)
├── config/
│   ├── rules.yaml                   # 12 detection rules
│   ├── responses.yaml               # 4-tier response strategies
│   ├── monitor.yaml                 # Monitoring scope + netblock backend + behavior_log toggle
│   ├── ai_profiles.yaml             # AI multi-profile configs (single source of truth)
│   ├── ai_config.yaml.example       # DeepSeek API key template
│   ├── users.yaml.example           # RBAC user configuration template
│   └── blocklist.yaml               # Blocked images list
├── server/                          # FastAPI + Vue3 dashboard (v0.5.6+, nginx-ready)
│   ├── app.py                       # FastAPI entry (RBAC + temp-token gating)
│   ├── deps.py                      # Role dependency guards (admin/operator/analyst)
│   ├── common.py                    # Shared log/event loaders (GUARD_LOGS_DIR aware)
│   ├── routes.py                    # REST API endpoints (24+)
│   └── static/                      # Zero-build Vue3 SPA (11 pages, Element Plus CDN)
├── dashboard/                       # Legacy Streamlit dashboard (deprecated, v0.5.6+)
│   ├── app.py                       # Entry point + navigation + forced password change
│   ├── common.py                    # Shared data loading utilities
│   ├── auth.py                      # AuthManager + TokenManager (RBAC)
│   └── pages/                       # 7 pages (kept for rollback)
├── tests/
│   ├── unit/                        # Unit tests (79 test functions)
│   │   ├── conftest.py              # Shared fixtures
│   │   ├── test_rule_schema.py      # Rule schema / condition tree tests
│   │   ├── test_matcher.py          # Rule matcher tests
│   │   ├── test_dashboard_utils.py  # Dashboard utility tests
│   │   ├── test_behavior_logger.py  # Behavior logger tests
│   │   ├── test_api_auth.py         # API RBAC / auth tests (v0.5.6)
│   │   └── test_netpol.py           # NetworkPolicy + CNI detection (v0.6.0)
│   ├── integration/
│   │   ├── test_escape_scenarios.sh # Smoke tests (15 checks)
│   │   └── scenarios/               # 8 E2E scenario tests
│   │       ├── lib.sh               # Shared lifecycle helpers
│   │       ├── build_image.sh       # Proxy-aware Docker image builder
│   │       ├── run_all_scenarios.sh # One-click scenario runner
│   │       ├── test_mount_escape.sh
│   │       ├── test_socket_mount.sh
│   │       ├── test_ptrace_escape.sh
│   │       ├── test_sensitive_file.sh
│   │       ├── test_reverse_shell.sh
│   │       ├── test_nsenter.sh
│   │       ├── test_cgroup_escape.sh
│   │       └── test_capset.sh
│   ├── k8s/                         # k3s E2E scenarios (v0.5.5)
│   │   └── scenarios/
│   │       ├── lib_k8s.sh           # run_escape_pod + guard readiness polling
│   │       └── run_all_k8s.sh       # 6 scenarios × 4 assertions
│   └── images/                      # Test Dockerfiles for each scenario
├── tools/
│   ├── bpf_smoke.py                 # Probe smoke test (6 probes)
│   └── bench_openat.py              # Performance benchmark (v0.4.3)
├── scripts/
│   └── migrate_rules_v04.py         # v0.3 → v0.4 rule schema migration
├── deploy/
│   ├── Dockerfile.guard             # Guard container image (k3s DaemonSet)
│   ├── Dockerfile.test              # Pre-built strace test image
│   ├── k8s/                         # configmap.yaml / daemonset.yaml / rbac.yaml
│   ├── systemd/                     # ebpf-guard.service (single-host, v0.4.3)
│   └── libbpf/                      # Bundled libbpf.so / libelf.so for container runtime
└── docs/
    ├── ADRs/                        # 19 Architecture Decision Records
    ├── MVP-运行验证报告.md / MVP-verification-report.md
    ├── 验证报告-v0.4.1.md / verification-report-v0.4.1.md
    ├── performance-report.md        # Bench results (v0.4.3)
    └── k8s-multi-node-demo.md       # 3-VM demo guide (v0.5.7)
```

---

## ⚙️ Configuration

### Detection Rules (`config/rules.yaml`)

Rules use a **Falco-style condition tree** (v0.4.0): `all` (AND) / `any` (OR) / `not` (negation) nested arbitrarily; leaf operators include `neq` / `startswith` / `endswith` / `contains` / `glob` / `exists`. `event_type` is a top-level key (indexing), never inside condition.

```yaml
rules:
  - name: "procfs_mount_escape"
    description: "Detect procfs mount from container"
    severity: "CRITICAL"
    event_type: "mount"
    condition:
      all:
        - fstype: "proc"
        - not:
            any:
              - comm:                  # Exclude infrastructure processes
                  - "dockerd"
                  - "containerd"
                  - "runc:[2:INIT]"
                  - "runc"
              - target_path:           # glob wildcard exclusion
                  - {glob: "/proc/thread-self/fd/*"}
    action: "alert_and_log"

  - name: "ptrace_host_init"
    description: "Detect ptrace on host PID 1 (systemd/init) from container"
    severity: "HIGH"
    event_type: "ptrace"
    condition:
      target_pid: 1         # Match behavior direction, not specific request codes
    action: "alert_and_log"

  - name: "sensitive_file_access"
    description: "Detect reading host sensitive files from container"
    severity: "HIGH"
    event_type: "openat"
    condition:
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
| v0.1 | MVP: Basic detection + Docker response | ✅ Released |
| v0.2 | 3-tier detection + graded automation (netblock, escalation) | ✅ Released |
| v0.3 | Dashboard + human-in-the-loop (multi-page, RBAC, XDP+iptables blocking, async AI, behavior logger) | ✅ Released |
| v0.4 | Rule engine rewrite (Falco-style condition trees) + BCC→libbpf CO-RE migration (hand-rolled ctypes loader) | ✅ Released |
|       | ↳ v0.4.3 — production prep (systemd + perf) | ✅ Released |
|       | ↳ v0.4.4 — behavior log IO (buffered + rotation) | ✅ Released |
| v0.5 | Single-instance lock (deployment-mode exclusion) → K8s DaemonSet native | ✅ Released |
|       | ↳ v0.5.0 — single-instance lock | ✅ Released |
|       | ↳ v0.5.1 — K8s container discovery + identity | ✅ Released |
|       | ↳ v0.5.2 — K8s responder (response loop) | ✅ Released |
|       | ↳ v0.5.3 — DaemonSet deployment (guard containerized on k3s) | ✅ Released |
|       | ↳ v0.5.4 — Network blocking (nsenter real isolation + adapt blueprint) | ⏹ Archived |
|       | ↳ v0.5.5 — K8s E2E scripting | ⏹ Archived |
|       | ↳ v0.5.6 — Panel migration (Streamlit→FastAPI+Vue3) | ⏹ Archived |
|       | ↳ v0.5.7 — Asset mgmt + topology + AI multi-config | ⏹ Archived |
|       | ↳ v0.5.8 — Attack chain analysis page | ⏹ Archived |
| v0.6 | NetworkPolicy isolation (CNI auto-detect) + Apache-2.0 license | ✅ Released |
|      | ↳ v0.6.0 — NetworkPolicy + Apache-2.0 migration | ✅ Released |
|      | ↳ v0.6.1 — GHCR all-in-one image + CI supply chain (ADR-048) | ✅ Released |
|      | ↳ v0.6.2 — supply-chain evidence chain: dependency-layer scan + image/git tag policy (ADR-049) | ✅ Released |
|      | ↳ v0.6.2.1 — hotfix: dashboard blank screen (app.js syntax corruption; render-level check discipline) | ✅ Released |
|      | ↳ v0.6.3 — asset inference + state persistence: AssetClassifier/AssetStore state machine (PENDING_REVIEW→CONFIRMED/OVERRIDDEN), 3-segment audit trail, /api/assets docker list + confirm/override/audit; ride-alongs: netblock snapshot+idempotent replay, Dockerfile iptables fix, netpol orphan sweep, host events log-only, entrypoint -u fix (ADR-050) | ✅ Released |
|      | ↳ v0.6.4 ~ v0.6.8 — asset UI / incremental log load / six-layer audit (bp_v06x: weekly releases) | 📋 In progress |
| v0.7 | Next batch: Guard Agent (ex-blueprint v0.8 scope, thesis core dev period) | 📋 Planned |
| v1.0 | First stable release (post-preview) | 📋 Planned |

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.

---

## 🏗️ Architecture Decisions (ADRs)

This project records key architecture decisions as **ADRs (Architecture Decision Records)** —
"why the code looks like this". Each decision is a standalone document, covering
probe selection (kprobe → tracepoint → CO-RE), detection architecture (behavior matrix),
response strategy (reversible-first), network blocking (XDP hybrid backend),
and the rule engine (Falco-style condition trees).

📄 [docs/ADRs/](docs/ADRs/) — decision index and full texts

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

## License

Licensed under the Apache License, Version 2.0.

> **License History**: Versions ≤ v0.5.x are MIT Licensed.
> Versions ≥ v0.6.0 are Apache-2.0 Licensed.
> See the [LICENSE](LICENSE) file for details.

---

## 👤 Maintainer

[@chenjx12](https://github.com/chenjx12)

---

## 📚 Learning Resources

If you want to learn eBPF from scratch, check out my learning notes:
- [eBPF Learning Notes](https://github.com/Chenjx12/ebpf-learning-notes) — Companion tutorial: 19 code examples + 4-part learning path from Hello World to K8s deployment (Chinese)

---

**Last Updated**: 2026-08-26
