# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[**中文版 / Chinese Version**](CHANGELOG_CN.md)

## [Unreleased]

### Planned
- Streamlit dashboard (v0.3)
- Kubernetes native support (v0.4)
- Performance benchmarking & systemd deployment

## [0.2.3] - 2026-08-09

### Added
- **Configurable monitoring scope** (`config/monitor.yaml`): choose which containers to monitor
  - `include`: whitelist mode — monitor ONLY listed containers (fnmatch wildcards)
  - `exclude`: blacklist mode — never monitor listed containers (takes priority)
  - `match_by`: match by container name or short ID
  - Empty lists = monitor all (default, behavior unchanged)
- **ContainerScope** (`src/core/scope.py`): standalone module, follows modularized architecture
- **Cold-path name resolution** (`src/core/identity.py`): container name resolved on-demand via Docker API when background refresh hasn't caught up, then cached

### Purpose
- Foundation for v0.3 dashboard container filtering
- Users can scope monitoring to production containers only, or exclude noisy test containers

### Verified
- Unit tests: 5/5 scope logic (default, include, exclude, priority, match_by=id)
- E2E exclude: container `t_exc` produces 0 alerts even on cold path (mount escape before background refresh)
- E2E include: only `t_inc` alerts (4/4 from included container, non-included produces 0)
- Regression: default config monitors all (3 alerts)

## [0.2.2] - 2026-08-09

### Changed
- **Modularized codebase**: extracted `ContainerIdentity` (identity.py) and `EventLogger` (event_log.py) into `src/core/`, main.py now focuses on pipeline orchestration
- **Event log enhanced**: `version` field, millisecond timestamps, `action_status` (executed / skipped_host / skipped_cooldown / error), parameterized `tier1_match`
- **EventLogger absolute path**: log written to project root regardless of CWD

### Fixed
- **docker-py 7.x compatibility**: `Container.disconnect()` removed in docker-py 7.x — network isolation now uses `Network.disconnect(container)`; verified `DISCONNECTED from bridge`
- **Silent response failure**: `isolate_network` now returns success/failure, `handle_alert` returns actual execution status (no more false 'executed' when action failed)
- **Broken variable ref**: `event_pid → event.pid` during refactor

### Verified
- mount escape → CRITICAL → pause_container → status=executed
- reverse shell → HIGH → isolate_network → DISCONNECTED from bridge
- Cooldown mechanism → status=skipped_cooldown (592s remaining)

## [0.2.0] - 2026-08-08

### Added
- **3-Tier Detection Pipeline**: Rule engine (Tier 1) → Attack matrix (Tier 2) → AI judge (Tier 3)
- **3 new eBPF probes**: execve, connect, openat (kernel-space path filter)
- **Attack matrix** (`src/detector/attack_matrix.py`): 8 attack vectors mapped to CVEs, 6 combination boost rules, 10s time window
- **AI analyzer** (`src/detector/ai_analyzer.py`): DeepSeek API integration (live-tested), confidence-gated response (>85% auto / 60-85% review / <60% log), offline fallback mode verified
- **5 new YAML rules**: docker_socket_mount, nsenter_escape, privileged_exec, reverse_shell, sensitive_file_access, host_directory_access
- Ring Buffer upgraded from 256 to 4096 entries

### Changed
- Detection pipeline now enriched: alerts include attack_vector, cve_refs, matrix_confidence
- Host process events automatically filtered for container-specific rules
- Rule engine now supports `attack_vector` and `cve_refs` fields

### Verified
- Single hit: procfs_mount → confidence 85%
- Combo hit: procfs_mount + sensitive_file_access → confidence 88% → auto-response triggered
- 5-probe Ring Buffer stable at 4096 entries with kernel-space openat filter

## [0.1.1] - 2026-08-08

### Fixed
- **main.py completely non-functional** — rewrote based on working reference
  ([`escape-respond.py`](https://github.com/Chenjx12/ebpf-learning-notes/blob/main/code/09-response/escape-respond.py)). Imports were
  pointing to non-existent class names (`DetectionEngine` → `EscapeDetector`,
  `DockerResponder` → `ResponseEngine`). eBPF loading, Ring Buffer consumption,
  and detection-response pipeline were entirely missing.
- **Container ID always "host" for `docker exec` processes** — added background
  thread refreshing PID→container map and cgroup→container map every 5s.
- **Ring Buffer flooded by openat events** — openat probe disabled by default
  (high-frequency syscall, 256-entry buffer overflows instantly). Users can
  re-enable after increasing `RINGBUF_SIZE` and adding kernel-space path filter.

### Changed
- eBPF probing strategy documented: tracepoint (`syscalls:sys_enter_*`) confirmed
  working on kernel 6.8. kprobe (`__x64_sys_*`) approach tested and rejected
  — `PT_REGS_PARM` macro inaccessible under kernel 6.8 syscall wrapper.

### Verified
- End-to-end pipeline: eBPF tracepoint → Ring Buffer → rule engine → CRITICAL
  alert → Docker `pause_container` action executed
- Verified with real privileged container: `mount -t proc proc /tmp/host_proc`
  correctly detected, container auto-paused

## [0.1.0] - 2026-08-07

### Added
- Initial release with MVP functionality
- eBPF kernel probes for mount/ptrace/openat syscalls
- YAML-based detection rule engine
- Docker response engine (pause/disconnect network)
- Ring Buffer for low-latency event transmission
- Cgroup-based container identity recognition
- Integration test suite
- Comprehensive documentation

### Features
- Real-time container escape detection
- Automatic response within 100ms
- Configurable detection rules via YAML
- Hot-reload support for rules and responses
- Color-coded CLI output with severity levels

### Technical Stack
- eBPF tracepoints (kernel space)
- Python 3.8+ with BCC framework
- Docker SDK for container management
- YAML for configuration

---

## Version Planning

- **v0.3** (Oct 2026): Streamlit dashboard
- **v0.4** (Nov 2026): Kubernetes native support
- **v1.0** (Dec 2026): Stable release for thesis defense

