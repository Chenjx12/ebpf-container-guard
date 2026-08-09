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

## [0.2.5] - 2026-08-09

### Added
- **Graded automation** (decision record #14): reversible actions auto-execute (pause/isolate/netblock); irreversible actions (kill/block) queue for human review — even with AI confidence ≥ 85%
- **AI suggestions now execute**: `handle_alert(forced_action, ai_confidence)` — AI-suggested action runs, with guardrail: kill/block requires AI confidence ≥ 85%, otherwise queued
- **Network traffic blocking** (`src/core/netblock.py`): iptables FORWARD DROP for malicious IP:port (reversible, TTL 1h auto-cleanup, business traffic preserved)
- **Response escalation** (`src/core/escalation.py`): same-image repeated attacks → hit1 pause / hit2 kill (queued) / hit3 image blocklist (queued, persisted to config/blocklist.yaml)
- **Event state machine** (decision record #16): `state` field in log — new / quarantine / pending_review / resolved; LOG_FORMAT_VERSION → 2
- Container image lookup: `identity.get_image()` (cold path + cache, same pattern as get_name)

### Purpose
- Human-in-the-loop: reversible actions fill the response gap instantly, irreversible verdicts go to the dashboard queue (v0.3)
- Attack loops: re-launching the same image escalates to blocklist

### Verified
- E2E: reverse shell → iptables DROP rule inserted (114.47.114.97:12150), netblocked=true in log
- Unit: escalation pause→kill→block progression + blocklist persistence; state machine mapping
- Regression: default monitoring unchanged

## [0.2.4] - 2026-08-09

### Added
- **Event-driven map refresh** (primary channel): Docker events (start/die) update container maps in real-time — container identity resolved instantly, no more waiting for the 5s poll
- **Polling fallback** (secondary channel): 5s full scan retained, catches containers running before guard start or events dropped during reconnect
- **Docker event handlers**: `_on_container_start` (add to cgroup map + name index + BPF PID map with retry), `_on_container_stop` (remove by ID match — cgroup dir may be gone on die)

### Changed
- `ContainerIdentity` now runs two background threads: events listener + polling
- Event stream errors auto-reconnect with 2s backoff

### Purpose
- Eliminates the cold-path window: container attacks within 1s of creation are correctly attributed (previously required on-demand Docker lookup)
- Foundation for reliable identity tracking under high container churn

### Verified
- E2E: mount escape 1s after container start → 3/3 alerts correctly attributed to container ID
- Unit: start event adds to all maps; die event removes from all maps (by ID, no cgroup stat)
- Regression: default monitoring unchanged

## [0.2.3] - 2026-08-09