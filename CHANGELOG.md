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