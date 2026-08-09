# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[**中文版 / Chinese Version**](CHANGELOG_CN.md)

## [Unreleased]

### Planned
- Kubernetes native support (v0.4)
- Custom frontend dashboard (CSAI-style, decision record #17)
- Performance benchmarking & systemd deployment

## [0.3.5] - 2026-08-09

### Added
- **Rule management panel** (dashboard):
  - View current rules (name/severity/description/attack_vector)
  - Manually add rules via form (event_type + condition fields) — hot-reload live in 3s
  - Rule change audit trail: `rules_audit.log` records every add (timestamp, action, rule_name, source, full content) — auditable, rollback-capable
- `append_rule_to_yaml(rule, source)` — source: 'ai_suggestion' | 'manual'
- `log_rule_audit()`, `load_rules()`, `load_rule_audit()` dashboard helpers

### Purpose
- Rules are knowledge assets: changes need approval + audit trail (decision record #14 principle — bigger impact, more human control)
- AI can go offline; the rule base runs independently (learning needs AI, execution does not)

### Verified
- Unit: manual + AI rules appended → YAML valid (8→10) → hot-reload → both match
- Audit log: 2 entries with correct source attribution
- Test suite: 15/15 PASS (no regression)

## [0.3.4] - 2026-08-09


### Added
- **AI suggested-rule review loop** (dashboard): AI discovers unknown attack patterns → suggests a rule → human reviews in the dashboard → one-click append to rules.yaml → hot-reload makes it live within 3s (v0.3.3)
- `append_rule_to_yaml()` — formats AI-suggested rule into rules.yaml list item (4-space indent, validated)
- `record_decision(scope='suggested_rule')` — tracks reviewed suggestions (confirm/dismiss)
- This closes the "unknown attack discovery" loop — a thesis innovation point: the system can learn new detection patterns from AI analysis + human approval

### Verified
- Unit: suggested rule → rules.yaml (YAML valid, 8→9 rules) → hot-reload → rule matches
- E2E: AI suggestion injected → rules.yaml appended → guard reloaded (9 rules) → attack triggered new rule (pending_review)

## [0.3.3] - 2026-08-09


### Added
- **Rules hot-reload**: `EscapeDetector.reload()` + mtime watcher thread — modify rules.yaml while guard runs, new rules active within 3s (no restart)
- **Test suite expanded to 15 tests**: static checks + 3-tier modules + core modules (identity/scope/escalation/netblock/decision_executor) + unit behaviors (rule match, matrix combo, escalation, scope, hot-reload, IP conversion, async AI structure)

### Verified
- E2E: modified rules.yaml while guard running → reload logged (8→9 rules) → new rule triggered within seconds
- Unit: reload 8→9→8 rules, new rule matches
- Test suite: 15/15 PASS

## [0.3.2] - 2026-08-09

### Added
- **Async AI analysis** (`AsyncAIAnalyzer` in ai_analyzer.py):
  - AI API calls moved to a background worker queue — ring buffer callback no longer blocks on DeepSeek latency (was seconds)
  - Events are logged instantly, AI verdicts fill in asynchronously to `ai_results.log`
  - AI is now an advisor, not a decision-maker: matrix confidence drives reversible responses, irreversible verdicts wait for humans (v0.3.1)
- **Dashboard**: merges async AI results (ai_results.log) into the review queue — shows "AI 研判中…" while pending, verdict appears when ready

### Fixed
- `time.strftime('%f')` not supported (microseconds) — replaced with `datetime.now().strftime()` for ISO timestamps with milliseconds; event_ts now matches between events.log and ai_results.log

### Verified
- Events on screen within 3s (no AI blocking) — previously waited for API latency
- ai_results.log fills in async: false_positive (30%) and true_positive (85%) correctly identified
- Timestamp matching between events.log ↔ ai_results.log ✅

## [0.3.1] - 2026-08-09

### Added
- **Decision executor** (`src/core/decision_executor.py`) — closes the human-in-the-loop loop:
  - Dashboard verdicts (decisions.log) are now EXECUTED by guard
  - `confirmed` → container killed (human-authorized irreversible action)
  - `dismissed` → isolation released (unpause + network reconnect)
  - Execution result written back to decisions.log (`executed` field + timestamp)
  - Startup seeds already-processed entries (no re-execution of old verdicts)

### Purpose
- The final step of human-machine collaboration: human verdict → guard executes
- Previously verdicts only landed in decisions.log with no effect (loop was broken)

### Verified
- dismissed → container unpaused (paused → running) ✅
- confirmed → container killed (paused → exited) ✅
- decisions.log shows executed=True + executed_at ✅

## [0.3.0] - 2026-08-09

### Added
- **Streamlit security dashboard** (`dashboard/app.py`): overview metrics, live alert stream (3s auto-refresh via st.fragment), container filter
- **Human review queue** — container-level (decision record #18): verdicts act on the container, all its pending events cascade-marked
- **Evidence view** (decision record #19): container profile (image/privileged/status/ports via Docker API) + behavior timeline (attack chain from events.log)
- Decisions persisted to `decisions.log` (scope=container)

### Fixed
- **Dashboard blank page**: auto-refresh loop (sleep→rerun) never rendered — replaced with `st.fragment(run_every=3)`
- **Verdict not disappearing**: `load_decisions` cache not cleared after decision — added `load_decisions.clear()`
- **Kill executed on repeated attacks** (v0.2.5 fix): irreversible actions ALWAYS queue for human review (decision record #14)

### Known Issue
- AI sync call blocks ring buffer callback during API latency — deferred to async AI / background queue

### Verified
- Alert stream real-time: mount escape + reverse shell → 6 events on screen
- Container-level review: 4 containers grouped, verdict cascades (17 events → one click)
- Repeated attacks: containers survive (kill queued, never auto)

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