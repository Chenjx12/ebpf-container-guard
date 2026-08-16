# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[**中文版 / Chinese Version**](CHANGELOG_CN.md)

## [0.5.7] - 2026-08-16

### Added
- **Asset management page** (`GET /api/assets` + sidebar entry):
  - **Topology graph** (ECharts, starfield background): nodes = pods clustered
    by physical node, namespace coloring, draggable/zoomable view, click pod
    for detail dialog
  - **Service association glow**: public/private service circle toggles
    (both off by default), private service filter dropdown (select to
    highlight), legend follows toggles
  - Asset list grouped by node + service exposure table + pod profile dialog
- **AI multi-profile management**:
  - `ai_profiles.yaml` as single config source; `ai_config.yaml` becomes
    activation snapshot (guard hot-reloads, zero code change)
  - **Fetch model list**: base_url + key → `{base_url}/models` → model
    dropdown selection (replaces manual model entry; verified DeepSeek v4)
  - Startup consistency: deleted ai_config auto-rebuilds / manual edits
    overwritten back to active / legacy ai_config migrated to default profile
  - Sidebar bottom-left **AI quick panel**: profile dropdown + threshold
    sliders + confirm switch + link to settings
- **Token authorization constraints**: can only issue to lower-privilege
  roles (frontend filter + backend enforcement), "授权给谁" member dropdown,
  note reserved for purpose
- **Sidebar icons** (expand/collapse), fixed viewport height
- **3-VM multi-node demo guide** (`docs/k8s-multi-node-demo.md`)
- Templates: `ai_profiles.yaml.example`, updated `ai_config.yaml.example`,
  configmap sync

### Fixed
- Sidebar scrolled away on long content (sticky height)
- AI quick dropdown empty after login (load on login)
- Token template compile error (stray template tag)
- Members moved into Settings page (removed internal path from title,
  role tag colors unified)

## [0.5.6] - 2026-08-16

### Added
- **Panel migration: Streamlit → FastAPI + Vue3** (`server/`):
  - REST API backend (FastAPI, 15+ endpoints, RBAC admin/operator/analyst),
    Vue3 + Element Plus CDN zero-build SPA (hash routing, role menus,
    polling refresh) — nginx-ready architecture
  - **Swagger /docs disabled by default** (`ENABLE_DOCS=1` to enable) —
    attack-surface minimization for a security product (ADR-045)
  - In-memory sessions (HttpOnly cookie, 8h, no JWT — immediate logout),
    one-time token gating (add_member/add_rule) reused from auth.py
  - `GUARD_LOGS_DIR` env override → points API at k8s DaemonSet guard's
    log dir (/var/lib/ebpf-guard)
  - `make panel` / `./run.sh --ui` (uvicorn, single worker)
- **Unit tests**: 16 new API auth/RBAC tests (temp users.yaml + log path
  isolation), total 121/121

### Fixed
- **Existing bug: old dashboard read no events** — dashboard/common.py read
  project-root events.log while main.py writes logs/ (since v0.5.2);
  server/common.py unified to logs/ (+ env override for k8s)

### Verified
- Decision linkage: API POST decision → k8s guard DecisionExecutor consumed
  within 2s (`[K8sExecutor] 无法解析 api-link-test-1`, no side effects)
- GUARD_LOGS_DIR= k8s dir → 5473 real alerts readable via API
- Full curl regression incl. 401/403 negatives

### Note
- `dashboard/` deprecated (kept for rollback until v0.6.0)
- Admin password changed during testing: `Guard@2026Admin`

## [0.5.5] - 2026-08-16

### Added
- **k3s E2E fully scripted** (`tests/k8s/scenarios/`): 6 escape scenarios × 4 assertions all green —
  `sudo bash tests/k8s/scenarios/run_all_k8s.sh` (procfs_mount / sensitive_file / reverse_shell /
  privileged_exec / cgroup_write / capset), unit tests 105/105, guard self-noise 0
  - `lib_k8s.sh`: `run_escape_pod` (poll pod Ready — `kubectl run` is async, fixed sleep raced),
    guard readiness wait ("6 probes" banner = bpf actually attached), timeout -k on exec
    (frozen container hangs exec — 124 is the expected freeze evidence)
- **Guard self-exemption** (main.py `_self_container_ids`): K8s mode skips guard's own container
  (ns/pod + container short-id dual match) — os.system iptables was triggering guard's own rules
- **cgroup_id reverse lookup** (identity.py `resolve_by_cgroup`): short-lived processes
  (mount/cat/echo exit before userspace resolves) now resolve via eBPF-captured cgroup inode
  (cgroup v2 kernfs ino == st_ino), no longer mislabeled `host`
- **events.log records actually-executed action**: responder writes `alert['executed_action']`
  (was matrix suggestion — misleading during debugging)
- **TZ fix**: Dockerfile.guard + tzdata, daemonset `TZ=Asia/Shanghai` (was 8h UTC skew)

### Fixed
- **openat kernel filter prefix bugs (root cause of event storm)**: `path[6]=='s'` matched
  `/proc/self/*`+`/proc/stat`, `/proc/self/mem|cmdline` prefix-matched `mountinfo`/`cgroup` —
  high-frequency host paths flooded the 1MB ringbuf → **execve events randomly dropped**.
  Now exact full-path matching (kcore/kallsyms, self/exe|mem|cmdline)
- **`_pids_in_cgroup` cross-contamination**: ignored cgroup_path arg, assigned every /proc pid
  with any cri-containerd scope to each container (252 pids all mixed, exec processes
  mislabeled as other containers) → exact scope-name matching (18-20 pids / 14-16 containers)
- **Hostname trap**: hostNetwork pod HOSTNAME env = node name → self-exemption needs downward
  API `POD_NAME` fieldRef
- **Scenario false-PASS**: kubectl exec failure silently swallowed (2>/dev/null) + fixed sleep 8
  → trigger never fired; now fails loudly
- **set -e kills**: timeout 124 (freeze expected) and empty glob `[ -f ]` exit 1 → `|| true`
- Poll loop sleep 0.1 → 0.02s (smaller burst drop window)

### Known limitation
- `env → /bin/sh` successful execve events dropped by ringbuf (2/2 observed); direct
  `sh → /bin/sh` (comm=sh) reliably delivered — trigger chain uses the latter

### Verified
- 6/6 k8s scenarios pass (procfs freeze + `cannot exec in a paused container` ironclad,
  C2 iptables DROP, privileged_exec freeze); pytest 105/105; guard self events 0

## [0.5.4] - 2026-08-14

### Added
- **Network blocking completed (containerized guard real isolation)**:
  - daemonset `hostNetwork: true` (shared host netns)
  - **nsenter approach**: `nsenter -t 1 -m -n iptables` enters host mount+netns using host iptables (avoids container glibc incompatibility) — isolate and C2 blocking both take real effect
  - k8s_responder + netblocker unified on nsenter (auto-switch in-container via serviceaccount; direct iptables on host)
  - Verified: `ISOLATED (iptables DROP 10.42.x)` rules actually inserted into host FORWARD chain
- **Network-mode adaptive blueprint** (`src/core/netpol_detect.py` design):
  - Detect CNI type (flannel/kube-router/calico) → adapt isolation implementation (flannel→iptables / kube-router→NetworkPolicy)
  - IsolationBackend interface (current NsenterIptablesBackend, future NetworkPolicyBackend)
  - Decision #43: B deferred (k3s CNI swap cost high)

### Fixed
- Mounting host /lib overwrote container libc (python wouldn't start) → nsenter host env instead
- Host iptables binary glibc-incompatible in container → nsenter -m

### Verified
- Containerized guard isolate really drops traffic (host FORWARD rules visible)
- Host regression: Docker mount + pytest 105/105

## [0.5.3] - 2026-08-14

### Added
- **DaemonSet deployment (guard containerized on k3s)**:
  - `deploy/Dockerfile.guard`: python:3.10-slim + host libbpf.so.1/libelf COPY (apt network-restricted) + precompiled .bpf.o + iptables degradation
  - `deploy/k8s/`: daemonset.yaml (hostPID + /sys mount + privileged + /app/logs hostPath persistence) + rbac.yaml (pods + deployments/statefulsets patch + replicasets get) + configmap.yaml (rules/responses/monitor, **no AI key**)
  - **in_cluster kubeconfig**: `src/core/kube_utils.py` — serviceaccount in-container, kubeconfig fallback on host (3 hardcoded sites unified)
  - **iptables degradation**: K8s container has no iptables (netns isolation) → isolate/netblock degrade to annotation-only + no-op
  - main.py logs unified to `logs/` (hostPath persistent, host-visible)
- k3s deploy flow: `docker build --network host` → `docker save | k3s ctr images import` → `kubectl apply -f deploy/k8s/`

### Verified
- DaemonSet pod Running; in_cluster active (K8sBackend k8s_mode=True)
- Containerized E2E: esc-deploy pod mounts procfs → procfs_mount_escape → **FROZEN + `cannot exec in a paused container`** → unfreeze restored
- Degradation: `[NetBlock] (no-op) container has no iptables`
- Logs persistent: /var/lib/ebpf-guard/
- Host regression: Docker mount scenario + pytest 105/105

### Fixed
- Containerized Docker responder init crash (no docker.sock) → responder deferred until runtime detection
- K8s executor missing `import sys`
- Log mount dir conflict (subPath file→dir) → unified /app/logs dir mount
- configmap accidentally contained AI key → removed (Secret or omitted)

## [0.5.2] - 2026-08-14

### Added
- **K8s responder (detection→response loop)**:
  - `src/responder/k8s_responder.py` (K8sResponseEngine, same interface as docker_responder): pause→**cgroup.freeze** (kernel v2 freezer, same mechanism as docker pause) + annotation; isolate→**iptables FORWARD DROP Pod IP** + annotation; kill_process→unchanged (host os.kill); kill_container→**delete pod** (Deployment/RS scale 0 first to prevent controller rebuild); block_image logs + queues only (admission webhook in v0.5.3)
  - `src/core/k8s_decision_executor.py`: confirmed→delete pod; dismissed→restore (unfreeze + iptables -D + clear annotation)
  - **IRREVERSIBLE_ACTIONS kept** (ADR-014 graded automation)
  - **XDP disabled in K8s** (docker0 absent + -s Pod IP semantics mismatch) → force iptables backend
  - Degradation: if kube-router detected (clears our rules) → annotation-only + warning

### Verified
- k3s E2E: esc-test2 pod reads /etc/shadow → sensitive_file_access → isolate_network → **iptables DROP 10.42.0.41 + annotation guard/isolated active**
- K8s identity cold-start fix: new pod short-ID → backend lookup display (`default/esc-test2`)
- cgroup.freeze manual write verified (v2 freezer writable)
- **Docker mount scenario regression passes** (dual-track intact); pytest 105/105

### Fixed
- K8s identity cold-start window: `_short_to_display` adds backend lookup fallback
- freeze when trigger process exited: pod-uid /proc scan fallback
- banner version → v0.5.2

## [0.5.1] - 2026-08-14

### Added
- **K8s adaptation step 1: container discovery + identity** (RuntimeBackend dual-track abstraction):
  - `RuntimeBackend` interface (list_containers/events_loop/cgroup_path/get_meta); DockerBackend moved verbatim (zero logic change) + new K8sBackend (kubernetes client watch pods + cgroup glob scan + cri-containerd parsing)
  - **Docker 6 E2E scenarios unaffected** (dual-track parallel; auto-detect docker.sock → Docker, containerd.sock + kubepods.slice → K8s)
  - `--runtime auto|docker|k8s` (default auto)
  - **Container identity**: K8s eBPF map value = `ns/pod` (e.g. `default/client`, readable); cgroup paths glob all QoS classes under kubepods.slice
- **Response no-op** (v0.5.1 detection-only): K8s mode responder/executor are no-op (Docker actions N/A); responses land in v0.5.2
- requirements +kubernetes (pure Python)

### Verified
- Docker mount scenario regression passes (DockerBackend unchanged)
- K8s mode: 12 containers / 192 processes mapped
- k3s pod reads /etc/shadow → sensitive_file_access hit, container identity `default/client`
- pytest 105/105

### Fixed
- Docker cgroup_path needs full ID (short-ID glob)
- display field >64B (eBPF map limit) → compact `ns/pod` format
- banner version v0.4.3 → v0.5.1

## [0.5.0] - 2026-08-14

### Added
- **Single-instance lock** (v0.5 opener): main.py acquires `fcntl.flock` on `/var/run/ebpf-guard.pid` at startup — unified mutual exclusion across run.sh / systemd / DaemonSet
  - Lock-failure prints "another instance running" and **exits 0** (avoids systemd `Restart=on-failure` loop)
  - Lock auto-releases on process exit (flock semantics), no manual cleanup
  - **Fixes legacy pitfalls**: unreliable run.sh pkill, systemd double-start, cross-mode collisions (foundation for v0.5 K8s deployment-mode mutual exclusion)

### Verified
- First instance holds lock / second instance rejected (exit 0)
- systemd double-start of same service is a no-op; **manual second instance rejected while systemd runs** (cross-mode exclusion)
- Lock released after systemctl stop; restartable

## [0.4.4] - 2026-08-14

### Added
- **BehaviorLogger IO optimization** (decision #37's optional optimization landed):
  - **Buffered writer**: file kept open, flush every 0.5s — eliminates the per-event `open('a')+write+close` 2-syscall overhead
  - **Daily + size rotation** (rename scheme): on date change / >50MB, `behaviors.log` → `behaviors.YYYY-MM-DD.log`; active file is always `behaviors.log` (dashboard/bench zero changes)
  - **Retention**: auto-clean files older than 7 days (prevents disk growth)
  - Guard flushes buffer on shutdown (`_shutdown`, prevents losing final events)
  - **Debug finding**: 2s flush caused large synchronous writes to block ringbuf at 10K+ ev/s (27% loss at 20K) → tuned to 0.5s, 40K now 0 loss — flush-granularity/throughput tradeoff recorded in decision #38
- **Bench tool adaptation** (tools/bench_openat.py): 15s drain matches buffered flush cycles; fixed guard-not-recreating-file-after-rm bug (`_maybe_rotate` checks file existence)

### Verified
- pytest 105/105 (6 new rotation/buffered unit tests)
- Re-benchmarked: **40K ev/s 0 loss, latency p50 52ms** (on par with per-event open('a'), syscall overhead eliminated at normal load)
- Guard live rotation verified (date/size/retention)

## [0.4.3] - 2026-08-14

### Added
- **systemd deployment** (single-host / edge / isolated-network form):
  - `deploy/systemd/ebpf-guard.service` — Type=simple / root / journald / on-failure restart
  - **Clean SIGTERM exit**: `signal.raise_signal(SIGINT)` reuses cleanup path + `_shutdown()` (XDP detach + iptables unblock + bpf.close, idempotent)
  - Key fix: XDP pin does NOT auto-detach on process exit (bpftool prog load + net attach pinned) — systemd stop must clean explicitly; iptables blocks have no self-healing caller (cleanup_expired uncalled) — unblock on shutdown
  - Verified: systemctl start/stop×3 loop, no XDP/iptables residue after stop
- **Performance benchmark tool + baseline report**:
  - `tools/bench_openat.py`: injects openat('/etc/shadow'), measures loss rate / latency percentiles / CPU usage, behavior_log on/off control group
  - `docs/performance-report.md` (**corrected data**): per-event paired latency — **zero loss up to 40K ev/s**, **real loss threshold ≈50K ev/s**, **latency p50 52-58ms** (poll 100ms granularity dominant), CPU delta <1% (within noise). The initial 1.67s latency was a measurement artifact (injection-distribution pollution), fixed via per-event pairing

### Changed
- **Doc consistency sweep**: README ×2 / test-guide ×2 / CONTRIBUTING ×2 / integration banner synced to v0.4.3 (12 rules / 6 probes / 10 vectors × 8 combos / capset probe)

### Verified
- systemctl start/stop×3 loop; journald shows "Deactivated successfully" after stop
- pytest 99/99 + integration suite 15/15
- Benchmark 3 runs consistent (0 loss / CPU delta ≈0)

## [0.4.2] - 2026-08-14

### Added
- **cgroup release_agent write detection** (CVE-2022-0492 escape chain completion):
  - openat probe kernel-side basename suffix match (release_agent / notify_on_release, v2 prefix `cgroup.release_agent` auto-covered) + write-flag check (O_WRONLY/O_RDWR)
  - Rule `cgroup_release_agent_write` (HIGH) — with existing `mount_cgroup` forms the full escape chain (combo confidence 92%)
- **capset capability coverage** (cap_sys_admin):
  - New capset probe (6th tracepoint, EVENT_CAPSET=6), reads data[0] effective/permitted
  - Rule `capset_cap_sys_admin` (MEDIUM)
- **bitand operator** (7th leaf operator): bit-inclusion check (`{bitand: 2097152}` = CAP_SYS_ADMIN), enables bit-level detection in the rule layer
- **E2E +2 scenarios** (8 total): cgroup synthetic write, capset ctypes call (incl. de-escalation negative test)

### Changed
- Event struct extended at tail with cap_effective / cap_permitted / open_flags (ctypes-compatible)
- attack_matrix +2 vectors (cgroup_release_agent 80% / capability_abuse 55%) +2 combos
- Fixed ring_buffer_poll iteration crash (first map access inside callback mutated the dict)

### Verified
- pytest 99/99; integration suite 15/15; all 8 E2E scenarios pass (6 old + 2 new)
- **Real CVE-2022-0492 PoC verification** (PaloAltoNetworks official, cgroup v2 host): release_agent writes ×2 + mount_cgroup all hit — detection is cgroup-version agnostic

## [0.4.1] - 2026-08-14

### Added
- **BCC → libbpf CO-RE migration** (decision record #33):
  - `escape-detect.bpf.c` / `xdp-block.bpf.c` rewritten in CO-RE style (`SEC("tracepoint/...")` + vmlinux.h + ringbuf reserve/submit); clang precompiled `.bpf.o`, zero compile at runtime
  - **Hand-rolled ctypes loader** (`src/core/libbpf.py`): wraps 19 exported libbpf.so.1 APIs (object load / tracepoint attach / map / ringbuf / XDP)
  - **BCC-compatible facade** (`src/core/bpf_runtime.py`): `BpfRuntime` + `MapView` + `RingBufView` — main.py / identity.py migrated with near-zero diff
- **Makefile build chain**: `bpftool btf dump` generates vmlinux.h (not committed; `.build/` gitignored) + both `.bpf.o` + `.BTF` section check
- **XDP migration**: bpftool generic-mode attach (libbpf 1.8's bpf_xdp_attach only supports native XDP; bridge NICs need skb mode); block/unblock/detach verified end-to-end
- **Dual-backend field parity** (`tests/parity/`): BCC and CO-RE loaded simultaneously, same triggers, field-by-field diff (85 events identical) — catches field-level misalignment E2E can't

### Changed
- Ring buffer upgraded from BCC's 4096 bytes (~9 events) to 1MB (`1<<20`), eliminating overflow risk
- BCC dependency removed: requirements.txt / setup.sh / README / test-guide / demo now declare libbpf + clang + bpftool
- Event parsing untouched (`struct event` field order preserved byte-for-byte; handle_event reused)

### Fixed
- BCC-era bounded-loop compile bug inside tracepoints (bpf2c limitation) — gone under CO-RE, unblocking complex probe logic for v0.4.2

### Verified
- Migration success criterion: all 6 E2E escape scenarios pass
- pytest 92/92 + integration suite 15/15
- Parity check: 85 events field-identical across backends
- eBPF smoke (`tools/bpf_smoke.py`): CO-RE load + 5-probe attach + event parsing

## [0.4.0] - 2026-08-13

### Added
- **Rule engine rewrite — Falco-style condition trees** (`src/detector/engine.py`):
  - Nested conditions: `all` (AND) / `any` (OR) / `not` (single node negation) — arbitrary `(A or B) and not C` combinations
  - Leaf operators: `==` (scalar exact / list OR, original semantics preserved), `neq`, `startswith`, `endswith`, `contains`, `glob` (fnmatch with exact-match-first), `exists`
  - `event_type` promoted to rule top-level key (index + implicit AND), banned inside condition
- **Rule schema validation** (`src/detector/rule_schema.py`):
  - Known-field registry (typo guard), single-key node invariant, max depth 5, operator value type checks
  - First load fails fast; hot-reload failure **keeps the existing rule set** (no more silent wipe)
  - `normalize_ai_rule()`: auto-normalizes AI-suggested rules (legacy flat condition → new tree)
- **One-shot migration script** (`scripts/migrate_rules_v04.py`): legacy rules.yaml → v0.4 schema, semantics preserved (multi-field → all, exclude → not/any, wildcards → glob operator)
- **pytest unit-test layer** (`tests/unit/`, 92 cases): operator matrix, combinator evaluation, migration equivalence (10 rules × synthetic event pool vs legacy implementation), schema validation, hot-reload protection, form parsing

### Changed
- `config/rules.yaml`: all 10 rules migrated to the new schema (semantics unchanged)
- Rules management page: multi-row condition form (field + operator + value, comma-separated = OR list); event_type as separate dropdown
- Rule ingestion gate: `append_rule_to_yaml` normalizes + validates before write; invalid rules rejected with a message
- AI suggested-rules page: full-rule YAML display; `ai_analyzer` prompt now includes the v0.4 schema example (controllable LLM output)
- `exclude` field removed (v0.4 breaking change; express via `not` inside condition)

### Verified
- Migration equivalence tests pass (new vs legacy matcher identical across all rules × event pool)
- `runc:[2:INIT]` bracket regression passes (exact-match-first preserved)
- Integration suite 15/15 (hot-reload Test 13 uses new schema)
- All 6 E2E escape scenarios pass
- Dashboard AppTest smoke passes (new rule form renders)

## [0.3.12] - 2026-08-13

### Added
- **run.sh** — one-click launcher (guard background + dashboard foreground); `--guard` / `--ui` / `--stop` subcommands; UI_CMD variable centralizes frontend startup (easy to swap to custom frontend later)
- **setup.sh** — idempotent environment setup: system deps (BCC/clang/docker), pip deps, config init (ai_config.yaml from .example, never overwrites); `--check` mode for inspection

### Changed
- README/CHANGELOG: version badges and roadmap updated to v0.3.12

## [0.3.11] - 2026-08-13

### Added
- **2 new detection rules** (total 10 rules):
  - `execve_network_tools`: detects curl/wget/nc/ncat execution — suspicious payload download or reverse connect (MITRE T1105)
  - `mount_cgroup`: detects cgroup filesystem mount — CVE-2022-0492 (cgroup release_agent escape) precursor
- **Rule expansion**:
  - `privileged_exec`: added `/bin/busybox` target path
  - `sensitive_file_access`: added `/proc/self/exe`, `/proc/self/mem`, `/proc/self/cmdline`, `/run/docker.sock` paths; added `runc:[2:INIT]` exclude to reduce false positives
- **eBPF kernel probe expansion** (`escape-detect.bpf.c`): opened `/proc/self/exe`, `/proc/self/mem`, `/proc/self/cmdline`, `/run/docker.sock` in the kernel-space path filter

### Fixed
- **comm field null bytes**: `event.comm` now stripped of trailing `\x00` bytes — fixes exclude matching for `runc:[2:INIT]` and other kernel comm values
- **_is_excluded fnmatch charset collision**: `fnmatch("runc:[2:INIT]", "runc:[2:INIT]")` returns False because `[2:INIT]` is parsed as a character set. Added exact match before fnmatch fallback.

### Verified
- All Python modules compile clean
- 10 rules loaded correctly (8 original + 2 new)
- Exclude `runc:[2:INIT]` now correctly matches (both null-strip and fnmatch fix)
- CVE-2019-5736 PoC testing: `privileged_exec` and `sensitive_file_access` rules trigger correctly

## [Unreleased]

### Planned
- Kubernetes native support (v0.4, DaemonSet + NetworkPolicy)
- New probes/rules (cgroup file-write for CVE-2022-0492, cap_sys_admin coverage)
- Custom frontend dashboard (CSAI-style, decision record #17)
- Performance benchmarking & systemd deployment

## [0.3.10] - 2026-08-11

### Added
- **BehaviorLogger** (`src/core/behavior_logger.py`): records ALL syscall events (mount, ptrace, execve, connect, openat) to `behaviors.log` as JSONL — configurable toggle `behavior_log: true|false` in `monitor.yaml`
- **Behavior Log Dashboard Page** (`dashboard/pages/behavior_log.py`): read-only analyzer with filtering by event_type, container ID, process name, time range (1min/5min/30min/custom), and host/container scope — paginated table, 5s auto-refresh
- **Forced password change on first login** (v0.3.10 RBAC enhancement): users with `initial` password flag are redirected to a mandatory change-password form before accessing the dashboard — password sidebar entry removed
- **Rule expansion**:
  - `nsenter_escape`: added `target_path: [/usr/bin/nsenter]` — nsenter may not always appear with `comm=nsenter`
  - `host_directory_access`: added `/host_sys/block` (host block devices)

### Changed
- `dashboard/common.py`: added `BEHAVIORS_LOG` constant and `load_behavior_log()` function
- `dashboard/app.py`: navigation includes behavior_log page; sidebar password change removed; forced password change interceptor on initial login
- `dashboard/auth.py`: `create_user` stores `initial: true` flag; `change_password` clears it; `is_initial_password()` / `clear_initial_flag()` methods added

### Verified
- BehaviorLogger: guard starts with `[Behavior] enabled: true`; mount attack → events.log has 1 alert, behaviors.log has 22+ mount records among 1200+ total records (includes normal dockerd/runc events)
- Behavior log page renders with 5s fragment refresh, all filters work
- Forced password change: initial user redirected to change-password form, re-login required after change
- Existing `users.yaml` users auto-backfilled with `initial: true` on next load

## [0.3.9] - 2026-08-11

### Added
- **XDP network blocking** (`src/ebpf/xdp-block.bpf.c` + `src/core/netblock_xdp.py`):
  - eBPF XDP program drops blocked packets at NIC ingress (microsecond, kernel-level)
  - Two block maps: whole-IP and IP:port (TCP/UDP)
- **Mixed backend** (`CompositeNetBlocker`): XDP for inbound + iptables FORWARD
  for outbound (C2 / reverse shell) — `netblock_backend: mixed` (default)
- **Scenario-based test suite** (`tests/integration/scenarios/`): 6 escape scenarios
  with pre-built Docker images, automated assertions (v0.3.9)
- **Test guide** (`tests/test-guide.md` / `tests/test-guide_CN.md`): bilingual
  documentation with test methods, expected results, and verified results

### Fixed
- **build_image.sh**: path resolution refactored to auto-derive Dockerfile from
  image tag; added `--network host` for container DNS during build
- **test_mount_escape.sh**: unified build via `build_image.sh` instead of inline
  `docker build`
- **docker_socket_mount rule**: kernel resolves `/var/run/docker.sock` to
  `/run/docker.sock` (symlink) — added `/run/docker.sock` to rule targets

### Design note
- XDP is ingress-only (packets entering an interface). Outbound container
  traffic (reverse shell / C2) does not pass XDP on docker0 — iptables FORWARD
  covers outbound, XDP covers inbound attack traffic. This split is documented
  in decision record.

### Verified
- XDP program loads, attaches to docker0, map block/unblock works
- Mixed E2E: baseline CONNECTED → blocked FAILED → unblocked CONNECTED
- Smoke test suite: 15/15 PASS
- Scenario tests (2026-08-11): **6/6 ALL PASS** — all escape scenarios verified
  end-to-end (procfs mount, socket mount, ptrace, sensitive file, reverse shell,
  nsenter) with correct Tier 1/2/3 detection, response actions, and iptables
  network blocking

## [0.3.8] - 2026-08-09


### Added
- **RBAC login** (CSAI-style): username/password required to enter dashboard
  - Roles: admin > operator > analyst
  - Initial admin auto-created on first session; password printed to terminal
  - Password hashing: pbkdf2_hmac(sha256, 100k); users.yaml gitignored
  - Change own password (all roles)
- **Role-filtered navigation**: pages shown per role
  - All: overview / review queue / AI rules / rule view / alerts
  - admin+operator: settings (AI config)
  - admin: member management
- **Member management**: admin adds members (password required, one role each);
  operator views list; admin+operator see all members
- **Temporary token authorization** (delegated access):
  - admin grants add_member / add_rule; operator grants add_rule
  - TTL 1-5 min, single-use, purpose-locked
  - Analyst can add rules via operator/admin token (needs to see rules for
    better analysis — rule VIEW is open to all)
  - Full audit trail: auth_audit.log records who granted what to whom, when used

### Verified
- Auth unit: hash/verify/create/change/initial admin (11 tests)
- Login: admin/operator/analyst sessions, wrong password rejected
- Token loop: operator grants add_rule → analyst verifies → adds rule →
  token single-use → audit shows grantor op1 / used_by sec1
- Operator cannot grant add_member; admin can
- Test suite: 15/15 PASS

## [0.3.7] - 2026-08-09


### Changed
- **Dashboard refactored to multi-page** (`st.navigation`):
  - 📊 Overview (metrics + container filter)
  - ⏳ Review Queue (container-level verdicts + evidence)
  - 🧠 AI Suggested Rules (unknown attack discovery review)
  - 📜 Rule Management (view/add/audit)
  - 📡 Live Alert Stream (+ netblock records)
  - ⚙️ Settings (AI config, hot-reload)
- `dashboard/common.py` — shared data loading/actions for all pages
- Each page has its own URL (shareable); single `streamlit run`

### Purpose
- Browser-style navigation (sidebar) — first step toward CSAI-style
  frontend architecture (decision record #17)
- Page structure maps directly to future frontend routes; data model
  (events/decisions/rules logs) is framework-agnostic and reusable

### Verified
- All 6 pages HTTP 200 at their URLs
- No import/error issues; guard unchanged

## [0.3.6] - 2026-08-09


### Added
- **Settings panel** (dashboard): AI configuration form
  - base_url / model / api_key / thresholds — no manual yaml editing
  - API key shown masked (sk-...last4); empty input keeps existing key
  - Save → ai_config.yaml → guard hot-reloads within 3s (no restart)
- **AI config hot-reload**: `AsyncAIAnalyzer.reload()` + mtime watcher
  (v0.3.3 pattern) — enabling AI / switching model takes effect live

### Verified
- Unit: reload() flips disabled→enabled, model updates
- E2E: started with empty key (AI disabled) → saved real key → guard
  reloaded ("config reloaded: enabled") → attack produced 5 AI verdicts
- Test suite: 15/15 PASS

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