# eBPF Container Guard — Verification Report v0.4.1 (2026-08-14)

> Historical verification: see [MVP-verification-report.md](MVP-verification-report.md)
> (v0.1.0 → v0.3.3, kept as an early-milestone snapshot).
> This report covers the current release (v0.4.1, after the BCC → libbpf CO-RE migration).

## Environment

| Item | Value |
|------|-------|
| OS | Ubuntu 22.04 LTS |
| Kernel | 6.8.0-136-generic (CONFIG_DEBUG_INFO_BTF=y) |
| eBPF framework | libbpf 1.8.0 (hand-rolled ctypes loader, zero BCC dependency) |
| Compiler | clang 14 (`-target bpf` precompiled CO-RE objects) |
| Container runtime | Docker (containerd) |
| Hardware | VMware VM, 2 vCPU / 8GB |

## Verification Matrix

| Check | Command | Result |
|-------|---------|--------|
| CO-RE build chain | `make build` | ✅ vmlinux.h + 2 `.bpf.o` + `.BTF` section check |
| eBPF load smoke | `sudo python3 tools/bpf_smoke.py` | ✅ 5 probes attached + event parsing |
| Unit tests | `python3 -m pytest tests/unit/` | ✅ 92/92 (incl. migration equivalence, runc:[2:INIT] regression) |
| Integration suite | `bash tests/integration/test_escape_scenarios.sh` | ✅ 15/15 |
| E2E escape scenarios | `sudo bash run_all_scenarios.sh` | ✅ 6/6 (mount / socket / ptrace / sensitive / reverse_shell / nsenter) |
| Dual-backend parity | `sudo bash tests/parity/parity_check.sh` | ✅ BCC vs CO-RE: 85 events field-identical |
| XDP block chain | XDPNetBlocker block/unblock | ✅ block → unblock full cycle |

## CO-RE Startup (v0.4.1+)

```bash
make build                # generate vmlinux.h + .bpf.o (first use)
./run.sh --guard          # detection engine (background)
./run.sh --ui             # dashboard (foreground)
```

Zero compile at runtime — `.bpf.o` precompiled + kernel BTF relocation,
compile once, run everywhere.

## Key Scenario Outputs

### Scenario 1: procfs mount escape (CRITICAL)

```
🚨 ALERT - CRITICAL
Rule: procfs_mount_escape
Container: 2287bfc722b9  Process: 27874 (mount)
Filesystem: proc -> target: /tmp/host_proc
🛡️  [RESPONSE] CRITICAL → pause_container
✅ Container 2287bfc722b9 PAUSED
```

### Scenario 2: reverse shell (HIGH, XDP/iptables block)

```
🚨 ALERT - HIGH
Rule: reverse_shell
🛡️  [RESPONSE] Netblock: 114.47.114.97:12150 DROP
Baseline CONNECTED → blocked FAILED → unblocked CONNECTED
```

### Scenario 3: dual-backend parity (migration correctness)

Same triggers fed to BCC and CO-RE probes simultaneously; 85 events
field-identical (event_type/pid/uid/comm/container_id/target_path/fstype/
target_pid/request_raw/daddr/dport) — catches field-level misalignment
(e.g. dport byte order) that E2E cannot.

## Migration Highlights (v0.4.1)

- **Success criterion**: all 6 E2E scenarios pass under CO-RE loading
- **Ring buffer**: 4096B → 1MB (`1<<20`), overflow risk eliminated (old capacity ≈ 9 events)
- **Event parsing**: `struct event` field order preserved byte-for-byte; handle_event reused unchanged
- **XDP**: bpftool generic-mode attach (libbpf 1.8's bpf_xdp_attach only supports native; bridge NICs need skb mode)
