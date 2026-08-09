#!/bin/bash
# Integration Test Suite for eBPF Container Guard (v0.3.3)
# Tests: static checks + module imports + core unit behaviors

PASS=0
FAIL=0
TOTAL=0

print_header() {
    echo ""
    echo "=========================================="
    echo "  eBPF Container Guard Test Suite"
    echo "  Version: v0.3.3 (5 probes | 8 rules | 3-tier + dashboard)"
    echo "=========================================="
    echo ""
}

print_test() {
    TOTAL=$((TOTAL + 1))
    echo "[TEST $TOTAL] $1..."
}

print_pass() {
    PASS=$((PASS + 1))
    echo "✅ PASS"
}

print_fail() {
    FAIL=$((FAIL + 1))
    echo "❌ FAIL: $1"
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "  Test Summary"
    echo "=========================================="
    echo "Total:  $TOTAL"
    echo "Passed: $PASS"
    echo "Failed: $FAIL"
    echo ""

    if [ $FAIL -eq 0 ]; then
        echo "🎉 All tests passed!"
        exit 0
    else
        echo "⚠️  Some tests failed"
        exit 1
    fi
}

# ============================================================
# Static checks
# ============================================================
print_header

# Test 1: Main entry point exists
print_test "Main entry point exists"
if [ -f "main.py" ]; then print_pass; else print_fail "main.py not found"; fi

# Test 2: Config files exist
print_test "Configuration files exist"
if [ -f "config/rules.yaml" ] && [ -f "config/responses.yaml" ] \
   && [ -f "config/monitor.yaml" ]; then
    print_pass
else
    print_fail "Config files missing (rules/responses/monitor)"
fi

# Test 3: eBPF program exists
print_test "eBPF probe program exists"
if [ -f "src/ebpf/escape-detect.bpf.c" ]; then
    print_pass
else
    print_fail "eBPF program not found"
fi

# Test 4: Python dependencies importable
print_test "Python dependencies importable"
if python3 -c "import bcc, yaml, docker, streamlit" 2>/dev/null; then
    print_pass
else
    print_fail "Missing dependencies (bcc, pyyaml, docker, streamlit)"
fi

# Test 5: YAML syntax valid
print_test "YAML configuration syntax valid"
if python3 -c "
import yaml
for f in ['config/rules.yaml', 'config/responses.yaml', 'config/monitor.yaml']:
    yaml.safe_load(open(f))
" 2>/dev/null; then
    print_pass
else
    print_fail "Invalid YAML syntax"
fi

# ============================================================
# Module existence checks (v0.2/v0.3 modules)
# ============================================================

# Test 6: Detection pipeline modules
print_test "Detection pipeline modules (3-tier)"
if [ -f "src/detector/engine.py" ] \
   && [ -f "src/detector/attack_matrix.py" ] \
   && [ -f "src/detector/ai_analyzer.py" ]; then
    print_pass
else
    print_fail "detector modules missing"
fi

# Test 7: Core infrastructure modules
print_test "Core infrastructure modules"
if [ -f "src/core/identity.py" ] \
   && [ -f "src/core/event_log.py" ] \
   && [ -f "src/core/scope.py" ] \
   && [ -f "src/core/escalation.py" ] \
   && [ -f "src/core/netblock.py" ] \
   && [ -f "src/core/decision_executor.py" ]; then
    print_pass
else
    print_fail "core modules missing"
fi

# Test 8: Responder + dashboard
print_test "Responder + dashboard exist"
if [ -f "src/responder/docker_responder.py" ] \
   && [ -f "dashboard/app.py" ]; then
    print_pass
else
    print_fail "responder/dashboard missing"
fi

# ============================================================
# Unit behaviors (no root needed)
# ============================================================

# Test 9: Rule engine loads 8 rules and matches
print_test "Rule engine loads rules and matches"
if python3 -c "
import sys; sys.path.insert(0, 'src')
from detector.engine import EscapeDetector
d = EscapeDetector('config/rules.yaml')
assert len(d.rules) >= 8, f'expected >=8 rules, got {len(d.rules)}'
# procfs mount escape should match
m = d.check_event({'event_type': 'mount', 'fstype': 'proc',
                   'target_path': '/tmp/host_proc', 'comm': 'mount'})
assert len(m) >= 1, 'procfs mount not matched'
# normal ext4 mount should NOT match
m2 = d.check_event({'event_type': 'mount', 'fstype': 'ext4',
                    'target_path': '/mnt/data', 'comm': 'mount'})
assert len(m2) == 0, 'normal mount wrongly matched'
print('rules_ok')
" 2>/dev/null; then
    print_pass
else
    print_fail "rule engine behavior"
fi

# Test 10: Attack matrix combination boost
print_test "Attack matrix combination boost"
if python3 -c "
import sys; sys.path.insert(0, 'src')
from detector.attack_matrix import AttackMatrix
m = AttackMatrix()
r1 = m.analyze('procfs_mount', 'test_c')
r2 = m.analyze('nsenter_escape', 'test_c')
assert r2.boosted, 'combination not boosted'
assert r2.final_confidence >= r2.base_confidence, 'confidence not raised'
print(f'combo_ok ({r2.base_confidence}→{r2.final_confidence})')
" 2>/dev/null; then
    print_pass
else
    print_fail "attack matrix combo"
fi

# Test 11: Escalation progression
print_test "Escalation pause→kill→block"
if python3 -c "
import sys; sys.path.insert(0, 'src')
from core.escalation import EscalationManager
import tempfile
with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as f:
    f.write('blocked_images: []\n'); p = f.name
e = EscalationManager(p)
assert e.decide('img:1') == 'pause_container'
assert e.decide('img:1') == 'kill_container'
assert e.decide('img:1') == 'block_image'
assert e.is_image_blocked('img:1')
print('escalation_ok')
" 2>/dev/null; then
    print_pass
else
    print_fail "escalation progression"
fi

# Test 12: Monitoring scope include/exclude
print_test "Monitoring scope filters"
if python3 -c "
import sys; sys.path.insert(0, 'src')
from core.scope import ContainerScope
import tempfile, yaml, os
with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as f:
    yaml.dump({'include': ['app-*'], 'exclude': ['app-test'],
               'match_by': 'name'}, f)
    p = f.name
s = ContainerScope(p)
assert s.should_monitor('id1', 'app-prod') == True
assert s.should_monitor('id2', 'app-test') == False  # exclude priority
assert s.should_monitor('id3', 'db-1') == False      # not in include
os.unlink(p)
print('scope_ok')
" 2>/dev/null; then
    print_pass
else
    print_fail "scope filtering"
fi

# Test 13: Rules hot-reload (v0.3.3)
print_test "Rules hot-reload"
if python3 -c "
import sys; sys.path.insert(0, 'src')
from detector.engine import EscapeDetector
import shutil
shutil.copy('config/rules.yaml', '/tmp/rb.yaml')
d = EscapeDetector('config/rules.yaml')
n1 = len(d.rules)
with open('config/rules.yaml', 'a') as f:
    f.write('''
  - name: \"test_hotload\"
    description: \"hotload test\"
    severity: \"LOW\"
    condition:
      event_type: \"execve\"
      comm: \"hotload_test\"
    action: \"alert_and_log\"
''')
d.reload()
assert len(d.rules) == n1 + 1, 'reload failed'
assert len(d.check_event({'event_type': 'execve', 'comm': 'hotload_test', 'pid': 1})) == 1
shutil.copy('/tmp/rb.yaml', 'config/rules.yaml')
d.reload()
print('hotreload_ok')
" 2>/dev/null; then
    print_pass
else
    print_fail "rules hot-reload"
fi

# Test 14: Netblocker ip conversion
print_test "Netblocker IP conversion"
if python3 -c "
import sys; sys.path.insert(0, 'src')
from core.netblock import ip_int_to_str
assert ip_int_to_str(1920103026) == '114.114.114.114'
print('ip_ok')
" 2>/dev/null; then
    print_pass
else
    print_fail "ip conversion"
fi

# Test 15: Async AI analyzer imports + queue
print_test "Async AI analyzer structure"
if python3 -c "
import sys; sys.path.insert(0, 'src')
from detector.ai_analyzer import AsyncAIAnalyzer
a = AsyncAIAnalyzer('/nonexistent/ai_config.yaml')
a.submit({}, [], 70, '2026-08-09T00:00:00.000')
print('async_ai_ok')
" 2>/dev/null; then
    print_pass
else
    print_fail "async AI analyzer"
fi

# ============================================================
# Summary
# ============================================================
print_summary
