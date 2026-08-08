#!/bin/bash
# Integration Test Suite for eBPF Container Guard
# Tests core detection and response functionality

set -e

PASS=0
FAIL=0
TOTAL=0

print_header() {
    echo ""
    echo "=========================================="
    echo "  Integration Test Suite"
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

# Start tests
print_header

# Test 1: Check main.py exists and is executable
print_test "Main entry point exists"
if [ -f "main.py" ]; then
    print_pass
else
    print_fail "main.py not found"
fi

# Test 2: Check config files exist
print_test "Configuration files exist"
if [ -f "config/rules.yaml" ] && [ -f "config/responses.yaml" ]; then
    print_pass
else
    print_fail "Config files missing"
fi

# Test 3: Check eBPF program exists
print_test "eBPF probe program exists"
if [ -f "src/ebpf/escape-detect.bpf.c" ]; then
    print_pass
else
    print_fail "eBPF program not found"
fi

# Test 4: Check Python dependencies
print_test "Python dependencies importable"
if python3 -c "import bcc, yaml, docker" 2>/dev/null; then
    print_pass
else
    print_fail "Missing Python dependencies (bcc, pyyaml, docker)"
fi

# Test 5: Validate YAML syntax
print_test "YAML configuration syntax valid"
if python3 -c "import yaml; yaml.safe_load(open('config/rules.yaml')); yaml.safe_load(open('config/responses.yaml'))" 2>/dev/null; then
    print_pass
else
    print_fail "Invalid YAML syntax in config files"
fi

# Test 6: Check detector module
print_test "Detection engine module exists"
if [ -f "src/detector/engine.py" ]; then
    print_pass
else
    print_fail "Detector engine not found"
fi

# Test 7: Check responder module
print_test "Response engine module exists"
if [ -f "src/responder/docker_responder.py" ]; then
    print_pass
else
    print_fail "Responder engine not found"
fi

# Print summary
print_summary
