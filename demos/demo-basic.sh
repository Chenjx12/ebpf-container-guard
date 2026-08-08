#!/bin/bash
# Demo: Basic eBPF Container Guard Monitoring
# This script demonstrates the basic monitoring capabilities

set -e

echo "=========================================="
echo "  eBPF Container Guard - Basic Demo"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (sudo)"
    exit 1
fi

# Check dependencies
echo "🔍 Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found"
    exit 1
fi

if ! python3 -c "import bcc" &> /dev/null; then
    echo "❌ BCC framework not installed"
    echo "   Install with: sudo apt install bpfcc-tools python3-bcc"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found"
    exit 1
fi

echo "✅ All dependencies satisfied"
echo ""

# Start monitoring in background
echo "🛡️  Starting eBPF Container Guard..."
python3 main.py --rules config/rules.yaml --responses config/responses.yaml &
GUARD_PID=$!

sleep 2

echo "✅ Monitor started (PID: $GUARD_PID)"
echo ""
echo "📊 Now try these commands in another terminal:"
echo ""
echo "  # Test 1: Normal operation (should NOT trigger alert)"
echo "  docker exec -it nginx ls /tmp"
echo ""
echo "  # Test 2: Procfs mount escape (SHOULD trigger CRITICAL alert)"
echo "  docker exec malicious-container mount -t proc proc /tmp/host_proc"
echo ""
echo "  # Test 3: Ptrace injection (SHOULD trigger HIGH alert)"
echo "  docker exec malicious-container strace -p 1"
echo ""
echo "⚠️  Press Ctrl+C to stop monitoring"
echo ""

# Wait for user interrupt
trap "kill $GUARD_PID 2>/dev/null; echo ''; echo '👋 Monitor stopped.'; exit 0" INT TERM

wait $GUARD_PID
