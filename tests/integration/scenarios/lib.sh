#!/bin/bash
# lib.sh — 场景化测试公共函数 (v0.3.9)
#
# 用法: source lib.sh; start_guard; trigger_attack; wait_and_assert; cleanup
#
# 预期日志输出说明:
#   终端（guard stdout）: 彩色告警（🚨 安全告警 - <SEVERITY> + 规则/容器/矩阵置信度）
#   events.log: JSONL 每行一个事件，含 rule/severity/state/tier2_confidence/
#               action/action_status 等字段

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GUARD_LOG="/tmp/guard_test.log"

PASS=0
FAIL=0
TOTAL=0

print_result() {
    echo ""
    echo "=========================================="
    echo "  场景测试: $1"
    echo "=========================================="
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

# -----------------------------------------------------------
# guard 生命周期
# -----------------------------------------------------------

reset_environment() {
    # 清 blocklist（guard root 写的，需 sudo）+ 日志 + 规则
    sudo tee "$PROJECT_ROOT/config/blocklist.yaml" > /dev/null << 'EOF'
blocked_images: []
EOF
    sudo pkill -f "python3 -u main.py" 2>/dev/null
    sleep 2
    sudo iptables -F FORWARD 2>/dev/null
    sudo ip link set docker0 xdp off 2>/dev/null
    rm -f "$PROJECT_ROOT"/events.log "$PROJECT_ROOT"/decisions.log \
       "$PROJECT_ROOT"/ai_results.log
}

start_guard() {
    echo "--- 启动 guard ---"
    cd "$PROJECT_ROOT"
    sudo python3 -u main.py > "$GUARD_LOG" 2>&1 &
    GUARD_PID=$!
    sleep 8
    if ! kill -0 $GUARD_PID 2>/dev/null; then
        echo "❌ guard 启动失败"
        tail -5 "$GUARD_LOG"
        return 1
    fi
    echo "✅ guard 运行中 (PID $GUARD_PID)"
    return 0
}

stop_guard() {
    sudo kill $GUARD_PID 2>/dev/null
    sleep 1
}

# -----------------------------------------------------------
# 断言
# -----------------------------------------------------------

# wait_for_rule <规则名> <等待秒数>
wait_for_rule() {
    local rule="$1"
    local wait_sec="${2:-8}"
    local found=0
    for i in $(seq 1 $wait_sec); do
        if grep -q "\"rule\": \"$rule\"" "$PROJECT_ROOT/events.log" 2>/dev/null; then
            found=1
            break
        fi
        sleep 1
    done
    return $((1 - found))
}

# print_event_log <规则名> — 打印该规则在 events.log 的 JSON 记录
print_event_log() {
    local rule="$1"
    echo "--- events.log 中 $rule 的记录 ---"
    grep "\"rule\": \"$rule\"" "$PROJECT_ROOT/events.log" 2>/dev/null \
        | head -1 | python3 -m json.tool 2>/dev/null || echo "  （无记录）"
}

# print_guard_alerts — 打印 guard 终端的告警摘要
print_guard_alerts() {
    echo "--- guard 终端告警 ---"
    grep -E "🚨|规则:|攻击向量:|容器:|置信度:|RESPONSE|NETBLOCK" \
        "$GUARD_LOG" | head -12 || echo "  （无告警输出）"
}

# -----------------------------------------------------------
# 清理
# -----------------------------------------------------------

cleanup() {
    stop_guard 2>/dev/null
    sudo pkill -f "python3 -u main.py" 2>/dev/null
    sleep 1
    # 删除本场景创建的容器（调用方通过 $TEST_CONTAINERS 指定）
    if [ -n "${TEST_CONTAINERS:-}" ]; then
        docker rm -f $TEST_CONTAINERS 2>/dev/null
    fi
    sudo iptables -F FORWARD 2>/dev/null
    sudo ip link set docker0 xdp off 2>/dev/null
    echo ""
    echo "=== 场景测试汇总 ==="
    echo "Total: $TOTAL  Passed: $PASS  Failed: $FAIL"
    [ $FAIL -eq 0 ] && echo "🎉 全部通过" || echo "⚠️ 存在失败"
}
