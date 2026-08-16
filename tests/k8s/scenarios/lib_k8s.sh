#!/bin/bash
# lib_k8s.sh — k3s 场景化测试公共函数 (v0.5.5)
#
# 用法: source lib_k8s.sh; import_image; start_guard; trigger; assert; cleanup
#
# 容器化 guard (DaemonSet) 的验证:
#   - guard 日志: 宿主 /var/lib/ebpf-guard/events.log (JSONL 含 action/action_status)
#   - 宿主 iptables: nsenter -t 1 -n iptables (guard 写 FORWARD 链)
#   - freeze 铁证: kubectl exec 报 "cannot exec in a paused container"
#   - 冷却规避: 每场景用唯一 pod 名 (cooldown 按 "ns/pod" 键控)
#
# 用法: sudo bash test_k8s_xxx.sh

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
K8S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVENTS_LOG="/var/lib/ebpf-guard/events.log"
GUARD_NS="kube-system"

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
# 镜像导入 (docker → k3s ctr)
# -----------------------------------------------------------

import_image() {
    local img="$1"
    if sudo k3s ctr images list | grep -q "$img"; then
        echo "  镜像 $img 已存在，跳过导入"
        return 0
    fi
    echo "--- 导入镜像 $img 到 k3s ---"
    docker save "$img" -o /tmp/k8s_import.tar
    sudo k3s ctr images import /tmp/k8s_import.tar
    rm -f /tmp/k8s_import.tar
}

# -----------------------------------------------------------
# guard 生命周期
# -----------------------------------------------------------

reset_environment() {
    # 清逃逸 pod + 宿主 FORWARD DROP 规则 + events.log
    for pod in $(kubectl get pods -n default -o name 2>/dev/null | grep -E "esc|test" | cut -d/ -f2); do
        kubectl delete pod "$pod" -n default --force --grace-period=0 2>/dev/null
    done
    # 清 guard 可能留下的 FORWARD DROP (按 10.42 网段)
    sudo nsenter -t 1 -n iptables -L FORWARD -n 2>/dev/null | \
        grep -E "10\.42\." | grep DROP | \
        awk '{print $4}' | while read -r ip; do
            sudo nsenter -t 1 -n iptables -D FORWARD -s "$ip" -j DROP 2>/dev/null
        done
    sudo rm -f "$EVENTS_LOG"
    # 重启 guard daemonset 清内存冷却 (escalation/cooldown 按镜像累计)
    kubectl rollout restart ds/ebpf-guard -n "$GUARD_NS" > /dev/null 2>&1
    sleep 10
}

start_guard() {
    echo "--- 启动 guard (DaemonSet) ---"
    kubectl apply -f "$PROJECT_ROOT/deploy/k8s/" 2>/dev/null
    kubectl rollout status ds/ebpf-guard -n "$GUARD_NS" --timeout=60s > /dev/null 2>&1
    # v0.5.5: 等 guard 真正就绪 (bpf attach 完成) — 固定 sleep 会竞态, 触发早于 attach 则全量丢事件
    # 注意: 不能 --tail 限量 — 告警噪声会把启动横幅挤出窗口
    for i in $(seq 1 30); do
        if kubectl logs ds/ebpf-guard -n "$GUARD_NS" 2>/dev/null | \
                grep -q "6 probes"; then
            sleep 2
            echo "✅ guard 就绪 (bpf 已 attach)"
            return 0
        fi
        sleep 1
    done
    echo "❌ guard 启动超时 (bpf 未就绪)"
    return 1
}

# -----------------------------------------------------------
# 逃逸 pod 创建 (v0.5.5: run + 轮询 Ready — 固定 sleep 会竞态,
# pod 未 Ready 时 kubectl exec 失败被吞 → 触发从未发生 → 假 PASS)
# -----------------------------------------------------------

run_escape_pod() {
    local pod="$1" image="$2"
    kubectl run "$pod" --image="$image" --privileged --restart=Never \
        --command -- sleep 300 2>/dev/null
    local i phase=""
    for i in $(seq 1 30); do
        phase=$(kubectl get pod "$pod" -n default \
                    -o jsonpath='{.status.phase}' 2>/dev/null)
        [ "$phase" = "Running" ] && return 0
        sleep 1
    done
    echo "  ❌ pod $pod 未就绪 (phase=$phase)"
    return 1
}

# -----------------------------------------------------------
# 断言
# -----------------------------------------------------------

wait_for_rule() {
    local rule="$1"
    local wait_sec="${2:-15}"
    for i in $(seq 1 $wait_sec); do
        if sudo grep -q "\"rule\": \"$rule\"" "$EVENTS_LOG" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

get_pod_ip() {
    local pod="$1"
    kubectl get pod "$pod" -n default -o jsonpath='{.status.pod_ip}' 2>/dev/null
}

assert_frozen() {
    local pod="$1"
    # freeze 铁证: kubectl exec 报 paused container
    local out
    out=$(timeout 5 kubectl exec -n default "$pod" -- /bin/sh -c "echo alive" 2>&1)
    if echo "$out" | grep -q "paused container"; then
        return 0
    fi
    return 1
}

assert_isolated() {
    local pod="$1"
    # 双重断言: iptables DROP 规则 或 annotation guard/isolated
    local ip
    ip=$(get_pod_ip "$pod")
    if [ -n "$ip" ]; then
        sleep 2
        sudo nsenter -t 1 -n iptables -L FORWARD -n 2>/dev/null | \
            grep -q "DROP.*$ip" && return 0
    fi
    # 兜底: annotation 记录 (隔离意图已打标)
    kubectl get pod "$pod" -n default -o jsonpath='{.metadata.annotations.guard/isolated}' 2>/dev/null | grep -q "2026" && return 0
    return 1
}

print_guard_log() {
    echo "--- guard 最近响应 ---"
    sudo grep -E "FROZEN|ISOLATED" /var/lib/ebpf-guard/response_audit.log 2>/dev/null | tail -3 || true
}

# -----------------------------------------------------------
# 清理
# -----------------------------------------------------------

cleanup() {
    local pod="${1:-}"
    if [ -n "$pod" ]; then
        kubectl delete pod "$pod" -n default --force --grace-period=0 2>/dev/null
    fi
    # 清 FORWARD DROP
    sudo nsenter -t 1 -n iptables -L FORWARD -n 2>/dev/null | \
        grep -E "10\.42\." | grep DROP | \
        awk '{print $4}' | while read -r ip; do
            sudo nsenter -t 1 -n iptables -D FORWARD -s "$ip" -j DROP 2>/dev/null
        done
    # 解冻残留 (|| true: glob 无匹配时 [ -f ] 返回 1, set -e 会退出)
    for f in /sys/fs/cgroup/kubepods.slice/*/*/kubepods-*/cri-containerd-*.scope/cgroup.freeze; do
        [ -f "$f" ] && echo 0 | sudo tee "$f" > /dev/null 2>&1 || true
    done
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "  场景测试汇总"
    echo "=========================================="
    echo "Total:  $TOTAL"
    echo "Passed: $PASS"
    echo "Failed: $FAIL"
    echo ""
    [ $FAIL -eq 0 ] && echo "🎉 全部通过" || echo "⚠️ 有场景失败"
    exit $FAIL
}
