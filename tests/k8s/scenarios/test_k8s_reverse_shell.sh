#!/bin/bash
# test_k8s_reverse_shell.sh — k3s 场景 (v0.5.5)
# 触发: echo CONNECT
# 断言: reverse_shell
set -e
cd "$(dirname "$0")"
source lib_k8s.sh

POD="esc-rsh"
IMAGE="ebpf-test:net"

print_result "k3s 反弹 shell / C2 出站 (reverse_shell)"

print_test "导入镜像 $IMAGE"
import_image "$IMAGE"
print_pass

reset_environment
start_guard || exit 1

print_test "创建逃逸 pod + 触发"
kubectl run "$POD" --image="$IMAGE" --privileged --restart=Never --command -- sleep 300 2>/dev/null
sleep 8
kubectl exec -n default "$POD" -- /bin/sh -c "echo CONNECT" 2>/dev/null
print_pass

print_test "检测到 reverse_shell"
if wait_for_rule "reverse_shell"; then
    print_pass
else
    print_fail "events.log 无 reverse_shell"
fi

print_test "C2 流量被阻断 (FORWARD DROP)"
if assert_isolated "$POD"; then
    print_pass
else
    print_fail "C2 流量被阻断 (FORWARD DROP)失败"
fi

print_guard_log
cleanup "$POD"
print_summary
