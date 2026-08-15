#!/bin/bash
# test_k8s_privileged_exec.sh — k3s 场景 (v0.5.5)
# 触发: echo EXEC
# 断言: privileged_exec
set -e
cd "$(dirname "$0")"
source lib_k8s.sh

POD="esc-priv"
IMAGE="ebpf-test:mount"

print_result "k3s 特权容器执行 shell (privileged_exec)"

print_test "导入镜像 $IMAGE"
import_image "$IMAGE"
print_pass

reset_environment
start_guard || exit 1

print_test "创建逃逸 pod + 触发"
kubectl run "$POD" --image="$IMAGE" --privileged --restart=Never --command -- sleep 300 2>/dev/null
sleep 8
kubectl exec -n default "$POD" -- /bin/sh -c "sh -c 'sleep 5' & sleep 1; echo EXEC" 2>/dev/null
print_pass

print_test "检测到 privileged_exec"
if wait_for_rule "privileged_exec"; then
    print_pass
else
    print_fail "events.log 无 privileged_exec"
fi

print_test "容器冻结 (paused container 铁证)"
if assert_frozen "$POD"; then
    print_pass
else
    print_fail "容器冻结 (paused container 铁证)失败"
fi

print_guard_log
cleanup "$POD"
print_summary
