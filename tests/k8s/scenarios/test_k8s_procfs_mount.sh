#!/bin/bash
# test_k8s_procfs_mount.sh — k3s procfs 挂载逃逸 (v0.5.5)
# 触发: pod 内 mount -t proc → CRITICAL → pause → cgroup.freeze
# 断言: FROZEN (events.log) + exec 卡住 (paused container 铁证)
set -e
cd "$(dirname "$0")"
source lib_k8s.sh

POD="esc-procfs"
IMAGE="ebpf-test:mount"

print_result "k3s procfs 挂载逃逸 (procfs_mount_escape)"

print_test "导入镜像 $IMAGE"
import_image "$IMAGE"
print_pass

reset_environment
start_guard || exit 1

print_test "创建逃逸 pod + 触发挂载"
kubectl run "$POD" --image="$IMAGE" --privileged --restart=Never --command -- sleep 300 2>/dev/null
sleep 8
kubectl exec -n default "$POD" -- /bin/sh -c "mkdir -p /tmp/host_proc && mount -t proc proc /tmp/host_proc && echo MOUNTED" 2>/dev/null
print_pass

print_test "检测到 procfs_mount_escape"
if wait_for_rule "procfs_mount_escape"; then
    print_pass
else
    print_fail "events.log 无 procfs_mount_escape"
fi

print_test "容器冻结 (paused container 铁证)"
if assert_frozen "$POD"; then
    print_pass
else
    print_fail "容器未冻结"
fi

print_guard_log
cleanup "$POD"
print_summary
