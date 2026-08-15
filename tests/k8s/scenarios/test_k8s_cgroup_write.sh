#!/bin/bash
# test_k8s_cgroup_write.sh — k3s 场景 (v0.5.5)
# 触发: mkdir -p /tmp/cgrp && echo 1 > /tmp/cgrp/notify_on_release && echo x > /tmp/cgrp/release_agent
# 断言: cgroup_release_agent_write
set -e
cd "$(dirname "$0")"
source lib_k8s.sh

POD="esc-cgroup"
IMAGE="ebpf-test:cgroup"

print_result "k3s cgroup release_agent 写入 (cgroup_release_agent_write)"

print_test "导入镜像 $IMAGE"
import_image "$IMAGE"
print_pass

reset_environment
start_guard || exit 1

print_test "创建逃逸 pod + 触发"
kubectl run "$POD" --image="$IMAGE" --privileged --restart=Never --command -- sleep 300 2>/dev/null
sleep 8
kubectl exec -n default "$POD" -- /bin/sh -c "mkdir -p /tmp/cgrp && echo 1 > /tmp/cgrp/notify_on_release && echo x > /tmp/cgrp/release_agent; echo WRITTEN" 2>/dev/null
print_pass

print_test "检测到 cgroup_release_agent_write"
if wait_for_rule "cgroup_release_agent_write"; then
    print_pass
else
    print_fail "events.log 无 cgroup_release_agent_write"
fi

print_test "容器网络被隔离 (FORWARD DROP)"
if assert_isolated "$POD"; then
    print_pass
else
    print_fail "容器网络被隔离 (FORWARD DROP)失败"
fi

print_guard_log
cleanup "$POD"
print_summary
