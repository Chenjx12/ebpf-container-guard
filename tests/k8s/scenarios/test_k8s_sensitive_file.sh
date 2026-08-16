#!/bin/bash
# test_k8s_sensitive_file.sh — k3s 场景 (v0.5.5)
# 触发: cat /etc/shadow > /dev/null 2>&1
# 断言: sensitive_file_access
set -e
cd "$(dirname "$0")"
source lib_k8s.sh

POD="esc-sensitive"
IMAGE="ebpf-test:sensitive"

print_result "k3s 敏感文件访问 (sensitive_file_access)"

print_test "导入镜像 $IMAGE"
import_image "$IMAGE"
print_pass

reset_environment
start_guard || exit 1

print_test "创建逃逸 pod + 触发"
if ! run_escape_pod "$POD" "$IMAGE"; then
    print_fail "pod 未就绪"
    cleanup "$POD"
    print_summary
fi
kubectl exec -n default "$POD" -- /bin/sh -c "cat /etc/shadow > /dev/null 2>&1; echo READ" 2>/dev/null || { print_fail "exec 触发失败"; cleanup "$POD"; print_summary; }
print_pass

print_test "检测到 sensitive_file_access"
if wait_for_rule "sensitive_file_access"; then
    print_pass
else
    print_fail "events.log 无 sensitive_file_access"
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
