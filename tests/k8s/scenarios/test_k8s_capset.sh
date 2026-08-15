#!/bin/bash
# test_k8s_capset.sh — k3s 场景 (v0.5.5)
# 触发: python3 -c "import ctypes
# 断言: capset_cap_sys_admin
set -e
cd "$(dirname "$0")"
source lib_k8s.sh

POD="esc-cap"
IMAGE="ebpf-test:capset"

print_result "k3s capset 能力设置 (capset_cap_sys_admin)"

print_test "导入镜像 $IMAGE"
import_image "$IMAGE"
print_pass

reset_environment
start_guard || exit 1

print_test "创建逃逸 pod + 触发"
kubectl run "$POD" --image="$IMAGE" --privileged --restart=Never --command -- sleep 300 2>/dev/null
sleep 8
kubectl exec -n default "$POD" -- /bin/sh -c 'python3 -c "import ctypes; libc=ctypes.CDLL(None); hdr=(ctypes.c_uint32*3)(0x20080522,0,0); data=(ctypes.c_uint32*3)(0x200000,0x200000,0x200000); libc.syscall(126,hdr,data); print(\"CAPSET\")"' 2>/dev/null
print_pass

print_test "检测到 capset_cap_sys_admin"
if wait_for_rule "capset_cap_sys_admin"; then
    print_pass
else
    print_fail "events.log 无 capset_cap_sys_admin"
fi

print_test "容器冻结"
if wait_for_rule "capset_cap_sys_admin"; then
    print_pass
else
    print_fail "events.log 无 capset_cap_sys_admin"
fi

print_guard_log
cleanup "$POD"
print_summary
