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
if ! run_escape_pod "$POD" "$IMAGE"; then
    print_fail "pod 未就绪"
    cleanup "$POD"
    print_summary
fi
# 触发链: 外层 runc:[2:INIT]→/bin/sh (comm=runc:[2:INIT] 排除) →
#         sh 子进程 exec /bin/sh (comm=sh ∉ 排除表 → 命中!)
# 不用 /usr/bin/env: env→/bin/sh 成功 execve 事件被 ring 丢弃(实测 2/2 丢)
# sleep 30 让子 sh 长驻 — resolve 兜底读 /proc/<pid>/cgroup 需进程存活
# timeout -k 5 必需: sh 命中后容器冻结, exec 连接挂住 — 挂住(124)即冻结预期;
# -k 5: kubectl exec 挂住时 SIGTERM 可能杀不掉, 5s 后 SIGKILL 兜底
# `|| true`: 124 是预期, 豁免 set -e 不让脚本退出
timeout -k 5 20 kubectl exec -n default "$POD" -- /bin/sh -c "/bin/sh -c 'sleep 30; echo EXEC'" 2>/dev/null || true
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
