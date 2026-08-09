#!/bin/bash
# test_ptrace_escape.sh — ptrace 注入逃逸场景测试
#
# 场景: --pid=host 容器内 strace 附加宿主机 PID 1 → 逃逸检测
# 预期:
#   终端: 🚨 安全告警 - HIGH / 规则: ptrace_host_init
#        Ptrace请求: PTRACE_SECCOMP_GET_METADATA -> 目标PID: 1
#        （strace 使用 0x4201/0x420e 等现代请求，匹配 target_pid=1 是核心）
#   events.log: {"rule":"ptrace_host_init","severity":"HIGH",
#                "state":"pending_review",...}（重复攻击会升级排队）
#
# 用法: sudo bash test_ptrace_escape.sh

set -e
cd "$(dirname "$0")"
source lib.sh

IMAGE="ebpf-test:ptrace"
CONTAINER="test_ptrace_escape"
TEST_CONTAINERS="$CONTAINER"

print_result "ptrace 注入逃逸 (ptrace_host_init)"

# 1. 构建镜像
print_test "构建测试镜像 $IMAGE"
bash ./build_image.sh "$IMAGE" "../images/Dockerfile.${IMAGE##*:}"
print_pass

# 2. 重置环境 + 启动 guard
reset_environment
start_guard || exit 1

# 3. 触发攻击
print_test "容器内 strace 附加宿主机 PID 1"
docker run -d --privileged --pid=host --cap-add=SYS_PTRACE \
    --name "$CONTAINER" "$IMAGE" > /dev/null
sleep 3
docker exec "$CONTAINER" bash -c \
    "timeout 5 strace -p 1 -e trace=read 2>&1 | head -3; echo PTRACE_DONE"
print_pass

# 4. 断言
print_test "检测到 ptrace_host_init"
if wait_for_rule "ptrace_host_init" 12; then
    print_pass
else
    print_fail "events.log 无 ptrace_host_init 记录"
fi

# 5. 输出预期日志
print_guard_alerts
print_event_log "ptrace_host_init"

# 6. 清理
cleanup
