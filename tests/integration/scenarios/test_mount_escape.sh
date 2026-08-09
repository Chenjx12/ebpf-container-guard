#!/bin/bash
# test_mount_escape.sh — procfs 挂载逃逸场景测试
#
# 场景: 特权容器内挂载宿主机 procfs → 逃逸检测
# 预期:
#   终端: 🚨 安全告警 - CRITICAL / 规则: procfs_mount_escape
#        攻击向量: procfs_mount / 文件系统: proc -> /tmp/host_proc
#        置信度: 88% 🔴 自动响应 / RESPONSE: CRITICAL → pause_container
#   events.log: {"rule":"procfs_mount_escape","severity":"CRITICAL",
#                "state":"resolved","action":"pause_container",
#                "action_status":"executed",...}
#
# 用法: sudo bash test_mount_escape.sh

set -e
cd "$(dirname "$0")"
source lib.sh

IMAGE="ebpf-test:mount"
CONTAINER="test_mount_escape"
TEST_CONTAINERS="$CONTAINER"

print_result "procfs 挂载逃逸 (procfs_mount_escape)"

# 1. 构建镜像
print_test "构建测试镜像 $IMAGE"
if docker build -q -t "$IMAGE" -f ../images/Dockerfile.mount ../.. \
    > /dev/null 2>&1; then
    print_pass
else
    print_fail "镜像构建失败"
    exit 1
fi

# 2. 重置环境 + 启动 guard
reset_environment
start_guard || exit 1

# 3. 触发攻击
print_test "特权容器挂载 procfs"
docker run -d --privileged --name "$CONTAINER" "$IMAGE" > /dev/null
sleep 3
docker exec "$CONTAINER" bash -c \
    "mkdir -p /tmp/host_proc && mount -t proc proc /tmp/host_proc && echo MOUNT_OK"
print_pass

# 4. 断言: events.log 出现 procfs_mount_escape
print_test "检测到 procfs_mount_escape"
if wait_for_rule "procfs_mount_escape"; then
    print_pass
else
    print_fail "events.log 无 procfs_mount_escape 记录"
fi

# 5. 输出预期日志
print_guard_alerts
print_event_log "procfs_mount_escape"

# 6. 清理
cleanup
