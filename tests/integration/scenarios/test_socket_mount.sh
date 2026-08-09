#!/bin/bash
# test_socket_mount.sh — Docker socket 挂载逃逸场景测试
#
# 场景: 特权容器挂载宿主 docker.sock → 逃逸前置步骤
# 预期:
#   终端: 🚨 安全告警 - CRITICAL / 规则: docker_socket_mount
#        攻击向量: docker_socket_mount
#        （socket 挂载是逃逸前置，优先级高）
#   events.log: {"rule":"docker_socket_mount","severity":"CRITICAL",...}
#
# 用法: sudo bash test_socket_mount.sh

set -e
cd "$(dirname "$0")"
source lib.sh

IMAGE="ebpf-test:mount"   # 复用 mount 镜像（含 util-linux mount）
CONTAINER="test_socket_mount"
TEST_CONTAINERS="$CONTAINER"

print_result "Docker socket 挂载 (docker_socket_mount)"

# 1. 构建镜像（若已存在则跳过）
print_test "准备测试镜像 $IMAGE"
if bash ./build_image.sh "$IMAGE" "../images/Dockerfile.${IMAGE##*:}"; then
    print_pass
else
    print_fail "镜像不可用"
    exit 1
fi

# 2. 重置环境 + 启动 guard
reset_environment
start_guard || exit 1

# 3. 触发攻击
print_test "特权容器挂载 docker.sock"
docker run -d --privileged --name "$CONTAINER" -v /var/run/docker.sock:/var/run/docker.sock \
    "$IMAGE" > /dev/null
sleep 3
docker exec "$CONTAINER" bash -c \
    "mount --bind /var/run/docker.sock /var/run/docker.sock && echo SOCKET_OK"
print_pass

# 4. 断言
print_test "检测到 docker_socket_mount"
if wait_for_rule "docker_socket_mount"; then
    print_pass
else
    print_fail "events.log 无 docker_socket_mount 记录"
fi

# 5. 输出预期日志
print_guard_alerts
print_event_log "docker_socket_mount"

# 6. 清理
cleanup
