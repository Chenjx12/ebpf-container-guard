#!/bin/bash
# test_nsenter.sh — nsenter 命名空间逃逸场景测试
#
# 场景: --pid=host 容器内 nsenter 进入宿主机命名空间 → 逃逸检测
# 预期:
#   终端: 🚨 安全告警 - CRITICAL / 规则: nsenter_escape
#        攻击向量: nsenter_escape
#   events.log: {"rule":"nsenter_escape","severity":"CRITICAL",...}
#
# 注意: nsenter 检测基于 execve 探针的 comm 匹配（comm=nsenter）。
#       真实攻击可能用 nsenter -t 1 -m -u -i -n sh 组合进入全部命名空间。
#
# 用法: sudo bash test_nsenter.sh

set -e
cd "$(dirname "$0")"
source lib.sh

IMAGE="ebpf-test:nsenter"
CONTAINER="test_nsenter"
TEST_CONTAINERS="$CONTAINER"

print_result "nsenter 命名空间逃逸 (nsenter_escape)"

# 1. 构建镜像
print_test "构建测试镜像 $IMAGE"
docker image inspect "$IMAGE" > /dev/null 2>&1 || \
    docker build -q -t "$IMAGE" -f ../images/Dockerfile.nsenter ../.. > /dev/null 2>&1
print_pass

# 2. 重置环境 + 启动 guard
reset_environment
start_guard || exit 1

# 3. 触发攻击
print_test "容器内 nsenter 进入宿主机命名空间"
docker run -d --privileged --pid=host --name "$CONTAINER" "$IMAGE" > /dev/null
sleep 3
docker exec "$CONTAINER" bash -c \
    "timeout 3 nsenter -t 1 -m -u -i -n true 2>/dev/null; echo NSENTER_DONE"
print_pass

# 4. 断言
print_test "检测到 nsenter_escape"
if wait_for_rule "nsenter_escape" 12; then
    print_pass
else
    print_fail "events.log 无 nsenter_escape 记录"
fi

# 5. 输出预期日志
print_guard_alerts
print_event_log "nsenter_escape"

# 6. 清理
cleanup
