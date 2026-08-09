#!/bin/bash
# test_sensitive_file.sh — 敏感文件访问场景测试
#
# 场景: 容器挂载宿主 /etc 后读取 /etc/shadow → 数据窃取检测
# 预期:
#   终端: 🚨 安全告警 - HIGH / 规则: sensitive_file_access
#        访问路径: /etc/shadow（openat 探针内核态路径过滤命中）
#   events.log: {"rule":"sensitive_file_access","severity":"HIGH",...}
#
# 注意: openat 探针仅上报匹配敏感路径的事件（内核态过滤），
#       正常文件访问不会产生事件——这是降噪设计。
#
# 用法: sudo bash test_sensitive_file.sh

set -e
cd "$(dirname "$0")"
source lib.sh

IMAGE="ebpf-test:sensitive"
CONTAINER="test_sensitive"
TEST_CONTAINERS="$CONTAINER"

print_result "敏感文件访问 (sensitive_file_access)"

# 1. 构建镜像
print_test "构建测试镜像 $IMAGE"
docker image inspect "$IMAGE" > /dev/null 2>&1 || \
    docker build -q -t "$IMAGE" -f ../images/Dockerfile.sensitive ../.. > /dev/null 2>&1
print_pass

# 2. 重置环境 + 启动 guard
reset_environment
start_guard || exit 1

# 3. 触发攻击
print_test "容器读取 /etc/shadow"
docker run -d --privileged --name "$CONTAINER" \
    -v /etc:/host_etc:ro "$IMAGE" > /dev/null
sleep 3
docker exec "$CONTAINER" bash -c \
    "cat /host_etc/shadow > /dev/null 2>&1; echo SHADOW_READ"
print_pass

# 4. 断言
print_test "检测到 sensitive_file_access"
if wait_for_rule "sensitive_file_access" 12; then
    print_pass
else
    print_fail "events.log 无 sensitive_file_access 记录"
fi

# 5. 输出预期日志
print_guard_alerts
print_event_log "sensitive_file_access"

# 6. 清理
cleanup
