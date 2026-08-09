#!/bin/bash
# test_reverse_shell.sh — 反弹 shell / C2 出站场景测试
#
# 场景: 容器内 curl 外部非标端口 → 网络攻击检测 + 流量阻断
# 预期:
#   终端: 🚨 安全告警 - HIGH / 规则: reverse_shell
#        🚫 [NETBLOCK] DROP <ip>:<port> (C2/反弹Shell阻断, 业务流量保留)
#   events.log: {"rule":"reverse_shell","severity":"HIGH",
#                "netblocked":true,...}
#   iptables:   FORWARD 链出现 DROP 规则（出站阻断）
#   XDP map:    block_port_map 有条目（入站阻断，mixed 后端）
#
# 注意: 目标 IP:port 用 192.168.65.1:7890（宿主机 clash 代理），
#       首次阻断后同一目标后续事件 netblocked=false（已阻断，设计）。
#
# 用法: sudo bash test_reverse_shell.sh

set -e
cd "$(dirname "$0")"
source lib.sh

IMAGE="ebpf-test:net"
CONTAINER="test_reverse_shell"
TEST_CONTAINERS="$CONTAINER"
TARGET_HOST="192.168.65.1"
TARGET_PORT="7890"

print_result "反弹 shell / C2 出站 (reverse_shell)"

# 1. 构建镜像
print_test "构建测试镜像 $IMAGE"
docker image inspect "$IMAGE" > /dev/null 2>&1 || \
    docker build -q -t "$IMAGE" -f ../images/Dockerfile.net ../.. > /dev/null 2>&1
print_pass

# 2. 重置环境 + 启动 guard
reset_environment
start_guard || exit 1

# 3. 触发攻击
print_test "容器连接外部非标端口 $TARGET_HOST:$TARGET_PORT"
docker run -d --privileged --name "$CONTAINER" "$IMAGE" > /dev/null
sleep 3
docker exec "$CONTAINER" bash -c \
    "timeout 3 bash -c 'echo > /dev/tcp/$TARGET_HOST/$TARGET_PORT' 2>/dev/null; echo CONNECT_ATTEMPT"
print_pass

# 4. 断言
print_test "检测到 reverse_shell"
if wait_for_rule "reverse_shell" 12; then
    print_pass
else
    print_fail "events.log 无 reverse_shell 记录"
fi

print_test "流量阻断已触发 (NETBLOCK)"
if grep -q "NETBLOCK" "$GUARD_LOG"; then
    print_pass
else
    print_fail "guard 无 NETBLOCK 输出"
fi

# 5. 输出预期日志
print_guard_alerts
print_event_log "reverse_shell"
echo "--- iptables 出站阻断规则 ---"
sudo iptables -L FORWARD -n 2>/dev/null | grep DROP | head -2

# 6. 清理
cleanup
