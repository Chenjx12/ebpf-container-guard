#!/bin/bash
# test_capset.sh — capset 能力设置场景测试 (v0.4.2)
#
# 场景: 容器内 capset 设置 CAP_SYS_ADMIN (0x200000)
#       → 能力覆盖检测 (capset_cap_sys_admin)
# 预期:
#   终端: 🚨 安全告警 - MEDIUM / 规则: capset_cap_sys_admin
#   events.log: {"rule":"capset_cap_sys_admin","severity":"MEDIUM",...}
#
# 说明: tracepoint 在 syscall 校验前触发, capset 成功或失败均上报;
#       负向测试: capset 清零 (降权) 不得触发告警。
#
# 用法: sudo bash test_capset.sh

set -e
cd "$(dirname "$0")"
source lib.sh

IMAGE="ebpf-test:capset"
CONTAINER="test_capset"
TEST_CONTAINERS="$CONTAINER"

print_result "capset 能力设置 (capset_cap_sys_admin)"

# 1. 构建镜像
print_test "构建测试镜像 $IMAGE"
bash ./build_image.sh "$IMAGE"
print_pass

# 2. 重置环境 + 启动 guard
reset_environment
start_guard || exit 1

# 3. 触发攻击（ctypes syscall capset 设置 CAP_SYS_ADMIN）
print_test "容器内 capset 设置 CAP_SYS_ADMIN"
docker run -d --privileged --name "$CONTAINER" "$IMAGE" > /dev/null
sleep 3
docker exec "$CONTAINER" python3 -c "
import ctypes, sys
libc = ctypes.CDLL(None)
SYS_capset = 126  # x86_64
# header: cap_version(_LINUX_CAPABILITY_VERSION_3) / pid
hdr = (ctypes.c_uint32 * 3)(0x20080522, 0, 0)
# data[0]: effective / permitted / inheritable — CAP_SYS_ADMIN = 0x200000
data = (ctypes.c_uint32 * 3)(0x200000, 0x200000, 0x200000)
ret = libc.syscall(SYS_capset, hdr, data)
print(f'capset ret={ret}')
"
print_pass

# 4. 断言
print_test "检测到 capset_cap_sys_admin"
if wait_for_rule "capset_cap_sys_admin" 12; then
    print_pass
else
    print_fail "events.log 无 capset_cap_sys_admin 记录"
fi

# 5. 负向: capset 清零（降权）不得告警
print_test "负向: capset 清零不告警"
COUNT_BEFORE=$(grep -c '"capset_cap_sys_admin"' "$PROJECT_ROOT/events.log" 2>/dev/null || echo 0)
docker exec "$CONTAINER" python3 -c "
import ctypes
libc = ctypes.CDLL(None)
hdr = (ctypes.c_uint32 * 3)(0x20080522, 0, 0)
data = (ctypes.c_uint32 * 3)(0, 0, 0)   # 清零, 不含 CAP_SYS_ADMIN
ret = libc.syscall(126, hdr, data)
print(f'capset clear ret={ret}')
"
sleep 3
COUNT_AFTER=$(grep -c '"capset_cap_sys_admin"' "$PROJECT_ROOT/events.log" 2>/dev/null || echo 0)
if [ "$COUNT_AFTER" -le "$COUNT_BEFORE" ]; then
    print_pass
else
    print_fail "capset 清零触发了告警 (计数 $COUNT_BEFORE → $COUNT_AFTER)"
fi

# 6. 输出预期日志
print_guard_alerts
print_event_log "capset_cap_sys_admin"

# 7. 清理
cleanup
