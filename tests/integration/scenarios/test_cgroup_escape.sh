#!/bin/bash
# test_cgroup_escape.sh — cgroup release_agent 写入场景测试 (v0.4.2)
#
# 场景: 特权容器内写入 release_agent/notify_on_release
#       → CVE-2022-0492 (cgroup release_agent 逃逸链) 写入检测
# 预期:
#   终端: 🚨 安全告警 - HIGH / 规则: cgroup_release_agent_write
#   events.log: {"rule":"cgroup_release_agent_write","severity":"HIGH",...}
#
# 说明: 主机为 cgroup v2 时无法挂载 cgroup v1 真链, 用合成写入
#       (--privileged 容器内任意目录写同名文件) 验证检测逻辑;
#       openat 探针内核态按 basename+写标志过滤, 与 cgroup 版本无关。
#
# 用法: sudo bash test_cgroup_escape.sh

set -e
cd "$(dirname "$0")"
source lib.sh

IMAGE="ebpf-test:cgroup"
CONTAINER="test_cgroup"
TEST_CONTAINERS="$CONTAINER"

print_result "cgroup release_agent 写入 (cgroup_release_agent_write)"

# 1. 构建镜像
print_test "构建测试镜像 $IMAGE"
bash ./build_image.sh "$IMAGE"
print_pass

# 2. 重置环境 + 启动 guard
reset_environment
start_guard || exit 1

# 3. 触发攻击（合成写入）
print_test "容器内写入 release_agent / notify_on_release"
docker run -d --privileged --name "$CONTAINER" "$IMAGE" > /dev/null
sleep 3
docker exec "$CONTAINER" bash -c "
    mkdir -p /tmp/cgrp
    echo 1 > /tmp/cgrp/notify_on_release
    echo /tmp/evil.sh > /tmp/cgrp/release_agent
    echo CGROUP_WRITE_DONE
"
print_pass

# 4. 断言
print_test "检测到 cgroup_release_agent_write"
if wait_for_rule "cgroup_release_agent_write" 12; then
    print_pass
else
    print_fail "events.log 无 cgroup_release_agent_write 记录"
fi

# 5. 输出预期日志
print_guard_alerts
print_event_log "cgroup_release_agent_write"

# 6. 清理
cleanup
