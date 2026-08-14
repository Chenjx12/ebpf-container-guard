#!/bin/bash
# run_all_scenarios.sh — 一键运行全部逃逸场景测试
#
# 用法: sudo bash run_all_scenarios.sh [场景名]
#   不带参数: 运行全部 6 个场景
#   带参数:   只运行指定场景（如 test_mount_escape）
#
# 场景列表:
#   test_mount_escape.sh      procfs 挂载逃逸 (CRITICAL)
#   test_socket_mount.sh      Docker socket 挂载 (CRITICAL)
#   test_ptrace_escape.sh     ptrace 注入 (HIGH)
#   test_sensitive_file.sh    敏感文件访问 (HIGH)
#   test_reverse_shell.sh     反弹 shell / C2 (HIGH)
#   test_nsenter.sh           nsenter 命名空间逃逸 (CRITICAL)
#   test_cgroup_escape.sh     cgroup release_agent 写入 (HIGH, v0.4.2)
#   test_capset.sh            capset 能力设置 (MEDIUM, v0.4.2)

set -e
cd "$(dirname "$0")"

SCENARIOS=(
    test_mount_escape.sh
    test_socket_mount.sh
    test_ptrace_escape.sh
    test_sensitive_file.sh
    test_reverse_shell.sh
    test_nsenter.sh
    test_cgroup_escape.sh
    test_capset.sh
)

if [ $# -gt 0 ]; then
    SCENARIOS=("$1")
fi

echo "=============================================="
echo "  eBPF Container Guard — 逃逸场景测试套件"
echo "=============================================="
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0

for s in "${SCENARIOS[@]}"; do
    echo ""
    echo "##############################################"
    echo "# 运行场景: $s"
    echo "##############################################"
    if sudo bash "$s"; then
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
done

echo ""
echo "=============================================="
echo "  场景套件汇总"
echo "=============================================="
echo "  通过: $TOTAL_PASS  失败: $TOTAL_FAIL"
[ $TOTAL_FAIL -eq 0 ] && echo "  🎉 全部场景通过" || echo "  ⚠️ 有场景失败"
exit $TOTAL_FAIL
