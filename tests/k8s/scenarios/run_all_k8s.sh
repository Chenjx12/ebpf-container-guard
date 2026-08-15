#!/bin/bash
# run_all_k8s.sh — k3s 逃逸场景测试套件一键运行 (v0.5.5)
#
# 用法: sudo bash run_all_k8s.sh [场景名]
#   不带参数: 运行全部 6 个场景
#   带参数:   只运行指定场景 (如 test_k8s_procfs_mount.sh)
set -e
cd "$(dirname "$0")"

SCENARIOS=(
    test_k8s_procfs_mount.sh
    test_k8s_sensitive_file.sh
    test_k8s_reverse_shell.sh
    test_k8s_privileged_exec.sh
    test_k8s_cgroup_write.sh
    test_k8s_capset.sh
)

if [ $# -gt 0 ]; then
    SCENARIOS=("$1")
fi

echo "=============================================="
echo "  eBPF Container Guard — k3s 逃逸场景测试套件"
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
