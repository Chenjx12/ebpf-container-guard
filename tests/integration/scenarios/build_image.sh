#!/bin/bash
# build_image.sh — 构建场景测试镜像（预置代理参数，网络可用时自动构建）
# 用法: bash build_image.sh <image_tag>
#   镜像名决定 Dockerfile: ebpf-test:mount → tests/images/Dockerfile.mount
#   构建上下文: 项目根目录

set -e
TAG="$1"
SCENARIOS_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCENARIOS_DIR/../../.." && pwd)"

if [ -z "$TAG" ]; then
    echo "用法: bash build_image.sh <image_tag>"
    exit 1
fi

IMAGE_NAME="${TAG##*:}"
DOCKERFILE="$PROJECT_ROOT/tests/images/Dockerfile.${IMAGE_NAME}"

echo "--- 构建 $TAG ---"
echo "  Dockerfile: $DOCKERFILE"
echo "  Context:    $PROJECT_ROOT"

# 镜像已存在则跳过
if docker image inspect "$TAG" > /dev/null 2>&1; then
    echo "  镜像已存在，跳过构建"
    exit 0
fi

# 构建（使用 host 网络共享宿主机 DNS/代理能力）
if docker build --network host -t "$TAG" \
    --build-arg HTTP_PROXY=http://192.168.65.1:7890 \
    --build-arg HTTPS_PROXY=http://192.168.65.1:7890 \
    -f "$DOCKERFILE" "$PROJECT_ROOT" > /tmp/build_${IMAGE_NAME}.log 2>&1; then
    echo "  ✅ 构建成功"
else
    echo "  ❌ 构建失败（可能是代理/网络问题）"
    echo "     检查: clash 代理是否开启 (192.168.65.1:7890)"
    echo "     日志: /tmp/build_${IMAGE_NAME}.log"
    sudo cat /tmp/build_${IMAGE_NAME}.log | tail -5
    exit 1
fi