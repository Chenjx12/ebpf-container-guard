#!/bin/bash
# build_image.sh — 构建场景测试镜像（预置代理参数，网络可用时自动构建）
# 用法: bash build_image.sh <image_tag> <dockerfile_path>

set -e
TAG="$1"
DOCKERFILE="$2"
PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

echo "--- 构建 $TAG ---"
cd "$PROJECT_ROOT"

# 镜像已存在则跳过
if docker image inspect "$TAG" > /dev/null 2>&1; then
    echo "  镜像已存在，跳过构建"
    exit 0
fi

# 构建（带代理 build-arg；失败时提示网络问题）
if docker build -t "$TAG" \
    --build-arg HTTP_PROXY=http://192.168.65.1:7890 \
    --build-arg HTTPS_PROXY=http://192.168.65.1:7890 \
    -f "$DOCKERFILE" . > /tmp/build_$(basename $TAG).log 2>&1; then
    echo "  ✅ 构建成功"
else
    echo "  ❌ 构建失败（可能是代理/网络问题）"
    echo "     检查: clash 代理是否开启 (192.168.65.1:7890)"
    echo "     日志: /tmp/build_$(basename $TAG).log"
    exit 1
fi
