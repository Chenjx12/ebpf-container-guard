#!/bin/bash
# setup.sh — eBPF Container Guard 环境初始化（幂等）
#
# 用法:
#   ./setup.sh          安装依赖 + 初始化配置
#   ./setup.sh --check  仅检查环境，不安装
#   ./setup.sh --help   帮助

set -e
cd "$(dirname "$0")"

PROJECT_ROOT="$(pwd)"
CHECK_ONLY=false

# 颜色
GREEN='\033[92m'; YELLOW='\033[93m'; RED='\033[91m'; CYAN='\033[96m'; RESET='\033[0m'

echo -e "${CYAN}========================================${RESET}"
echo -e "${CYAN}  eBPF Container Guard — 环境初始化${RESET}"
echo -e "${CYAN}========================================${RESET}"

case "${1:-}" in
    --check|check)
        CHECK_ONLY=true
        echo -e "${YELLOW}检查模式：仅检查，不安装${RESET}"
        ;;
    --help|help|-h)
        sed -n '2,8p' "$0"
        exit 0
        ;;
esac

# ================================================================
# 检查函数
# ================================================================
check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

install_if_missing() {
    local pkg="$1"
    local apt_pkg="$2"
    if check_cmd "$pkg"; then
        echo -e "  ${GREEN}✅ $pkg 已安装${RESET}"
        return 0
    fi
    if [ "$CHECK_ONLY" = true ]; then
        echo -e "  ${RED}❌ $pkg 未安装（需 apt install $apt_pkg）${RESET}"
        return 1
    fi
    echo -e "  ${YELLOW}⬇️  安装 $apt_pkg ...${RESET}"
    sudo apt install -y "$apt_pkg" >/dev/null 2>&1
    if check_cmd "$pkg"; then
        echo -e "  ${GREEN}✅ $pkg 安装完成${RESET}"
    else
        echo -e "  ${RED}❌ $pkg 安装失败，请手动安装${RESET}"
        return 1
    fi
}

# ================================================================
# 步骤 1: 系统依赖
# ================================================================
echo ""
echo -e "${CYAN}[1/4] 系统依赖检查${RESET}"
install_if_missing "python3" "python3" || true
install_if_missing "clang" "clang" || true

# BCC (python3-bcc 提供 bcc 模块)
if python3 -c "import bcc" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✅ python3-bcc 已安装${RESET}"
else
    if [ "$CHECK_ONLY" = true ]; then
        echo -e "  ${RED}❌ python3-bcc 未安装（需 apt install python3-bcc bpfcc-tools）${RESET}"
    else
        echo -e "  ${YELLOW}⬇️  安装 python3-bcc bpfcc-tools ...${RESET}"
        sudo apt install -y python3-bcc bpfcc-tools >/dev/null 2>&1
        if python3 -c "import bcc" >/dev/null 2>&1; then
            echo -e "  ${GREEN}✅ python3-bcc 安装完成${RESET}"
        else
            echo -e "  ${RED}❌ BCC 安装失败，请手动安装: sudo apt install python3-bcc bpfcc-tools${RESET}"
        fi
    fi
fi

# Docker
if check_cmd "docker" && docker info >/dev/null 2>&1; then
    echo -e "  ${GREEN}✅ Docker 运行中${RESET}"
else
    if [ "$CHECK_ONLY" = true ]; then
        echo -e "  ${RED}❌ Docker 不可用（需安装并启动 docker）${RESET}"
    else
        echo -e "  ${YELLOW}⬇️  安装 Docker ...${RESET}"
        sudo apt install -y docker.io >/dev/null 2>&1 || true
        sudo systemctl enable docker >/dev/null 2>&1 || true
        sudo systemctl start docker >/dev/null 2>&1 || true
        if docker info >/dev/null 2>&1; then
            echo -e "  ${GREEN}✅ Docker 启动成功${RESET}"
        else
            echo -e "  ${RED}❌ Docker 启动失败，请手动检查${RESET}"
        fi
    fi
fi

# ================================================================
# 步骤 2: Python 依赖
# ================================================================
echo ""
echo -e "${CYAN}[2/4] Python 依赖${RESET}"
if [ "$CHECK_ONLY" = true ]; then
    echo -e "  ${YELLOW}检查 requirements.txt 依赖...${RESET}"
    # 用 pip show 检查（包名与 import 名可能不同，如 pyyaml→yaml）
    MISSING=""
    while read -r line; do
        line=$(echo "$line" | xargs)
        [ -z "$line" ] && continue
        case "$line" in \#*) continue;; esac
        pkg=$(echo "$line" | sed 's/[<>=!~].*//')
        pip3 show "$pkg" >/dev/null 2>&1 || MISSING="$MISSING $pkg"
    done < requirements.txt
    if [ -n "$MISSING" ]; then
        echo -e "  ${RED}❌ 缺失:${MISSING}${RESET}"
        echo -e "  ${YELLOW}请运行 ./setup.sh 安装${RESET}"
    else
        echo -e "  ${GREEN}✅ 所有依赖已安装${RESET}"
    fi
else
    echo -e "  ${YELLOW}⬇️  安装 pip 依赖...${RESET}"
    pip3 install -r requirements.txt >/dev/null 2>&1 || pip3 install --user -r requirements.txt >/dev/null 2>&1
    echo -e "  ${GREEN}✅ Python 依赖安装完成${RESET}"
fi

# ================================================================
# 步骤 3: 配置初始化（不覆盖已有文件）
# ================================================================
echo ""
echo -e "${CYAN}[3/4] 配置文件检查${RESET}"

if [ ! -f "config/ai_config.yaml" ]; then
    cp config/ai_config.yaml.example config/ai_config.yaml
    echo -e "  ${YELLOW}⬇️  已生成 config/ai_config.yaml（请手动填入 API Key）${RESET}"
else
    echo -e "  ${GREEN}✅ config/ai_config.yaml 已存在${RESET}"
fi

# ================================================================
# 步骤 4: 环境汇总
# ================================================================
echo ""
echo -e "${CYAN}[4/4] 环境检查汇总${RESET}"

# 内核版本
KERNEL=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$KERNEL_MAJOR" -gt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 15 ]; }; then
    echo -e "  ${GREEN}✅ 内核版本: $KERNEL (≥5.15)${RESET}"
else
    echo -e "  ${YELLOW}⚠️  内核版本: $KERNEL (建议 ≥5.15)${RESET}"
fi

# 权限检查
if [ "$(id -u)" = "0" ]; then
    echo -e "  ${GREEN}✅ 当前用户: root${RESET}"
elif sudo -n true 2>/dev/null; then
    echo -e "  ${GREEN}✅ 当前用户: 可 sudo${RESET}"
else
    echo -e "  ${YELLOW}⚠️  当前用户无免密 sudo（运行 guard 时需要密码）${RESET}"
fi

# Docker 组检查
if groups | grep -q docker; then
    echo -e "  ${GREEN}✅ docker 组权限${RESET}"
else
    echo -e "  ${YELLOW}⚠️  不在 docker 组（docker 命令可能需 sudo）${RESET}"
fi

echo ""
echo -e "${CYAN}========================================${RESET}"
if [ "$CHECK_ONLY" = true ]; then
    echo -e "${CYAN}  检查完成${RESET}"
else
    echo -e "${CYAN}  初始化完成 — 现在运行:${RESET}"
    echo -e "${CYAN}  ./run.sh${RESET}"
fi
echo -e "${CYAN}========================================${RESET}"
