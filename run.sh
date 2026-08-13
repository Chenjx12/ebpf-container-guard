#!/bin/bash
# run.sh — eBPF Container Guard 统一启动入口 (v0.3.11)
#
# 用法:
#   ./run.sh           启动 guard（后台）+ 面板（前台）
#   ./run.sh --guard   仅启动 guard（后台）
#   ./run.sh --ui      仅启动面板（前台）
#   ./run.sh --stop    停止所有
#
# 更换前端时只需修改 UI_CMD 变量。

set -e
cd "$(dirname "$0")"

PROJECT_ROOT="$(pwd)"
GUARD_PID_FILE="/tmp/ebpf-guard.pid"

# 前端启动命令（更换前端时只改这里）
UI_CMD="streamlit run dashboard/app.py --server.headless true --server.port 8501"

start_guard() {
    if [ -f "$GUARD_PID_FILE" ] && kill -0 $(cat "$GUARD_PID_FILE") 2>/dev/null; then
        echo "⚠️  Guard 已在运行 (PID $(cat "$GUARD_PID_FILE"))"
        return
    fi
    echo "🔵 启动 Guard 检测引擎..."
    sudo PYTHONUNBUFFERED=1 python3 main.py &
    echo $! > "$GUARD_PID_FILE"
    echo "✅  Guard 已启动 (PID $(cat "$GUARD_PID_FILE"))"
}

start_ui() {
    echo "🟢 启动面板..."
    echo "   面板地址: http://localhost:8501"
    echo "   首次启动请查看终端中的初始密码"
    echo ""
    eval "$UI_CMD"
}

stop_all() {
    echo "🛑 停止所有服务..."
    if [ -f "$GUARD_PID_FILE" ]; then
        sudo kill $(cat "$GUARD_PID_FILE") 2>/dev/null || true
        rm -f "$GUARD_PID_FILE"
    fi
    sudo pkill -f "python3 main.py" 2>/dev/null || true
    kill $(lsof -ti:8501) 2>/dev/null || true
    echo "✅ 已停止"
}

case "${1:-all}" in
    --guard|guard)
        start_guard
        ;;
    --ui|ui)
        start_ui
        ;;
    --stop|stop)
        stop_all
        ;;
    --help|help|-h)
        sed -n '3,9p' "$0"
        ;;
    *)
        start_guard
        start_ui
        ;;
esac