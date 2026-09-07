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

# 前端启动命令（v0.5.6: FastAPI + Vue3 面板, 默认 8000 端口）
# 必须 --workers 1: 内存 session + 一次性 token 多 worker 会丢失
# ENABLE_DOCS=1 才开放 /docs (Swagger) — 安全产品默认零暴露面
UI_CMD="python3 -m uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 1"

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
    echo "🟢 启动安全面板 (FastAPI + Vue3)..."
    echo "   面板地址: http://localhost:8000"
    echo "   首次启动请查看终端中的初始密码"
    echo ""
    eval "$UI_CMD"
}

stop_all() {
    echo "🛑 停止所有服务..."
    # 1) 优先: 锁文件 PID (run.sh 启动的 guard) — 优雅退出 + 最多等 5s
    if [ -f "$GUARD_PID_FILE" ]; then
        local pid
        pid=$(cat "$GUARD_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            sudo kill "$pid" 2>/dev/null || true
            for _ in 1 2 3 4 5; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1
            done
        fi
        rm -f "$GUARD_PID_FILE"
    fi
    # 2) 兜底 (v0.6.4 M4b): 仅当仍有 guard 实例存活时清理 —
    #    收敛 pkill 误杀面 (systemd 实例 / 手动 sudo 实例等非 run.sh 启动者)
    if pgrep -f "python3 main.py" > /dev/null 2>&1; then
        echo "⚠️  检测到非锁文件的 guard 实例, 兜底清理..."
        sudo pkill -f "python3 main.py" 2>/dev/null || true
        sleep 1
    fi
    # 3) UI 面板: 按端口精确定位 (仅杀占用者)
    local ui_pid
    ui_pid=$(lsof -ti:8000 2>/dev/null || true)
    [ -n "$ui_pid" ] && kill $ui_pid 2>/dev/null || true
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