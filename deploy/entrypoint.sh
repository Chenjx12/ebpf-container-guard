#!/bin/bash
# entrypoint.sh — 全合一容器入口 (v0.6.1, ADR-048)
# guard 检测引擎后台 + FastAPI/Vue3 面板前台；SIGTERM 联动退出
set -e

cleanup() {
    echo "[entrypoint] 收到退出信号, 停止 guard..."
    if [ -n "$GUARD_PID" ]; then
        kill "$GUARD_PID" 2>/dev/null || true
        wait "$GUARD_PID" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup SIGTERM SIGINT

# guard 后台启动（运行时参数可透传，如 --runtime k8s；v0.6.1 docker 形态默认 auto）
echo "[entrypoint] 启动 guard 检测引擎..."
python3 -u main.py "$@" &
GUARD_PID=$!

# 面板前台 — workers 必须 1：内存 session + 一次性 token 多 worker 会丢失
echo "[entrypoint] 启动安全面板 http://0.0.0.0:8000 ..."
echo "[entrypoint] 首次启动初始账号密码见下方日志输出"
python3 -m uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 1