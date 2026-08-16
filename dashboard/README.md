# ⚠️ DEPRECATED — 旧 Streamlit 面板 (v0.5.6 起停用)

本目录是 v0.3.x 的 Streamlit 面板，v0.5.6 已迁移为 **FastAPI + Vue3**
（见 `server/`）。保留仅用于回滚对照，计划 v0.6.0 删除。

- 新面板: `make panel` / `./run.sh --ui` → http://localhost:8000
- 旧面板启动: `streamlit run dashboard/app.py` (仅回滚/对照用)

**已知问题（迁移已修复）**：本目录 `common.py` 读取项目根 `events.log`
等路径，与 main.py 自 v0.5.2 起写入的 `logs/` 子目录不一致——旧面板
实际读不到事件日志。新 `server/common.py` 已统一，并支持
`GUARD_LOGS_DIR` 环境变量指向 k8s 容器化 guard 的日志目录。
