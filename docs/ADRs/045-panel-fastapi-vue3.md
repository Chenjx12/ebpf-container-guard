# ADR-045: 面板迁移——Streamlit → FastAPI + Vue3（API 化 + 暴露面管控）

## 状态
Accepted (v0.5.6)

## 背景
v0.3.0 起的面板是 Streamlit（dashboard/，9 页面），与 main.py 通过文件通道联动（decisions.log 轮询 + yaml 3s 热加载）。用户提出架构升级：后端出标准 API、前端独立、可接 nginx。探索中发现**存量 bug**：dashboard/common.py 读项目根 events.log，而 main.py 自 v0.5.2 写 logs/ 子目录——现网面板实际读不到事件日志。

## 技术选型决策
- **后端 FastAPI**（vs Flask）：自带 /docs 交互文档（答辩演示）、pydantic 声明式校验；Flask 背景迁移成本低，简历 +1 现代框架
- **前端 Vue3 + Element Plus CDN**（vs React 工程化）：零构建零打包，vendor 本地副本离线兜底，哈希路由自写 ~30 行
- **认证**：服务端内存 session（secrets.token_urlsafe(32) cookie，HttpOnly+Lax，8h），**不用 JWT**——安全产品要登出即失效 + token 一次性原子性；单 worker 约束写进 run.sh
- **路径修复**：统一到 logs/（修复存量 bug），`GUARD_LOGS_DIR` 环境变量支持 k8s 容器化 guard 的日志目录（/var/lib/ebpf-guard）

## 暴露面管控（安全默认）
- **/docs (Swagger) 默认关闭**，`ENABLE_DOCS=1` 才挂载——渗透测试视角 API 文档是信息泄露点，安全产品自身不做零暴露面
- Cookie HttpOnly + SameSite=Lax 必设；Secure 生产开本地关
- RBAC 三层（admin/operator/analyst），token 门控（add_member/add_rule 一次性）沿用 auth.py 原逻辑

## 验证
- 单测 121/121（新增 16 例 API 认证/RBAC，临时 users.yaml + 日志路径隔离）
- API 全端点 curl 回归（含 401/403 负例）
- **联动实证**：API 写判决 → k8s guard DecisionExecutor 2s 内消费（`[K8sExecutor] 无法解析 api-link-test-1`，假 ID 无副作用）
- 路径覆盖实证：GUARD_LOGS_DIR 指向 /var/lib/ebpf-guard 读到 k8s guard 真实 5473 条告警
- 测试副作用教训：PUT 配置端点实测曾覆盖真实 ai_config.yaml 的 API key——备份机制（save_ai_config .bak）当场恢复，单测已改临时路径隔离

## 后果
- ✅ 标准 REST API（15+ 端点）+ Vue3 SPA，nginx 反代部署就绪
- ✅ 修掉旧面板读不到事件的存量 bug
- ✅ /docs 安全默认 + 环境变量开关（答辩点：安全产品自身暴露面管控）
- ❌ 内存 session 重启失效（单 worker + 重启需重登，已接受）
- ❌ 旧 dashboard/ 保留至 v0.6.0（deprecated 标记，回滚保障）
- 📝 联动纯文件通道验证成立：写同样文件，main.py 的 DecisionExecutor/热加载天然工作，**main.py 零改动**

## 关联
- ADR-014（分级自动化）、决策 #14（判决粒度=容器）、决策 #17（定制前端面板）
- server/ 代码：server/app.py（装配+session）、server/routes.py（API）、server/common.py（数据层）、server/static/（Vue3 SPA）
