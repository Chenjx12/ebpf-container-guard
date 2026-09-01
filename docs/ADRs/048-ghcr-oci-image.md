# ADR-048: 全合一 OCI 镜像发布（GHCR 供应链首秀）

## 状态
Accepted (v0.6.1)

## 背景
v0.5.3 的 DaemonSet 镜像（`deploy/Dockerfile.guard`）是 **guard-only**：面板不打包、无 CI、
依赖未锁版本、requirements 含已弃用的 streamlit（v0.5.6 面板迁移后）。v0.6.1 验收锚点是
「docker pull 后 3 步内起面板、读真实事件」——镜像形态必须交付**全功能**（guard 引擎 + 面板同容器）。

## 方案

### 镜像（`deploy/Dockerfile`，全合一）
- Base：`python:3.10-slim`（**非 distroless**——entrypoint 需 shell、面板需 Python 运行时）
- 打包：`src/`（引擎 + server 依赖的 rule_schema/kube_utils）+ `server/`（含 `static/` Vue 构建产物）+
  `dashboard/`（auth 模块）+ `config/` + `.build/*.o`（CO-RE 探针）+ `main.py` + `entrypoint.sh`
- `entrypoint.sh`：guard（`python3 -u main.py`）后台 + uvicorn 面板前台
  （`--workers 1`——内存 session + 一次性 token 多 worker 会丢失，run.sh 既有约束）+ SIGTERM trap 联动退出
- 运行要求（README 文档化，不宣称普通权限可跑）：`--privileged` + `--pid=host` + `--network host` +
  `/sys` 挂载（BTF/tracefs）+ `/var/run/docker.sock` 挂载（docker 模式身份解析）

### 依赖（`requirements.txt`）
- 锁版本：pyyaml/docker/kubernetes/fastapi/uvicorn/argon2-cffi/pandas
- **剔除 streamlit**（v0.5.6 弃用；run.sh 仅剩兼容性 kill）

### CI（`.github/workflows/`）
- `ci.yml`：push/PR → `pytest tests/unit`（146 用例基线，全 BPF-free）
- `release.yml`：`v*` tag → docker build → trivy 扫描 + Syft SBOM → GHCR push（**GITHUB_TOKEN**，
  无需外部凭据）→ gh release 附 SBOM + 扫描报告（决策 #48 教训：发完确认 `published_at`）
- 镜像 tag 对齐 git tag：`ghcr.io/chenjx12/ebpf-container-guard:v0.6.x`

## 后果
- ✅ 「3 步验收」可达：pull → docker run（特权参数）→ 浏览器面板 + 真实事件
- ✅ 供应链证据链：trivy 报告 + SBOM 随 release 附，后续 v0.6.x 每版镜像对齐
- ❌ 镜像体积大于 guard-only（面板 + pandas）；distroless 更小但 shell/Python 不可用
- 📝 DaemonSet 镜像名切 GHCR 留后续版本（v0.6.x 内），本期验收为 docker 单机形态；
  `deploy/Dockerfile.guard` 保持 DaemonSet 变体不删

## 关联
- ADR-042（DaemonSet 容器化）、ADR-045（面板迁移）、ADR-047（攻击链）
- 决策 #48（release 纪律）、决策 #49（v0.6.x 路线）、bp_v06x.md（v0.6.1）