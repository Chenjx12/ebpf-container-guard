# ADR-050: 资产推断 + 状态落盘（PENDING_REVIEW 状态机 + 三段留痕 + 重启恢复）

## 状态
Accepted (v0.6.3) — 2026-09-02 docker 单机冒烟全绿后转正 (CHANGELOG v0.6.3 Verified):
资产状态机 / 三段留痕 / 真实阻断 / 重启恢复全链路实测通过。k8s NetworkPolicy
孤儿清扫已实现 + 单测覆盖, 未做 k8s E2E 实测 (开发机 k3s 宿主态, 诚实标注,
待后续版本补验)。

## 背景
bp_v06x v0.6.3 验收锚点：「**新资产自动落 PENDING_REVIEW**；**重启后资产状态与阻断规则
都在**」。现状缺口：
- `/api/assets` 只有 k8s pod 分组视图（docker 模式直接报「k8s API 不可用」），
  无分类、无状态机、无留痕
- netblock 阻断规则**纯内存**（停机靠 `_shutdown` 主动 unblock 兜底；异常退出 /
  容器重建后规则即失）
- k8s 隔离后容器销毁，deny-all netpol 无人回收（防泄漏）
- host 事件规则判定只有半豁免（靠 attack_vector 白名单），无结构性表达与测试固化

## 方案

### 资产推断（server 侧，不动 guard 引擎管线）
- `src/core/assets.py`：
  - `AssetClassifier(rules_file=config/assets.yaml)` — 规则可配置：
    `namespace`(fnmatch) / `labels`(全等，多键须全中) / `image`(正则)；
    **首条命中定级**；全部未中 → **兜底 medium**
  - `AssetStore(state_file=logs/assets.yaml, audit_file=logs/assets_audit.log)`：
    状态机 `PENDING_REVIEW → CONFIRMED / OVERRIDDEN`；YAML 原子落盘
    （tmp+rename）；**三段留痕 JSONL**：
    `auto_inference`（首次推断）/ `human_decision`（确认/覆盖，含人、理由）/
    `status_transition`（状态变更）——v0.6.7 六层审计的人工决策层直接转写此文件
- **状态文件位置 = logs/ 挂载目录**（容器内 /app/logs，跨容器重建持久）——
  与 users.yaml 教训（config/ 可写层，重建即失，v0.6.2.1/决策 #51）形成对比：
  **需要跨重建持久的数据必须放 LOGS_DIR**

### API（server/routes.py）
- `GET /api/assets` — 增强不破坏现有面板结构：
  - k8s 模式：pod 分组不变，每个 pod 增加 `level / asset_state / asset_rule / audit_count`
  - docker 模式（v0.6.3 新增）：容器清单 + 同样分类字段（不再报错）
- `POST /api/assets/{asset_id}/confirm` — `{reason}`（operator+）
- `POST /api/assets/{asset_id}/override` — `{level, reason}`（admin）
- `GET /api/assets/{asset_id}/audit` — 三段留痕可查（v0.6.4 前端接入）

### 顺风车（同主题「重启后状态不丢」）
1. **netblock 重启恢复**：`NetBlocker(persist_path=logs/netblock_rules.yaml)` —
   block/unblock 时同步快照；启动 `replay()` 重放 iptables FORWARD DROP；
   XDP 层不在镜像（bpftool 缺失已知限制）→ 重放覆盖实际生效的 iptables 层
2. **NetworkPolicy 清理兜底**：`NetworkPolicyBackend.sweep_orphaned()` —
   按 `managed-by=ebpf-container-guard` 标签找 guard 创建的 netpol，
   pod 已不存在则删除；k8s 模式每 30s 后台清扫
3. **host 事件仅记录不告警（形式化）**：`handle_event` 结构性表达——
   规则判定只保留 `ptrace_host_init`（宿主 ptrace 攻容器是真实向量，
   v0.5.x 既有决策），其余 host 事件只进 behaviors.log

## 后果
- ✅ 资产分级可讲：分类器规则可配置、兜底诚实（未命中 = medium，不虚标）
- ✅ 状态机 + 三段留痕可审计：确认/覆盖留人、留理由、留时间线
- ✅ 重启恢复闭环：资产状态 + 阻断规则都在（验收锚点），netpol 不泄漏
- ❌ 资产状态由 server 侧维护，guard 引擎不消费分级（分级处置留 v0.6.x 后续/
  v0.7 Guard Agent）
- 📝 面板渲染必须渲染级验收（决策 #51 连带：/api/assets 改动同样要渲染验证）

## 关联
- ADR-043（nsenter netblock）、ADR-045（面板迁移）、ADR-048/049（镜像供应链）、
  决策 #51（渲染级验收）、决策 #52（本地，本决策的决策记录）