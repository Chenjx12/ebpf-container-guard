# ADR-046: AI 多配置管理 + 资产拓扑可视化

## 状态
Accepted (v0.5.7)

## 背景
① AI 配置单一（手动填 model），用户要参考 cc-switch 的多配置管理：获取模型列表（base_url+key → /models）、命名配置、一键切换。② 资产页只有列表，用户要拓扑图展示服务关联。

## AI 多配置：方案 B（profiles + 激活快照）

**备选**：
- A：guard 直读 ai_profiles.yaml 的 active——"彻底"，但 k8s 部署需 profiles 挂载 + key Secret 合并，复杂度上升
- **B（选中）**：ai_profiles.yaml 唯一存储+编辑入口，ai_config.yaml 仅激活快照（guard 零改动热加载）。k8s 完全兼容、无回归

**启动一致性**（用户提出）：面板启动 `sync_ai_snapshot()`——active profile 覆盖写 ai_config.yaml。删 ai_config 自动重建、手动改被覆盖回 active、存量自动迁移为 default profile。

**获取模型**：`POST /api/ai/models`（base_url+key → `{base_url}/models`，OpenAI 兼容 Bearer）→ 模型下拉。实测 DeepSeek 返回 v4 模型（deepseek-v4-flash/pro），比配置里的旧 deepseek-chat 更新——多配置价值体现。

## 资产拓扑：ECharts graph + 节点光晕

**踩坑链**：
1. **graphic circle 服务圈**：坐标系与 graph roam 变换不同步 → 圈不跟随 pod。弃用
2. **节点虚线边框**：贴节点，不满足"圈比节点大不连着"
3. **节点光晕（选中）**：`itemStyle.shadowColor/shadowBlur` 随节点走，roam 同步——天然"大一圈不接触"

**布局**：force 布局每次 setOption 重算 → 交互慢 + 一直动；改 **layout:'none' 手动圆周排布**（注意 x/y 是像素非百分比——曾挤左上角）+ 轮询去重（数据不变不重建）。

**服务圈控制**：公共/私有服务独立开关（都默认不亮）+ 私有服务筛选下拉（选中即高亮）。图例（graphic text）随开关出现——graphic 增量 setOption 不清旧元素，需 `replaceMerge: ['graphic']`。

## token 授权约束
只能授权给比自己权限低的角色：前端 eligibleUsers 过滤（体验）+ 后端 ROLE_RANK 校验（防抓包篡改 for_user）。

## 后果
- ✅ AI 多配置：profiles 唯一源 + 启动一致性 + 模型获取 + 左下角快捷切换
- ✅ 资产拓扑：物理机成簇 + 服务光晕 + 筛选 + 图例
- ✅ token 授权只能给低权限（前后端双重）
- ❌ k8s 容器侧 AI 切换仍需 configmap+Secret（profiles 只宿主机面板侧，注记）
- 📝 ECharts graphic 坐标系/合并策略是坑；登录前 API 401 需登录后重载

## 关联
- ADR-045（面板迁移）、决策 #43（网络适配蓝图——流量方向图待其落地）
