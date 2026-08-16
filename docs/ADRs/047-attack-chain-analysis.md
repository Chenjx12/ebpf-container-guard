# ADR-047: 攻击链分析——行为时间窗阶段聚合 + 流程图

## 状态
Accepted (v0.5.8)

## 背景
系统已能检测告警（events.log）+ 记录全量行为（behaviors.log），但"检测到攻击后能还原攻击过程吗"没有答案。用户要求：单独页面以**方框箭头流程图**展示攻击链（kill chain 视角），从告警跳转。

## 方案

### 后端：`GET /api/attack-chain`（阶段聚合启发式）
- 输入：container（必填）+ ts（可选）。ts 不传时取该容器**最近告警**为锚点——**容器全周期**：同容器多次告警合并成一条链（用户确认）
- 时间窗：`[最近告警 - window(600s), 最近告警]`——往前追溯攻击前置步骤
- **阶段启发式**（事件类型→阶段映射，按优先级）：窃取数据（openat shadow/kcore）→ 外联 C2（connect）→ 利用执行（execve sh/工具）→ 提权逃逸（mount/capset/ptrace）→ 侦查探测（openat /etc /proc）
- **系统 comm 噪声过滤**：runc/containerd/k3s-server/pause 等排除（容器启动噪声曾污染阶段）
- 同阶段连续事件合并为一步；事件同 comm+target 去重计数（×N）
- **跨轮转文件**：行为按天轮转（behaviors.log.YYYY-MM-DD），攻击链查询可能跨天——新增 `load_behavior_rotated` 读当前+最近 7 个轮转文件

### 前端：AttackChainPage（方框箭头流程图）
- ECharts graph：`symbol: 'rect'` 长条矩形 + 箭头边；阶段着色（柔和深色系）；多行 label（阶段/相对秒/关键命令）
- 点击方框 → ElMessageBox 事件详情；悬停 tooltip 预览
- 完整性说明（"仅展示最近 10 分钟行为"）；阶段 >5 时方框自适应变窄
- 告警详情弹窗「查看完整攻击链」按钮 → 自动关弹窗 → `#/chain?container=...`
- 顶部被攻击目标画像（复用 review/profile）

## 踩坑
- **ECharts graph 的 label 不随 roam 缩放**：`label.scale` 实测无效（白字像素 maxrow 553→553 不变）——攻击链回退 `roam: 'move'`（只拖不缩）；资产拓扑保留缩放（节点短名，割裂感小）
- **轮转文件读取**：`_read_jsonl` 需接受 str 路径（glob 返回 str）；attack-chain 需全量读（tail 窗口截断可能漏攻击时刻）
- **时间戳**：behaviors 时间戳是本地（guard TZ=Asia/Shanghai），k8s API 的 creation_timestamp 是 UTC（需 +00:00 标记转本地）

## 后果
- ✅ 攻击链完整还原：告警 → 阶段流程图（侦查→提权→利用→C2→窃取）
- ✅ 同容器多次告警合并成一条链 + 告警标记
- ✅ 事件去重/完整性说明/自适应防溢出
- ❌ 滚轮缩放不可用（label 不跟随，只拖）
- 📝 阶段启发式是简单规则版，后续可升级为规则驱动/LLM 增强

## 关联
- ADR-046（AI 多配置+资产拓扑）、决策 #43（网络适配蓝图）
- 答辩故事："检测 → 攻击链还原 → 响应"完整闭环
