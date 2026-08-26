# 架构决策记录 (Architecture Decision Records)

本项目用 **ADR** 记录关键架构决策——"为什么代码长这样"。ADR 是 ThoughtWorks
技术雷达推荐的工程实践（AWS / Microsoft / Kubernetes KEP 均采用），每个决策
独立成篇，按决策序号编号（NNN = 内部决策记录序号），全局唯一稳定。

## 决策索引

| ADR | 标题 | 状态 | 版本 |
|-----|------|------|------|
| [000](000-adr-publication.md) | 将内部决策记录转为公开 ADR 文档 | Accepted | v0.4.1 |
| [003](003-probe-tracepoint.md) | 探针方案从 kprobe 回退到 tracepoint | Superseded by [033](033-libbpf-core.md) | v0.1.1 |
| [006](006-behavior-matrix.md) | 行为矩阵而非 CVE 签名 | Accepted | v0.2.0 |
| [014](014-graded-automation.md) | 分级自动化响应（可逆自动/不可逆人工） | Accepted | v0.2.5 |
| [024](024-xdp-ingress-limit.md) | XDP 网络阻断的 ingress 限制与混合后端 | Accepted | v0.3.9 |
| [032](032-rule-engine-conditions.md) | 规则引擎重构：Falco 风格条件树 | Accepted | v0.4.0 |
| [033](033-libbpf-core.md) | BCC → libbpf CO-RE 迁移 | Accepted | v0.4.1 |
| [036](036-systemd-deployment.md) | systemd 部署形态与干净退出 | Accepted | v0.4.3 |
| [037](037-performance-benchmark.md) | 性能压测方法与 IO 瓶颈归因 | Accepted | v0.4.3 |
| [038](038-behavior-logger-io.md) | BehaviorLogger buffered writer + 按天轮转 | Accepted | v0.4.4 |
| [039](039-single-instance-lock.md) | 单实例锁（部署形态互斥基础） | Accepted | v0.5.0 |
| [040](040-k8s-runtime-backend.md) | K8s 适配：RuntimeBackend 双轨抽象 | Accepted | v0.5.1 |
| [041](041-k8s-responder.md) | K8s responder：动作映射与降级 | Accepted | v0.5.2 |
| [042](042-daemonset-deployment.md) | DaemonSet 容器化部署（in_cluster + 降级） | Accepted | v0.5.3 |
| [043](043-nsenter-netblock.md) | 网络阻断补全（nsenter 宿主 iptables + 适配蓝图） | Accepted | v0.5.4 |
| [044](044-k8s-e2e-scripted.md) | K8s E2E 全量脚本化与六重 bug 修复 | Accepted | v0.5.5 |
| [045](045-panel-fastapi-vue3.md) | 面板迁移：Streamlit → FastAPI + Vue3 | Accepted | v0.5.6 |
| [046](046-ai-profiles-assets-topo.md) | AI 多配置管理 + 资产拓扑图 | Accepted | v0.5.7 |
| [047](047-attack-chain-analysis.md) | 攻击链分析页面（阶段聚合 + 流程图） | Accepted | v0.5.8 |

## 格式

每篇 ADR 遵循标准结构（Nygard 格式的实践变体）：

```
状态 → 背景 → 验证过程 → 备选方案 → 决策 → 后果 → 关联
```

- **状态**：Accepted / Superseded（被后续决策取代，如 ADR-003 → ADR-033）
- **后果**：✅ 好处 / ❌ 代价 / 📝 教训
- **关联**：ADR 互链（决策间的演进关系）

## 编号体系

- ADR-000：本目录的自举决策（关于决策的决策）
- ADR-001~033：对应内部决策记录 #1~33
- ADR-034~037：预留（文档双语 / GitHub Releases / OpenAI 兼容接口 / 隐私与工具痕迹）——036/037 已被 systemd/压测决策占用
- ADR-038+：将来新增决策

其余决策（#1/#2/#4/#5/#7~#13/#15~#23/#25~#31）保留在**内部决策记录**
（本地文档，含隐私信息不上传），将按批次迁移到本目录。
