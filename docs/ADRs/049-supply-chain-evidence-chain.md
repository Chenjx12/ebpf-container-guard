# ADR-049: 供应链证据链（依赖层扫描 + 镜像 tag 对齐策略）

## 状态
Proposed (v0.6.2) — 发布验证通过后转 Accepted

## 背景
v0.6.1（ADR-048）已交付「镜像层 trivy 扫描 + SBOM + release 附件」。bp_v06x 的 v0.6.2
验收锚点是「**release 带 SBOM + 扫描报告；README 照做能起**」。仍有缺口：
- **依赖层无独立证据**：镜像层扫描覆盖镜像内文件（含 vendored `.so`），但 `requirements.txt` /
  `Dockerfile` / 源码层的漏洞（含 pip 依赖已修复版本）要仓库级 `trivy fs` 才现形
- **tag 对齐策略未成文**：决策 #49 定了「镜像 tag 对齐 git tag」的原则，但没有用户可读的
  策略文档——消费者不知道 `latest` 语义、演示/保底应拉哪个 tag、每次发版产物在哪

## 方案

### 依赖层扫描（release.yml）
- 新增 **trivy fs 扫描**（`scan-ref: .`，scanners `vuln,secret`）：
  - `skip-dirs: .git` —— CI checkout 会把凭据写进 `.git/config`，secret 扫描兜底防误报
  - 门槛与镜像层一致：severity `CRITICAL,HIGH` + `ignore-unfixed: true`，`exit-code: 1`
  - json 报告独立输出，作为 release 附件（`trivy-fs-report.<tag>.json`）
- 镜像层扫描（table 门槛 + json 报告）保持不变
- **附件三件套**：SBOM（cyclonedx）+ 镜像 trivy json + 依赖层 trivy json

### 镜像 tag 对齐策略（文档化，`docs/镜像发布策略.md` + `docs/image-tag-policy.md`）
- **GHCR tag = git tag 字符串**（带 `v` 前缀，二者严格一致）：`ghcr.io/chenjx12/ebpf-container-guard:v0.6.N`
- 每次 `v*` tag 推送触发 release.yml 构建同名字符串镜像 tag；`latest` 随最新 release 移动
- **演示/保底固定拉具体版本 tag**（v0.6.0 永远是回退安全网），不依赖 `latest`
- 镜像 tag 必须小写（Docker 约束）——GitHub 仓库名含大写（`Chenjx12`），CI 里用小写变换
- v0.6.1 已按此规则发布（`v0.6.1` 镜像存在且 manifest 可查），本文档把规则固定下来

### README（快速开始 3 步为验收锚点）
- 镜像启动步骤保持 3 步（pull → run → 看日志取初始密码开面板）
- 新增「供应链证据链」说明：每版 release 附 SBOM + 镜像扫描 + 依赖扫描，注明查看入口

## 后果
- ✅ 双证据链闭环：镜像层 + 依赖层各自门槛与报告，漏洞可追溯到具体层
- ✅ secret 扫描兜底：防止凭据误入库（本地开发也曾发生过 configmap 误含 AI key——决策 #42 教训）
- ✅ tag 对齐策略成文：消费者/面试官都能说清「tag 即版本、保底拉具体 tag」
- ❌ 每次发版多 2 个 trivy 步骤（fs 门槛 + fs json），CI 时长约 +1~2 分钟
- 📝 依赖层扫描结果可能因 trivy DB 版本波动——门槛只看 CRITICAL/HIGH + ignore-unfixed，
  与镜像层一致（v0.6.1 已按此口径清零）

## 关联
- ADR-048（全合一镜像）、决策 #48（release 纪律）、决策 #49（tag 对齐原则）、
  决策 #42（凭据红线）、bp_v06x.md（v0.6.2 验收锚点）