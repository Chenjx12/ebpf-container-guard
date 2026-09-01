# 贡献指南

感谢你对本项目的关注！本文档提供了参与贡献的指南。

[**English Version / 英文版**](CONTRIBUTING.md)

---

## 🎯 如何贡献

### 报告 Bug

在提交 Bug 报告之前，请先检查已有 Issues。Bug 报告应包含：

- **清晰的标题和描述**
- **复现步骤**
- **预期行为 vs 实际行为**
- **环境信息**（操作系统、内核版本、Python 版本）
- **截图或日志**（如适用）

**示例**：
```markdown
**Bug 描述**
容器冻结操作失败，提示权限拒绝错误。

**复现步骤**
1. 运行 `sudo python3 main.py`
2. 在容器中触发 procfs 挂载
3. 看到错误："Permission denied: /var/run/docker.sock"

**环境信息**
- OS: Ubuntu 22.04
- Kernel: 5.15.0-76-generic
- Docker: 24.0.5
```

### 功能建议

欢迎提出功能建议！请提供：

- **使用场景**：为什么需要这个功能？
- **建议方案**：应该如何实现？
- **已考虑的替代方案**：你考虑过的其他方法

### Pull Request 流程

1. **Fork** 本仓库
2. **创建分支**（`git checkout -b feature/amazing-feature`）
3. **编写代码**，保持清晰的 Commit Message
4. **充分测试**（运行集成测试）
5. **提交 PR**，附上详细说明

#### Commit Message 规范

```
feat: add execve syscall monitoring        # 新功能
fix: resolve cgroup_id mapping race condition  # 修复
docs: update deployment guide with K8s examples # 文档
test: add false positive rate test cases    # 测试
chore: update dependencies                 # 杂项
```

---

## 🛠️ 开发环境搭建

### 前置要求

- Ubuntu 22.04 LTS（kernel ≥ 5.15）
- Python 3.8+
- Docker 已安装并运行
- BCC 框架已安装

### 本地开发

```bash
# 克隆 Fork 后的仓库
git clone https://github.com/YOUR_USERNAME/ebpf-container-guard.git
cd ebpf-container-guard

# 安装依赖
pip install -r requirements.txt

# 详细模式调试运行
sudo python3 main.py --verbose

# 运行测试
bash tests/integration/test_escape_scenarios.sh
```

### 代码风格

- **Python**：遵循 PEP 8，尽量使用类型注解
- **C/eBPF**：命名风格一致，复杂逻辑添加注释
- **YAML**：2 空格缩进，键名有意义

---

## 📋 项目结构

```
ebpf-container-guard/
├── main.py                          # 主入口（管线编排）
├── src/
│   ├── core/                        # 基础设施
│   │   ├── identity.py              # 容器身份识别（三级回退 + 事件驱动刷新）
│   │   ├── event_log.py             # 结构化 JSON 事件日志（状态机）
│   │   ├── scope.py                 # 监控范围（include/exclude 容器）
│   │   ├── escalation.py            # 响应升级（重复攻击 → 镜像拉黑）
│   │   └── netblock.py              # 网络流量阻断（iptables DROP，可逆）
│   ├── ebpf/                        # eBPF 内核程序（.bpf.c，5 个 tracepoint）
│   ├── detector/                    # 检测管线（三层）
│   │   ├── engine.py                # Tier 1: YAML 规则引擎
│   │   ├── attack_matrix.py         # Tier 2: 行为→CVE 矩阵
│   │   └── ai_analyzer.py           # Tier 3: AI 研判（OpenAI 兼容）
│   └── responder/                   # 响应引擎（分级自动化）
│       └── docker_responder.py      # Docker 动作 + 人工判决队列
├── config/                          # YAML 配置文件
│   ├── rules.yaml                   # 12 条检测规则
│   ├── responses.yaml               # 严重度→动作策略
│   ├── monitor.yaml                 # 监控范围（include/exclude）
│   ├── blocklist.yaml               # 拉黑镜像（运行时状态，gitignored）
│   └── ai_config.yaml.example       # AI API 配置模板
├── deploy/                          # 部署资产
├── tests/                           # 集成测试和单元测试
├── demos/                           # 演示脚本
└── docs/                            # 文档（中英双语）
```

---

## 🧪 测试

### 运行测试

```bash
# 全部测试
bash tests/integration/test_escape_scenarios.sh

# 单个测试
bash tests/integration/test_procfs_mount.sh
```

### 编写测试

新功能应包含对应的测试：

```bash
#!/bin/bash
# tests/integration/test_your_feature.sh

echo "[TEST] 你的功能描述..."

# 测试步骤
# ...

if [ $? -eq 0 ]; then
    echo "✅ PASS"
else
    echo "❌ FAIL"
    exit 1
fi
```

---

## 📖 文档

添加功能时，请同步更新相关文档：

- **README.md**：面向用户的变更
- **docs/**：技术深度文档
- **代码注释**：复杂算法或 eBPF 逻辑

---

## 🔒 安全注意事项

- 不要提交 API 密钥或敏感凭据
- 使用 `.gitignore` 排除包含密钥的配置文件
- 通过邮件私下报告安全漏洞

---

## 🤝 社区

- **有问题？** 提 Issue 并添加 `question` 标签
- **讨论**：使用 GitHub Discussions 进行一般讨论
- **行为准则**：保持尊重和包容

---

## 📄 许可证

贡献即表示你同意将你的贡献以 Apache-2.0 许可证发布（v0.6.0 起；≤ v0.5.x 仍为 MIT）。
详见 [LICENSE](LICENSE)。

---

感谢你对 eBPF Container Guard 的贡献！🚀
