# Contributing to eBPF Container Guard

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

[**中文版 / Chinese Version**](CONTRIBUTING_CN.md)

## 🎯 How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the behavior
- **Expected vs actual behavior**
- **Environment details** (OS, kernel version, Python version)
- **Screenshots or logs** if applicable

**Example:**
```markdown
**Describe the bug**
Container pause action fails with permission denied error.

**To Reproduce**
1. Run `sudo python3 main.py`
2. Trigger procfs mount in container
3. See error: "Permission denied: /var/run/docker.sock"

**Environment**
- OS: Ubuntu 22.04
- Kernel: 5.15.0-76-generic
- Docker: 24.0.5
```

### Suggesting Features

Feature suggestions are welcome! Please provide:

- **Use case**: Why is this feature needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches you've thought about

### Pull Requests

1. **Fork** the repository
2. **Create a branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** with clear commit messages
4. **Test thoroughly** (run integration tests)
5. **Submit a PR** with detailed description

#### Commit Message Guidelines

```
feat: add execve syscall monitoring
fix: resolve cgroup_id mapping race condition
docs: update deployment guide with K8s examples
test: add false positive rate test cases
```

## 🛠️ Development Setup

### Prerequisites

- Ubuntu 22.04 LTS (kernel ≥ 5.15)
- Python 3.8+
- Docker installed and running
- BCC framework installed

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ebpf-container-guard.git
cd ebpf-container-guard

# Install dependencies
pip install -r requirements.txt

# Run in verbose mode for debugging
sudo python3 main.py --verbose

# Run tests
bash tests/integration/test_escape_scenarios.sh
```

### Code Style

- **Python**: Follow PEP 8, use type hints where possible
- **C/eBPF**: Use consistent naming, add comments for complex logic
- **YAML**: 2-space indentation, meaningful key names

## 📋 Project Structure

```
ebpf-container-guard/
├── main.py                          # Entry point (pipeline orchestration)
├── src/
│   ├── core/                        # Infrastructure
│   │   ├── identity.py              # Container identity (3-tier fallback + event-driven refresh)
│   │   ├── event_log.py             # Structured JSON event logger (state machine)
│   │   ├── scope.py                 # Monitoring scope (include/exclude containers)
│   │   ├── escalation.py            # Response escalation (repeated attacks → blocklist)
│   │   └── netblock.py              # Network traffic blocking (iptables DROP, reversible)
│   ├── ebpf/                        # eBPF kernel programs (.bpf.c, 5 tracepoints)
│   ├── detector/                    # Detection pipeline (3-tier)
│   │   ├── engine.py                # Tier 1: YAML rule engine
│   │   ├── attack_matrix.py         # Tier 2: behavior→CVE matrix
│   │   └── ai_analyzer.py           # Tier 3: AI judge (OpenAI-compatible)
│   └── responder/                   # Response engine (graded automation)
│       └── docker_responder.py      # Docker actions + human review queue
├── config/                          # YAML configuration files
│   ├── rules.yaml                   # 12 detection rules
│   ├── responses.yaml               # Severity→action policy
│   ├── monitor.yaml                 # Monitoring scope (include/exclude)
│   ├── blocklist.yaml               # Blocked images (runtime state, gitignored)
│   └── ai_config.yaml.example       # AI API config template
├── deploy/                          # Deployment assets
├── tests/                           # Integration and unit tests
├── demos/                           # Demo scripts
└── docs/                            # Documentation (bilingual)
```

## 🧪 Testing

### Running Tests

```bash
# All tests
bash tests/integration/test_escape_scenarios.sh

# Specific test
bash tests/integration/test_procfs_mount.sh
```

### Writing Tests

New features should include corresponding tests:

```bash
#!/bin/bash
# tests/integration/test_your_feature.sh

echo "[TEST] Your feature description..."

# Test steps
# ...

if [ $? -eq 0 ]; then
    echo "✅ PASS"
else
    echo "❌ FAIL"
    exit 1
fi
```

## 📖 Documentation

When adding features, update relevant documentation:

- **README.md**: User-facing changes
- **docs/**: Technical deep dives
- **Code comments**: Complex algorithms or eBPF logic

## 🔒 Security Considerations

- Never commit API keys or sensitive credentials
- Use `.gitignore` for config files with secrets
- Report security vulnerabilities privately via email

## 🤝 Community

- **Questions?** Open an issue with label `question`
- **Discussions**: Use GitHub Discussions for general topics
- **Code of Conduct**: Be respectful and inclusive

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to eBPF Container Guard! 🚀
