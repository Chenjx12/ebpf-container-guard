.PHONY: help build test run clean deploy logs panel

panel: ## Start security panel (FastAPI + Vue3, v0.5.6)
	@echo "🖥️  Starting security panel (FastAPI + Vue3)..."
	python3 -m uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 1

# v0.4.1: CO-RE 构建链 — vmlinux.h 不入库 (内核版本相关), 生成到 .build/
BPF_ARCH = x86   # bpf_tracing.h 用 __TARGET_ARCH_x86 代表 x86-64
CLANG_FLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	-I/usr/include/x86_64-linux-gnu -I.build

help: ## Show this help message
	@echo "eBPF Container Guard - Makefile Commands"
	@echo ""
	@echo "Usage: make [command]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.build/vmlinux.h: ## Generate vmlinux.h from kernel BTF (CO-RE 必需)
	@mkdir -p .build
	@echo "🔨 Generating vmlinux.h from /sys/kernel/btf/vmlinux..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > .build/vmlinux.h
	@grep -q "trace_event_raw_sys_enter" .build/vmlinux.h || \
		(echo "❌ vmlinux.h 缺少 trace_event_raw_sys_enter, 中止"; exit 1)
	@echo "✅ vmlinux.h generated ($(shell wc -c < .build/vmlinux.h) bytes)"

.build/escape-detect.bpf.o: src/ebpf/escape-detect.bpf.c .build/vmlinux.h
	@echo "🔨 Compiling escape-detect.bpf.c (CO-RE)..."
	@clang $(CLANG_FLAGS) -c src/ebpf/escape-detect.bpf.c -o $@
	@echo "✅ escape-detect.bpf.o"

.build/xdp-block.bpf.o: src/ebpf/xdp-block.bpf.c .build/vmlinux.h
	@echo "🔨 Compiling xdp-block.bpf.c (CO-RE)..."
	@clang $(CLANG_FLAGS) -c src/ebpf/xdp-block.bpf.c -o $@
	@echo "✅ xdp-block.bpf.o"

build: .build/escape-detect.bpf.o .build/xdp-block.bpf.o ## Build eBPF programs (CO-RE)
	@readelf -S .build/escape-detect.bpf.o | grep -q "\.BTF" && \
		echo "✅ .BTF 段确认: CO-RE 对象完整"

test: ## Run integration tests
	@echo "🧪 Running integration tests..."
	bash tests/integration/test_escape_scenarios.sh

run: ## Start eBPF Container Guard (requires sudo)
	@echo "🛡️  Starting eBPF Container Guard..."
	sudo python3 main.py --verbose

run-quiet: ## Start in quiet mode (production)
	@echo "🛡️  Starting eBPF Container Guard (quiet mode)..."
	sudo python3 main.py

deploy: ## Deploy to Docker (coming in v0.2.0)
	@echo "🐳 Building Docker image..."
	docker build -t ebpf-container-guard:latest .
	@echo "✅ Docker image built"

logs: ## View container logs
	@echo "📋 Viewing logs..."
	docker logs -f ebpf-guard

clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	rm -rf .build
	find . -name "*.o" -type f -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -type f -delete
	@echo "✅ Clean complete"

install-deps: ## Install Python dependencies
	@echo "📦 Installing dependencies..."
	pip install -r requirements.txt
	@echo "✅ Dependencies installed"

lint: ## Run Python linter
	@echo "🔍 Running linter..."
	python3 -m flake8 src/ --max-line-length=100 || echo "⚠️  Linting issues found"

format: ## Format Python code
	@echo "✨ Formatting code..."
	python3 -m black src/ || echo "⚠️  Black not installed"
