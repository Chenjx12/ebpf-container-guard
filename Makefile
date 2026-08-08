.PHONY: help build test run clean deploy logs

help: ## Show this help message
	@echo "eBPF Container Guard - Makefile Commands"
	@echo ""
	@echo "Usage: make [command]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build eBPF program (requires clang and libbpf)
	@echo "🔨 Building eBPF program..."
	cd src/ebpf && \
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
		-I/usr/include/x86_64-linux-gnu \
		-c escape-detect.bpf.c -o escape-detect.bpf.o
	@echo "✅ Build complete: src/ebpf/escape-detect.bpf.o"

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
