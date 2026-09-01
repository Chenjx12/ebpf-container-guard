# eBPF Container Guard — 全合一镜像 (v0.6.1, ADR-048)
# 单容器交付 guard 检测引擎 + FastAPI/Vue3 面板（首个 GHCR 供应链镜像）。
# 构建: docker build -f deploy/Dockerfile -t ghcr.io/chenjx12/ebpf-container-guard:v0.6.1 .
# 运行: 见 README「快速开始（镜像版）」3 步（特权参数是必需的，不是可选项）。
#
# 与 deploy/Dockerfile.guard（v0.5.3 DaemonSet guard-only 变体）并存：
#   - 本文件 = 全合一（v0.6.1 验收形态：docker 单机，pull 后 3 步起面板）
#   - Dockerfile.guard = DaemonSet 变体保留不删（镜像名切 GHCR 留后续版本）

FROM python:3.10-slim

# libbpf.so.1 动态依赖: libz 自带, libelf 从 deploy/libbpf COPY (apt 网络受限)
COPY deploy/libbpf/libelf.so.1.0.0 /usr/lib/x86_64-linux-gnu/libelf.so.1.0.0
RUN ln -sf /usr/lib/x86_64-linux-gnu/libelf.so.1.0.0 \
    /usr/lib/x86_64-linux-gnu/libelf.so.1

# tzdata — 事件时间戳用本地时区 (TZ env 需 zoneinfo, 否则容器 UTC 偏差 8h)
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# 运行时依赖（v0.6.1 起锁定版本；面板与 guard 同镜像，见 requirements.txt）
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# libbpf.so.1 (1.8.0, 版本化符号 ctypes 自动解析)
COPY deploy/libbpf/libbpf.so.1.8.0 /usr/lib/x86_64-linux-gnu/libbpf.so.1.8.0
RUN ln -sf /usr/lib/x86_64-linux-gnu/libbpf.so.1.8.0 \
    /usr/lib/x86_64-linux-gnu/libbpf.so.1

WORKDIR /app

# 代码（server 依赖 src 的 rule_schema/kube_utils, deps 依赖 dashboard.auth）
COPY main.py ./
COPY deploy/entrypoint.sh ./entrypoint.sh
COPY src/ src/
COPY server/ server/
COPY dashboard/ dashboard/
COPY config/ config/

# 预编译 CO-RE 探针
COPY .build/escape-detect.bpf.o .build/xdp-block.bpf.o .build/

# 单实例锁目录（容器内可写）+ 日志目录（hostPath 挂载）
RUN chmod +x entrypoint.sh && mkdir -p /var/run /app/logs

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]