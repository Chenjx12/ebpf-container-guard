# eBPF Container Guard — 全合一镜像 (v0.6.1, ADR-048)
# 单容器交付 guard 检测引擎 + FastAPI/Vue3 面板（首个 GHCR 供应链镜像）。
# 构建: docker build -f deploy/Dockerfile -t ghcr.io/chenjx12/ebpf-container-guard:v0.6.1 .
# 运行: 见 README「快速开始（镜像版）」3 步（特权参数是必需的，不是可选项）。
#
# 与 deploy/Dockerfile.guard（v0.5.3 DaemonSet guard-only 变体）并存：
#   - 本文件 = 全合一（v0.6.1 验收形态：docker 单机，pull 后 3 步起面板）
#   - Dockerfile.guard = DaemonSet 变体保留不删（镜像名切 GHCR 留后续版本）

FROM python:3.10-slim

# APT_MIRROR — 允许本地构建切换 apt 源 (CI 保持默认 deb.debian.org,
# 供应链扫描/发布行为不受影响; 本地网络 DNS 抖动时用镜像源加速稳定:
# docker build --build-arg APT_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian)
ARG APT_MIRROR=http://deb.debian.org/debian
ARG APT_MIRROR_SECURITY=http://deb.debian.org/debian-security

# libbpf.so.1 动态依赖: libz 自带, libelf 从 deploy/libbpf COPY (apt 网络受限)
COPY deploy/libbpf/libelf.so.1.0.0 /usr/lib/x86_64-linux-gnu/libelf.so.1.0.0
RUN ln -sf /usr/lib/x86_64-linux-gnu/libelf.so.1.0.0 \
    /usr/lib/x86_64-linux-gnu/libelf.so.1

# tzdata — 事件时间戳用本地时区 (TZ env 需 zoneinfo, 否则容器 UTC 偏差 8h)
# iptables — v0.6.3 顺风车 1 (ADR-050): docker 单机形态的 netblock 是
#   NetBlocker → 容器内直接执行 iptables 操作宿主 FORWARD 链 (privileged +
#   hostNetwork 共享 netns)。slim 基础镜像无 iptables 二进制, 此前缺装导致
#   block() 抛 FileNotFoundError 杀死整个事件管线 (攻击矩阵打印后事件丢失) —
#   已实测确认并在此修复 (顺带: 重放 replay() 也依赖该二进制)。
# 注: base python:3.10-slim 是 Debian trixie, sources 为 deb822 格式
#   (/etc/apt/sources.list.d/debian.sources), URIs 行无尾斜杠 —
#   用行尾锚定的行替换精确切换主源与安全源。
RUN if [ "$APT_MIRROR" != "http://deb.debian.org/debian" ]; then \
        sed -i "s|^URIs: http://deb\.debian\.org/debian$|URIs: ${APT_MIRROR}|; \
                s|^URIs: http://deb\.debian\.org/debian-security$|URIs: ${APT_MIRROR_SECURITY}|" \
            /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        tzdata \
        iptables \
    && rm -rf /var/lib/apt/lists/*

# 运行时依赖（v0.6.1 起锁定版本；面板与 guard 同镜像，见 requirements.txt）
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# v0.6.1 CI 供应链门槛修复: trivy 扫出 2 个 HIGH，根因是 base python:3.10-slim
# 自带 setuptools 的 _vendor/ 内嵌副本 (jaraco.context 5.3.0 / wheel 0.45.1)。
# 已实测: 升级独立包无效 — 必须升级 setuptools 本体，_vendor 整体换新到修复版。
# (wheel 独立包 base 已自带 0.46.3 ≥ fix 0.46.2, 无需再动)
RUN pip install --no-cache-dir --upgrade setuptools==84.0.0 jaraco.context==6.1.0

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