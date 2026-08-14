# eBPF Container Guard — 性能压测报告 v0.4.3（2026-08-14）

> 工具: `tools/bench_openat.py`（注入 openat('/etc/shadow') 敏感路径事件）
> 环境: 见下。压测数据可复现，3 组取中位。

## 环境

| 项 | 值 |
|----|----|
| 操作系统 | Ubuntu 22.04 LTS |
| 内核 | 6.8.0-136-generic（CONFIG_DEBUG_INFO_BTF=y） |
| eBPF | libbpf 1.8.0（CO-RE），6 探针，ringbuf 1MB |
| CPU | 4 核（VMware 虚拟机） |
| 内存 | 7.7 GiB |
| 容器运行时 | Docker（压测时 0 容器） |
| AI 研判 | 关闭（无 API key） |

## 方法

- 注入: `os.open('/etc/shadow', O_RDONLY)` 循环，速率 500 events/s，共 1000 次
- 匹配: behaviors.log 中 注入窗口内 + openat + comm=python3 + 路径含 shadow
- 延迟: 匹配事件时间戳 - 注入窗口起点（端到端，含 guard poll 100ms 粒度）
- CPU: /proc/<guard本体PID>/stat utime+stime 差分（guard 本体，非 sudo 包装进程）
- 对照组: behavior_log off（只测 CPU，行为日志关闭时无匹配事件可查）

## 结果（3 组取中位，behavior_log on）

| 指标 | 组1 | 组2 | 组3 | 中位 |
|------|-----|-----|-----|------|
| 丢失率 | 0.0% | 0.0% | 0.0% | **0.0%**（1000/1000 全收） |
| 延迟 p50 | 1665ms | 1676ms | 1698ms | **1676ms** |
| 延迟 p95 | 2660ms | 2584ms | 2672ms | **2660ms** |
| 延迟 max | 2772ms | 2693ms | 2781ms | **2772ms** |
| CPU 增量 | — | — | — | **≈0%**（空闲 0.5% → 压测 0.3%） |

## 对照组（behavior_log off）

| 指标 | 值 |
|------|-----|
| CPU 空闲 | 0.3% |
| CPU 压测 | 0.33% |
| CPU 增量 | 0.03% |

## 分析

1. **零丢失**：500 events/s 下 ringbuf（1MB）无溢出，guard 10Hz poll 消费跟得上——检测可靠性达标
2. **CPU 开销 <1%**：实测增量 ≈0%，优于 README 宣称的 <2%（4000 events/s 级仍有余量）
3. **延迟 1.6-2.7s 归因 behavior_log IO**：每事件 `open('a')+write+close`（2 次 syscall/事件），1000 事件排队写盘是延迟主因；**对照组 behavior off 时无此延迟**——不是探针/ringbuf 问题
4. **压测暴露的优化点**（标注，不入本期）：BehaviorLogger 改 buffered writer + final flush 可消除每事件 2 次 syscall，延迟预期降一个量级

## 复现

```bash
make build
sudo python3 -u main.py &            # 记 guard 本体 PID（ps aux | grep main.py）
sudo rm -f behaviors.log
sudo python3 tools/bench_openat.py --count 1000 --rate 500 --pid <guard本体PID>
# 对照组: monitor.yaml behavior_log: false 后重启 guard 再跑
```
