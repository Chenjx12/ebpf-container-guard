# eBPF Container Guard — 性能压测报告 v0.4.3（2026-08-14，数据修正版）

> 工具: `tools/bench_openat.py` v2（逐事件配对延迟 + 阶梯模式）
> 方法论修正：v0.4.3 初版延迟用"落盘时间 − 注入窗口起点"是度量假象（注入分布污染），
> 本版改为**逐事件配对**（behaviors.log 按序 = 注入按序），延迟为真实端到端值。

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

- 注入: `os.open('/etc/shadow', O_RDONLY)` 循环，速率可控
- **逐事件配对延迟**: 注入时记每事件 wall 时间戳，behaviors.log 中同 comm(openat)+同路径 按序配对——延迟 = 落盘时间 − 对应注入时间
- 丢失率: 注入 N vs 窗口内匹配数
- CPU: /proc/<guard本体PID>/stat utime+stime 差分（guard 本体，非 sudo 包装进程）
- 阶梯: 1K→3K→5K→8K→10K 每档落盘（后补测 15K/25K/40K/50K 找极限）

## 结果

### 丢失率与延迟（逐事件配对）

| 速率 (ev/s) | 注入 | 丢失率 | 延迟 p50 | p95 | max |
|-------------|------|--------|----------|-----|-----|
| 2000 | 1000 | 0% | 58ms | 96ms | 101ms |
| 2000 | 3000 | 0% | 52ms | 96ms | 101ms |
| 2500 | 5000 | 0% | 54ms | 96ms | 102ms |
| 4000 | 8000 | 0% | 56ms | 98ms | 104ms |
| 5000 | 10000 | 0% | 58ms | 113ms | 144ms |
| 7500 | 15000 | 0% | 55ms | 99ms | 110ms |
| 12500 | 25000 | 0% | 53ms | 102ms | 124ms |
| 20000 | 40000 | **0%** | 53ms | 101ms | 119ms |
| 25000 | 50000 | **0.09%** (45/50000) | 62ms | 106ms | 118ms |

### CPU 占用

| 速率 | CPU 增量 |
|------|----------|
| 空闲基线 | 0.3-0.5% |
| 全部档位 | -1.2% ~ +0.7%（**噪声范围内，<1%**） |

## 分析

1. **零丢失至 40K ev/s**：ringbuf 1MB 消费跟得上——guard 每 poll(100ms) 可排空 1MB（约 2400 条），注入 20K/s 时 100ms 窗口 2000 条 < 上限
2. **真实丢包阈值 ≈50K ev/s**（0.09%）——远超 README 宣称场景（容器逃逸事件实际 <100/s）
3. **真实延迟 52-58ms**（p50）：由 poll(100ms) 粒度主导，符合预期——**v0.4.3 初版 1.67s 是度量假象**（注入分布污染）
4. **CPU 增量 <1%（噪声内）**：guard 热路径（ctypes 解析 + 字典匹配）开销极低；初版"≈0%"结论成立但数据是噪声——真实信号在高速率下仍未超过噪声（证明开销确实小）
5. **behavior_log IO 影响**：p95 96-113ms 与 0.09% 丢失在 50K 时出现——IO 排队在极高速率才成为瓶颈；正常场景无感

## 局限

- 4 核自压测：注入进程与 guard 抢 CPU，噪声 ±1%（报告注明）
- 延迟含 poll 粒度下限（50-100ms），非探针本身延迟（探针微秒级）
- CPU 采样 0.5s 间隔，瞬时尖峰可能漏采

## 复现

```bash
make build
sudo python3 -u main.py &            # 记 guard 本体 PID（ps aux | grep main.py 取 python3 行）
sudo rm -f behaviors.log
sudo python3 tools/bench_openat.py --pid <guard本体PID> --ladder
# 单档: sudo python3 tools/bench_openat.py --pid <PID> --count 40000 --rate 20000
```
