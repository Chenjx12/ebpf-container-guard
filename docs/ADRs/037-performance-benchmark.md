# ADR-037: 性能压测方法与 IO 瓶颈归因

## 状态
Accepted (v0.4.3)

## 背景
外部评估点名"CPU 开销 < 2% 但缺乏压测数据"——毕设实验验证章节需要可复现的基准。项目此前无任何性能统计代码。

## 验证过程
`tools/bench_openat.py` 注入 `os.open('/etc/shadow', O_RDONLY)`（500 events/s × 1000 次），统计：
- 丢失率：注入数 vs behaviors.log 匹配数（注入窗口内 openat + comm=python3 + 路径含 shadow）
- 延迟：匹配事件时间戳 - 注入窗口起点（含 guard poll 100ms 粒度）
- CPU：/proc/<guard本体PID>/stat utime+stime 差分

**压测暴露的坑**：guard 本体 PID 是 `sudo python3 -u main.py` 的子进程——用 sudo 包装进程的 PID 读 stat 拿到 0 CPU（包装进程不干活）。必须 `ps aux | grep main.py` 取后者。

## 备选方案
- 注入方式：openat('/etc/shadow')（内核态过滤后命中上报，最现实）vs mount 洪泛（干扰 docker0）——选 openat
- 对照组：behavior_log on/off——归因 IO vs 探针

## 决策
采用 bench_openat.py + 3 组取中位 + 对照组。结果：
- **丢失率 0%**（500 events/s，ringbuf 1MB 无溢出，10Hz poll 消费跟得上）
- **CPU 增量 ≈0%**（空闲 0.5% → 压测 0.3%，优于宣称 <2%）
- **延迟 p50≈1.67s 归因 behavior_log 每事件 `open('a')+write+close`**（对照组 behavior off 无此延迟）——非探针/ringbuf 问题

## 后果
- ✅ 毕设实验验证有可复现数据（docs/performance-report.md）；K8s 多节点后可对比
- ✅ 确认检测可靠性（零丢失）与资源占用（<1%）
- ❌ 延迟受 IO 影响——标注可选优化：BehaviorLogger 改 buffered writer + final flush（消除每事件 2 次 syscall，延迟预期降一个量级），不入本期
- 📝 延迟下限由 poll(100ms) 粒度决定，p50≈50-100ms 属预期，非 IO 归因

## 关联
- [ADR-036](036-systemd-deployment.md)：压测工具暴露的 PID 获取经验
- [ADR-014](014-graded-automation.md)：实时检测性能与分级响应的关系
