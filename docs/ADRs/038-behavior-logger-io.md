# ADR-038: BehaviorLogger buffered writer + 按天轮转

## 状态
Accepted (v0.4.4)

## 背景
压测（ADR-037）暴露 behavior_logger 每事件 `open('a')+write+close`（2 次 syscall/事件），50K ev/s 时 IO 排队成瓶颈。标注为可选优化，v0.4.4 落地。同时解决"行为日志按时间区分"的生产化需求。

## 验证过程
初版 flush_interval=2s → **10K+ ev/s 时丢 27%**（20K ev/s）：每 2s 大批量同步写（~4MB）阻塞 guard 事件循环，阻塞期 ringbuf 溢出。调 0.5s → **40K ev/s 0 丢失**，延迟 p50 52ms（与逐事件 open('a') 持平）。

**附带发现**：buffered 后文件被外部 `rm -f` 不重建（旧 inode 继续写，磁盘不可见）——`_maybe_rotate` 检查文件存在性重建。

## 备选方案
- **方案 A（选中）**：buffered writer + rename 轮转——活跃文件恒为 behaviors.log，跨天/超 50MB 改名 behaviors.YYYY-MM-DD.log。**读取侧零改动**（面板/压测读 behaviors.log 即最新）
- 方案 B：按天命名 behaviors.YYYY-MM-DD.log——读取侧要扫描合并多文件，改动大
- 方案 C：保持逐事件 open('a')——无 syscall 优化，且无按天区分

## 决策
采用方案 A：buffered writer（每 0.5s flush）+ 按天/大小轮转（rename）+ 保留 7 天自动清理 + guard 退出 flush。**flush 粒度 0.5s** 是正常负载（<100 ev/s）与极限（40K ev/s）的平衡点——flush 越稀单次写盘越大、阻塞越长。

## 后果
- ✅ 消除每事件 2 次 syscall；行为日志按天可追溯；磁盘有界（保留 7 天）
- ✅ 40K ev/s 0 丢失、延迟 p50 52ms（与逐事件 open('a') 持平）
- ❌ 崩溃丢数据窗口 ≤0.5s（审计主链 events.log 不丢，行为日志可接受）
- 📝 **flush 粒度与吞吐成反比**——批量写盘的阻塞时间随 flush 周期线性增长；压测度量需匹配 flush 周期（bench 排空 15s 防批次效应误报）

## 关联
- [ADR-037](037-performance-benchmark.md)：压测暴露的 IO 瓶颈，本决策为其优化落地
- [ADR-014](014-graded-automation.md)：行为日志是人工研判的证据链（按天可追溯增强取证）
