#!/usr/bin/env python3
"""bench_openat.py — 性能压测 (v0.4.3)

注入 openat 敏感路径事件 (cat /etc/shadow 等价), 统计:
  1. 丢失率: 注入 N vs behaviors.log 匹配事件数 (openat+comm=bench_openat+shadow)
  2. 延迟:   behaviors.log 毫秒时间戳 - 注入 monotonic → p50/p95/max
  3. CPU:    /proc/<pid>/stat utime+stime 差分 → guard 核占用

对照组: --no-behavior (behavior_log 关) 归因 IO vs 探针。

用法 (sudo):
  python3 tools/bench_openat.py --count 2000 --rate 500 --pid <guard_pid>
  python3 tools/bench_openat.py --count 2000 --rate 500 --pid <guard_pid> --no-behavior
"""
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEHAVIORS_LOG = ROOT / "behaviors.log"


def read_cpu_ticks(pid):
    """读取进程 CPU 时间 (utime+stime, 单位 clock ticks)"""
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
            return int(parts[13]) + int(parts[14])  # utime + stime
    except Exception:
        return None


def sample_cpu(pid, duration, interval=0.5):
    """采样 guard CPU 占用, 返回 [(t, cpu%)]"""
    ticks_per_sec = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
    samples = []
    t0 = time.time()
    prev_ticks, prev_t = read_cpu_ticks(pid), t0
    while time.time() - t0 < duration:
        time.sleep(interval)
        cur_ticks, cur_t = read_cpu_ticks(pid), time.time()
        if prev_ticks is not None and cur_ticks is not None:
            delta = cur_ticks - prev_ticks
            elapsed = cur_t - prev_t
            cpu = (delta / ticks_per_sec / elapsed) * 100.0
            samples.append((cur_t - t0, cpu))
        prev_ticks, prev_t = cur_ticks, cur_t
    return samples


def parse_behaviors():
    """解析 behaviors.log → [(ts_ms, event_type, comm, path)]"""
    events = []
    if not BEHAVIORS_LOG.exists():
        return events
    with open(BEHAVIORS_LOG) as f:
        for line in f:
            try:
                d = json.loads(line)
            except Exception:
                continue
            ts = d.get('timestamp')  # "2026-08-14T11:20:00.123" ISO 毫秒
            events.append((ts, d.get('event_type'), d.get('comm'),
                           d.get('target_path', '')))
    return events


def ts_to_ms(ts):
    """ISO 时间戳 → 毫秒 (epoch)"""
    if not ts:
        return 0
    try:
        dt = time.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S')
        ms = int(ts[20:23]) if len(ts) > 20 and ts[19] == '.' else 0
        return int(time.mktime(dt) * 1000) + ms
    except Exception:
        return 0


def percentile(values, p):
    if not values:
        return 0
    values = sorted(values)
    idx = int(len(values) * p / 100)
    return values[min(idx, len(values) - 1)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--count', type=int, default=2000)
    ap.add_argument('--rate', type=int, default=500, help='注入速率 (events/s)')
    ap.add_argument('--pid', type=int, required=True, help='guard 进程 PID')
    ap.add_argument('--no-behavior', action='store_true',
                    help='对照组: behavior_log 关闭')
    args = ap.parse_args()

    print(f"=== bench_openat: count={args.count} rate={args.rate}/s "
          f"pid={args.pid} behavior_log={'off' if args.no_behavior else 'on'} ===")

    # 阶段 0: 空闲 CPU 基线 10s
    print("[阶段0] 空闲 CPU 基线 10s ...")
    idle = sample_cpu(args.pid, 10)
    idle_cpu = sum(c for _, c in idle) / len(idle) if idle else 0

    # 阶段 1: 注入
    print(f"[阶段1] 注入 {args.count} 次 openat('/etc/shadow') @ {args.rate}/s ...")
    inject_ts = []  # monotonic 注入时间
    inject_start_mono = time.monotonic()
    inject_start_wall = time.time()
    interval = 1.0 / args.rate
    for i in range(args.count):
        t0 = time.monotonic()
        try:
            fd = os.open('/etc/shadow', os.O_RDONLY)
            os.close(fd)
        except OSError:
            pass
        inject_ts.append(t0)
        # 限速 (除首事件)
        if i < args.count - 1:
            wait = interval - (time.monotonic() - t0)
            if wait > 0:
                time.sleep(wait)
    inject_end_mono = time.monotonic()
    inject_end_wall = time.time()
    # 注入窗口 [start_wall-0.5s, end_wall+1s] — 过滤窗口外干扰事件
    win_start = inject_start_wall - 0.5
    win_end = inject_end_wall + 1.0

    # 阶段 2: 排空 3s (guard 10Hz poll 余量)
    print("[阶段2] 排空 3s ...")
    time.sleep(3)
    cpu_samples = sample_cpu(args.pid, 3)
    load_cpu = sum(c for _, c in cpu_samples) / len(cpu_samples) if cpu_samples else 0

    # 阶段 3: 分析
    events = parse_behaviors()
    # 匹配: 注入窗口内 + openat + comm=python3 + /etc/shadow
    matched = [e for e in events
               if e[1] == 'openat' and e[2] == 'python3'
               and e[3].endswith('shadow')
               and win_start * 1000 <= ts_to_ms(e[0]) <= win_end * 1000]
    # 注: 若 no_behavior, behaviors.log 无事件 → 丢失率按 0 匹配算
    lost = max(0, args.count - len(matched))

    # 延迟: 匹配事件时间 - 注入窗口起点 (注入是 0.5s 内密集, 近似端到端延迟)
    delays = [ts_to_ms(m[0]) - int(win_start * 1000) for m in matched]

    print("\n=== 结果 ===")
    print(f"注入: {args.count} | 匹配: {len(matched)} | 丢失: {lost} "
          f"({lost/args.count*100:.1f}%)")
    if delays:
        print(f"延迟: p50={percentile(delays,50)}ms "
              f"p95={percentile(delays,95)}ms max={max(delays)}ms")
    print(f"CPU: 空闲 {idle_cpu:.1f}% | 压测 {load_cpu:.1f}% "
          f"| 增量 {load_cpu - idle_cpu:.1f}%")

    # 输出 JSON (可重复采集)
    result = {
        'count': args.count, 'rate': args.rate, 'pid': args.pid,
        'behavior_log': not args.no_behavior,
        'lost': lost, 'loss_rate': round(lost / args.count * 100, 2),
        'delay_p50_ms': percentile(delays, 50) if delays else None,
        'delay_p95_ms': percentile(delays, 95) if delays else None,
        'delay_max_ms': max(delays) if delays else None,
        'cpu_idle': round(idle_cpu, 2), 'cpu_load': round(load_cpu, 2),
        'cpu_delta': round(load_cpu - idle_cpu, 2),
    }
    print("\nJSON:", json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
