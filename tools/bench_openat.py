#!/usr/bin/env python3
"""bench_openat.py — 性能压测 v2 (v0.4.3 数据可信化)

注入 openat('/etc/shadow') 敏感路径事件, 统计:
  1. 丢失率: 注入 N vs behaviors.log 匹配事件数 (逐事件配对)
  2. 延迟:   逐事件配对 — 落盘时间戳 - 对应注入时间 (修正 1.67s 度量假象)
  3. CPU:    /proc/<pid>/stat utime+stime 差分 (guard 本体 PID!)

阶梯模式: --ladder 1K→3K→5K→8K→10K, 每档先落盘 JSON 再升下一档
  (即使下一档崩溃, 已测档位数据保住)

资源限定: ulimit -v / -n 限注入进程 (单进程资源耗尽只崩自己, 不碰系统)

用法 (sudo):
  sudo python3 tools/bench_openat.py --pid <guard本体PID> --ladder
  sudo python3 tools/bench_openat.py --pid <guard本体PID> --count 3000 --rate 2000
"""
import argparse
import json
import os
import resource
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEHAVIORS_LOG = ROOT / "behaviors.log"
LADDER = [1000, 3000, 5000, 8000, 10000]
RESULTS_PATH = Path("/tmp/bench_ladder.json")


def read_cpu_ticks(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
            return int(parts[13]) + int(parts[14])
    except Exception:
        return None


def sample_cpu(pid, duration, interval=0.5):
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
    """解析 behaviors.log → [(ts_ms, comm, path)], 按出现顺序"""
    events = []
    if not BEHAVIORS_LOG.exists():
        return events
    with open(BEHAVIORS_LOG) as f:
        for line in f:
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get('event_type') != 'openat':
                continue
            if d.get('comm') != 'python3':
                continue
            if not str(d.get('target_path', '')).endswith('shadow'):
                continue
            events.append((ts_to_ms(d.get('timestamp')), d.get('comm'),
                           d.get('target_path', '')))
    return events


def ts_to_ms(ts):
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


def inject(count, rate):
    """注入 N 次 openat('/etc/shadow'), 返回 [注入 wall_ms 时间戳] (按序)"""
    interval = 1.0 / rate
    inject_wall_ms = []
    for i in range(count):
        t0 = time.time()
        try:
            fd = os.open('/etc/shadow', os.O_RDONLY)
            os.close(fd)
        except OSError:
            pass
        inject_wall_ms.append(int(t0 * 1000))
        if i < count - 1:
            wait = interval - (time.time() - t0)
            if wait > 0:
                time.sleep(wait)
    return inject_wall_ms


def run_bench(count, rate, pid, save_path=None):
    """跑单档, 返回结果 dict"""
    # 限资源 (注入进程自己崩不碰系统)
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)   # 256MB
    resource.setrlimit(resource.RLIMIT_NOFILE, (2048,) * 2)            # 2048 fd

    # 空闲 CPU 基线 (短, 2s)
    idle = sample_cpu(pid, 2)
    idle_cpu = sum(c for _, c in idle) / len(idle) if idle else 0

    # 注入
    t_inj_start = time.time()
    inject_wall_ms = inject(count, rate)
    t_inj_end = time.time()

    # 排空 (guard 10Hz poll + buffered flush 周期 2s + 消费滞后:
    # v0.4.4 需 15s 让缓冲与消费全部落盘, 否则批次效应误报丢失)
    time.sleep(15)

    # 分析: 逐事件配对 (behaviors 按序 = 注入按序, 同 comm 同路径)
    events = parse_behaviors()
    # 只取注入窗口内的事件 (窗口: 注入前 0.5s ~ 注入后 15s)
    win_start_ms = int((t_inj_start - 0.5) * 1000)
    win_end_ms = int((t_inj_end + 15) * 1000)
    matched = [e for e in events if win_start_ms <= e[0] <= win_end_ms]

    lost = max(0, count - len(matched))

    # 逐事件延迟: matched[i] 落盘时间 - inject[i] 注入时间
    delays = []
    for i, (ev_ms, _, _) in enumerate(matched[:count]):
        if i < len(inject_wall_ms):
            delays.append(ev_ms - inject_wall_ms[i])

    # CPU 采样 (注入后)
    cpu_samples = sample_cpu(pid, 3)
    load_cpu = (sum(c for _, c in cpu_samples) / len(cpu_samples)
                if cpu_samples else 0)

    result = {
        'count': count, 'rate': rate, 'pid': pid,
        'lost': lost, 'loss_rate': round(lost / count * 100, 2),
        'delay_p50_ms': percentile(delays, 50) if delays else None,
        'delay_p95_ms': percentile(delays, 95) if delays else None,
        'delay_max_ms': max(delays) if delays else None,
        'delay_n': len(delays),
        'cpu_idle': round(idle_cpu, 2), 'cpu_load': round(load_cpu, 2),
        'cpu_delta': round(load_cpu - idle_cpu, 2),
    }
    # 即时落盘 (每档先保存, 即使下一档崩溃数据保住)
    if save_path:
        data = []
        if save_path.exists():
            try:
                data = json.loads(save_path.read_text())
            except Exception:
                data = []
        data.append(result)
        save_path.write_text(json.dumps(data, ensure_ascii=False, indent=1))

    print(f"  注入 {count} | 匹配 {len(matched)} | 丢失 {lost} "
          f"({result['loss_rate']}%) | 延迟 p50={result['delay_p50_ms']}ms "
          f"p95={result['delay_p95_ms']}ms max={result['delay_max_ms']}ms | "
          f"CPU 增量 {result['cpu_delta']}%")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, required=True, help='guard 本体 PID')
    ap.add_argument('--count', type=int, default=3000)
    ap.add_argument('--rate', type=int, default=2000)
    ap.add_argument('--ladder', action='store_true',
                    help='阶梯模式: 1K→3K→5K→8K→10K, 每档落盘')
    args = ap.parse_args()

    if args.ladder:
        print(f"=== 阶梯压测 ({LADDER}) pid={args.pid} ===")
        results = []
        for count in LADDER:
            rate = max(2000, count // 2)   # 每档 2s 内注入完
            print(f"[档] count={count} rate={rate}/s ...")
            r = run_bench(count, rate, args.pid, save_path=RESULTS_PATH)
            results.append(r)
            if r['loss_rate'] > 0:
                print(f"  ⚠️ 丢包阈值: {count} 档开始丢 ({r['loss_rate']}%)")
                break
        print(f"\n✅ 阶梯完成, 结果已落盘: {RESULTS_PATH}")
    else:
        print(f"=== bench: count={args.count} rate={args.rate}/s pid={args.pid} ===")
        run_bench(args.count, args.rate, args.pid)


if __name__ == '__main__':
    main()
