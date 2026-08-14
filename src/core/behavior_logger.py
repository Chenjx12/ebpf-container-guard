import glob
import json
import os
import time
from datetime import datetime, timedelta


class BehaviorLogger:
    """Records ALL syscall events to behaviors.log (v0.3.10, v0.4.4 优化).

    v0.4.4: buffered writer + 按天/大小轮转 (rename 方案)。
    - 保持文件打开, write 追加, 每 flush_interval 秒 flush 一次
      (消除每事件 open('a')+write+close 的 2 次 syscall, 压测决策 #37)
    - 跨天或超 max_bytes 时: close → rename 为 behaviors.YYYY-MM-DD.log → 新开
      (读取侧读 behaviors.log 即最新, 零改动)
    - 保留 retain_days 天, 启动/轮转时清理旧文件
    - 崩溃丢数据窗口 ≤ flush_interval (审计主链 events.log 不丢, 可接受)
    """

    LOG_FORMAT_VERSION = 1
    DEFAULT_MAX_BYTES = 50 * 1024 * 1024   # 50MB
    DEFAULT_RETAIN_DAYS = 7
    DEFAULT_FLUSH_INTERVAL = 0.5           # 秒 — 高速率下 2s 大 flush 阻塞 ringbuf

    def __init__(self, log_path="behaviors.log", enabled=True,
                 max_bytes=DEFAULT_MAX_BYTES, retain_days=DEFAULT_RETAIN_DAYS,
                 flush_interval=DEFAULT_FLUSH_INTERVAL):
        self.log_path = log_path
        self.enabled = enabled
        self.max_bytes = max_bytes
        self.retain_days = retain_days
        self.flush_interval = flush_interval
        self._file = None
        self._cur_date = None
        self._last_flush = 0.0
        self._written = 0   # 累计写入字节 (避免每事件 tell() syscall)
        self._cleanup_old()

    def _open(self):
        self._file = open(self.log_path, 'a')
        self._cur_date = datetime.now().date()
        self._last_flush = self._now()
        self._written = 0

    def _now(self):
        return time.monotonic()

    def _cleanup_old(self):
        """删除 retain_days 天前的 behaviors.*.log"""
        cutoff = (datetime.now() - timedelta(days=self.retain_days)).date()
        for old in glob.glob(self.log_path + ".*"):
            # 匹配 behaviors.YYYY-MM-DD.log (日期在最后一段)
            name = os.path.basename(old)
            parts = name.rsplit('.', 1)
            if len(parts) == 2:
                try:
                    d = datetime.strptime(parts[-1], '%Y-%m-%d').date()
                    if d < cutoff:
                        os.remove(old)
                except ValueError:
                    pass

    def _maybe_rotate(self):
        now = datetime.now()
        if self._file is None:
            self._open()
            return
        # 外部删除 (rm -f) 后重建 — 旧 inode 无引用, 新文件从零开始
        if not os.path.exists(self.log_path):
            self._file.flush()
            self._file.close()
            self._open()
            return
        if now.date() != self._cur_date or self._written > self.max_bytes:
            self._file.flush()
            self._file.close()
            os.rename(self.log_path,
                      f"{self.log_path}.{self._cur_date:%Y-%m-%d}")
            self._open()
            self._cleanup_old()

    def write(self, event_dict):
        """Write a raw syscall event to the behavior log."""
        if not self.enabled:
            return
        now = datetime.now()
        entry = {
            'version': self.LOG_FORMAT_VERSION,
            'timestamp': now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3],
            'event_type': event_dict.get('event_type', 'unknown'),
            'container_id': event_dict.get('container_id', 'unknown'),
            'pid': event_dict.get('pid'), 'uid': event_dict.get('uid'),
            'comm': event_dict.get('comm'),
            'target_path': event_dict.get('target_path'),
            'fstype': event_dict.get('fstype'),
            'target_pid': event_dict.get('target_pid'),
            'request': event_dict.get('request'),
            'daddr': event_dict.get('daddr'),
            'dport': event_dict.get('dport'),
        }
        self._maybe_rotate()
        line = json.dumps(entry, ensure_ascii=False) + '\n'
        self._file.write(line)
        self._written += len(line.encode('utf-8'))
        if self._now() - self._last_flush >= self.flush_interval:
            self._file.flush()
            self._last_flush = self._now()

    def flush(self):
        """主动 flush (关闭/退出时调用)"""
        if self._file:
            self._file.flush()

    def close(self):
        if self._file:
            self._file.flush()
            self._file.close()
            self._file = None
