import glob
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timedelta



# ----------------------------------------------------------------------
# 序列化：手写模板（快路径）
#
# json.dumps 一条约 7–10us，是每事件成本的大头（哈希只要 0.7us）。
# 这里用固定模板拼字符串，实测约 4–5us（1.8–2x），且**输出与
# json.dumps(ensure_ascii=False, separators=(',',':')) 逐字节一致** ——
# 校验端仍用 json.dumps 重算，两边必须字节相同。
#
# 任何可疑情况（引号/反斜杠/控制字符/非预期类型）一律回落到 json.dumps，
# 保证正确性优先于速度。
# ----------------------------------------------------------------------

_BODY_JSON = ('{"version":%(version)d,"seq":%(seq)d,"prev":"%(prev)s",'
              '"timestamp":"%(timestamp)s","event_type":"%(event_type)s",'
              '"container_id":"%(container_id)s","pid":%(pid)s,"uid":%(uid)s,'
              '"comm":%(comm)s,"target_path":%(target_path)s,"fstype":%(fstype)s,'
              '"target_pid":%(target_pid)s,"request":%(request)s,'
              '"daddr":%(daddr)s,"dport":%(dport)s}')


def _q(v):
    """字符串 → JSON 字符串字面量（不转义，调用方已保证安全）。"""
    return 'null' if v is None else '"' + v + '"'


def _n(v):
    return 'null' if v is None else str(v)


def _build_body(entry):
    """返回与 json.dumps 等价的紧凑 JSON 字符串。"""
    try:
        prev = entry['prev']
        ts = entry['timestamp']
        et = entry['event_type']
        cid = entry['container_id']
        comm = entry['comm']
        path = entry['target_path']
        fstype = entry['fstype']
        req = entry['request']
        daddr = entry['daddr']
        version = entry['version']
        seq = entry['seq']
        pid = entry['pid']
        uid = entry['uid']
        tpid = entry['target_pid']
        dport = entry['dport']
    except (KeyError, TypeError):
        return _json_body(entry)

    # 类型守卫：任何非预期类型直接回落（bool 是 int 子类，需显式排除）
    if (version.__class__ is not int or seq.__class__ is not int
            or prev.__class__ is not str or ts.__class__ is not str
            or et.__class__ is not str or cid.__class__ is not str):
        return _json_body(entry)
    for v in (pid, uid, tpid, dport):
        if v is not None and v.__class__ is not int:
            return _json_body(entry)
    for v in (comm, path, fstype, req, daddr):
        if v is not None and v.__class__ is not str:
            return _json_body(entry)

    # 一次扫描完成转义需求判定（拼接后扫描比逐字段快）
    joined = ''.join([x for x in (prev, ts, et, cid, comm, path, fstype, req, daddr)
                      if x is not None])
    if '"' in joined or '\\' in joined or not joined.isprintable():
        return _json_body(entry)

    return (_BODY_JSON % {
        'version': version, 'seq': seq, 'prev': prev, 'timestamp': ts,
        'event_type': et, 'container_id': cid, 'pid': _n(pid), 'uid': _n(uid),
        'comm': _q(comm), 'target_path': _q(path), 'fstype': _q(fstype),
        'target_pid': _n(tpid), 'request': _q(req), 'daddr': _q(daddr),
        'dport': _n(dport),
    })


def _json_body(entry):
    return json.dumps(entry, ensure_ascii=False, separators=(',', ':'))


class BehaviorLogger:
    """Records ALL syscall events to behaviors.log — v2: 可校验的哈希链。

    v2 (P0 取证改造) 在原缓冲写入 + 轮转的基础上，为每条记录加三类字段，
    构成跨文件、跨重启连续的证据链：

        seq   单调递增序号（跨文件连续）
        prev  上一条记录的 hash（首条为 64 个 0 的创世值）
        hash  sha256(prev + body)（或 HMAC-SHA256，integrity_mode="hmac"）

    同时修复两个会导致证据丢失的缺陷：

      1. 同一天内按大小轮转会 os.rename 到同名文件，第二份覆盖第一份。
         新命名 behaviors.log.YYYY-MM-DD.NNN 带序号，杜绝覆盖。
      2. _cleanup_old 用 rsplit('.', 1) 取日期，文件名一旦带序号就解析失败、
         旧文件永不被删。改为正则匹配（同时兼容无序号的历史文件名）。

    写入性能：只序列化一次（body），hash 追加在尾部，实测 +0.71us/条
    （20k ev/s 时约 +1.4% 单核）。
    """

    LOG_FORMAT_VERSION = 2
    DEFAULT_MAX_BYTES = 50 * 1024 * 1024   # 50MB
    DEFAULT_RETAIN_DAYS = 7
    DEFAULT_FLUSH_INTERVAL = 0.1           # 秒 — 0.5s 批次会让 p95 出现 flush 停顿尖峰

    # 哈希链创世值：首条记录的 prev
    GENESIS = '0' * 64


    def __init__(self, log_path="behaviors.log", enabled=True,
                 max_bytes=DEFAULT_MAX_BYTES, retain_days=DEFAULT_RETAIN_DAYS,
                 flush_interval=DEFAULT_FLUSH_INTERVAL,
                 integrity_mode="hash", key_path=None):
        self.log_path = log_path
        self.enabled = enabled
        self.max_bytes = max_bytes
        self.retain_days = retain_days
        self.flush_interval = flush_interval

        self.integrity_mode = integrity_mode
        self._key = self._load_key(key_path) if integrity_mode == "hmac" else None

        self._file = None
        self._cur_date = None
        self._last_flush = 0.0
        self._written = 0          # 累计写入字节 (避免每事件 tell() syscall)
        self._seq = 0              # 已写入的最大序号
        self._last_hash = self.GENESIS
        self._state_loaded = False  # 仅首次 _open 时从磁盘恢复链状态

        # 轮转文件命名：behaviors.log.2026-11-13.001（兼容历史无序号文件）
        self._name_re = re.compile(
            r'^' + re.escape(os.path.basename(self.log_path))
            + r'\.(\d{4}-\d{2}-\d{2})(?:\.(\d{3}))?$')

        self._cleanup_old()

    # ------------------------------------------------------------------
    # 密钥（hmac 模式）
    # ------------------------------------------------------------------
    @staticmethod
    def _load_key(path):
        if not path or not os.path.exists(path):
            raise FileNotFoundError(
                f"integrity_mode=hmac 但找不到密钥文件: {path}")
        st = os.stat(path)
        if st.st_mode & 0o077:
            raise PermissionError(
                f"密钥文件权限过宽（{oct(st.st_mode & 0o777)}），应为 0600: {path}")
        with open(path, 'rb') as f:
            key = f.read()
        if len(key) < 16:
            raise ValueError(f"密钥过短（{len(key)} 字节），至少 16 字节: {path}")
        return key

    # ------------------------------------------------------------------
    # 摘要
    # ------------------------------------------------------------------
    def _digest(self, prev_hex, body):
        payload = (prev_hex + body).encode('utf-8')
        if self._key:
            return hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return hashlib.sha256(payload).hexdigest()

    # ------------------------------------------------------------------
    # 链状态恢复
    # ------------------------------------------------------------------
    def _read_last_state(self, path):
        """读文件最后一条合法记录，返回 (seq, hash)；空/损坏返回 None。"""
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        if size == 0:
            return None
        with open(path, 'rb') as f:
            # 尾部 64KB 足够覆盖最后若干行
            f.seek(max(0, size - 65536))
            tail = f.read()
        for raw in reversed(tail.splitlines()):
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                continue
            if 'seq' in rec and 'hash' in rec:
                return int(rec['seq']), rec['hash']
            return None   # 命中 v1 格式记录 → 该文件未受保护
        return None

    def _latest_file(self):
        """当前活跃文件优先，其次 (日期, 序号) 最大的轮转文件。"""
        if os.path.exists(self.log_path) and os.path.getsize(self.log_path) > 0:
            return self.log_path
        cands = []
        for p in glob.glob(self.log_path + ".*"):
            m = self._name_re.match(os.path.basename(p))
            if m:
                cands.append(((m.group(1), int(m.group(2) or 0)), p))
        return max(cands)[1] if cands else None

    def _recover_state(self):
        latest = self._latest_file()
        if latest:
            state = self._read_last_state(latest)
            if state:
                self._seq, self._last_hash = state
                return
        self._seq, self._last_hash = 0, self.GENESIS

    # ------------------------------------------------------------------
    # 文件打开 / 轮转 / 清理
    # ------------------------------------------------------------------
    def _open(self):
        if not self._state_loaded:
            self._recover_state()
            self._state_loaded = True
        self._file = open(self.log_path, 'a')
        self._cur_date = datetime.now().date()
        self._last_flush = self._now()
        try:
            # 追加模式下必须从现有大小起算，否则 max_bytes 判定失真
            self._written = os.path.getsize(self.log_path)
        except OSError:
            self._written = 0

    def _now(self):
        return time.monotonic()

    def _rotate_target(self, date):
        """生成不冲突的轮转文件名：behaviors.log.2026-11-13.001"""
        base = f"{self.log_path}.{date:%Y-%m-%d}"
        n = 1
        while os.path.exists(f"{base}.{n:03d}"):
            n += 1
        return f"{base}.{n:03d}"

    def _cleanup_old(self):
        """删除 retain_days 天前的轮转文件（兼容带/不带序号两种命名）。"""
        cutoff = (datetime.now() - timedelta(days=self.retain_days)).date()
        for old in glob.glob(self.log_path + ".*"):
            m = self._name_re.match(os.path.basename(old))
            if not m:
                continue
            try:
                if datetime.strptime(m.group(1), '%Y-%m-%d').date() < cutoff:
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
            os.rename(self.log_path, self._rotate_target(self._cur_date))
            self._open()
            self._cleanup_old()

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def write(self, event_dict):
        """Write one chained record to the behavior log."""
        if not self.enabled:
            return
        self._maybe_rotate()

        now = datetime.now()
        seq = self._seq + 1
        prev = self._last_hash
        # 字段顺序即规范化顺序：校验端按同样顺序/分隔符重新序列化即可逐字节复现
        entry = {
            'version': self.LOG_FORMAT_VERSION,
            'seq': seq,
            'prev': prev,
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
        # 只序列化一次；hash 追加在尾部（body 必以 '}' 结尾）
        body = _build_body(entry)
        digest = self._digest(prev, body)
        line = body[:-1] + ',"hash":"' + digest + '"}\n'

        self._file.write(line)
        self._seq = seq
        self._last_hash = digest
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
