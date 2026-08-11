class BehaviorLogger:
    """Records ALL syscall events to behaviors.log (v0.3.10)."""

    LOG_FORMAT_VERSION = 1

    def __init__(self, log_path="behaviors.log", enabled=True):
        self.log_path = log_path
        self.enabled = enabled

    def write(self, event_dict):
        """Write a raw syscall event to the behavior log."""
        if not self.enabled:
            return
        from datetime import datetime
        import json
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
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
