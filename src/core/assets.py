#!/usr/bin/env python3
"""
Asset classifier + state store (v0.6.3, ADR-050).

AssetClassifier — 资产分级:
  - config/assets.yaml 规则可配置: namespace(fnmatch) / labels(全等) / image(正则)
  - 首条命中定级; 全部未中 → 兜底 medium (诚实标注, 不虚标)

AssetStore — 资产状态机 + 三段留痕:
  - 状态机: PENDING_REVIEW → CONFIRMED / OVERRIDDEN
  - logs/assets.yaml 原子落盘 (tmp+rename) — 跨容器重建持久 (logs/ = 挂载目录)
  - logs/assets_audit.log 三段留痕 JSONL:
      auto_inference  (首次推断) / human_decision (确认/覆盖: 人+理由)
      status_transition (状态变更)          — v0.6.7 六层审计可直接转写
"""

import json
import os
import re
import fnmatch
import tempfile
import time
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# AssetClassifier
# ---------------------------------------------------------------------------

class AssetClassifier:
    """Rule-based asset grading. First matching rule wins; fallback medium."""

    DEFAULT_LEVEL = "medium"
    LEVELS = ("critical", "high", "medium", "low")

    def __init__(self, rules_file="config/assets.yaml"):
        self.rules_file = rules_file
        self.rules = []
        self.default_level = self.DEFAULT_LEVEL
        self._load()

    def _load(self):
        import yaml
        try:
            with open(self.rules_file, 'r') as f:
                cfg = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            print(f"  [!] AssetClassifier: 无法读取 {self.rules_file}, "
                  f"使用空规则集 + 兜底 {self.DEFAULT_LEVEL}", file=__import__('sys').stderr)
            self.rules = []
            self.default_level = self.DEFAULT_LEVEL
            return
        self.rules = [r for r in cfg.get('rules', []) if isinstance(r, dict)]
        self.default_level = cfg.get('default_level', self.DEFAULT_LEVEL)
        if self.default_level not in self.LEVELS:
            self.default_level = self.DEFAULT_LEVEL
        print(f"  [Assets] 分类器已加载: {len(self.rules)} 条规则, "
              f"兜底 {self.default_level}")

    def reload(self):
        self._load()

    def classify(self, asset: dict):
        """asset: {id, name, image, namespace?, labels?} →
        (level, rule_name, note) — 兜底 (default_level, None, None)。"""
        image = asset.get('image') or ''
        namespace = asset.get('namespace') or ''
        labels = asset.get('labels') or {}
        for rule in self.rules:
            if not self._match(rule, image, namespace, labels):
                continue
            level = rule.get('level', self.DEFAULT_LEVEL)
            if level not in self.LEVELS:
                level = self.DEFAULT_LEVEL
            return (level, rule.get('name'), rule.get('note'))
        return (self.default_level, None, None)

    @staticmethod
    def _match(rule, image, namespace, labels):
        if rule.get('namespace'):
            n = rule['namespace']
            if namespace != n and not fnmatch.fnmatch(namespace, n):
                return False
        if rule.get('labels'):
            for k, v in rule['labels'].items():
                if labels.get(k) != v:
                    return False
        if rule.get('image'):
            try:
                if not re.search(rule['image'], image, re.IGNORECASE):
                    return False
            except re.error:
                return False
        # 至少一个匹配维度, 否则视为空规则不命中
        return bool(rule.get('namespace') or rule.get('labels') or rule.get('image'))


# ---------------------------------------------------------------------------
# AssetStore
# ---------------------------------------------------------------------------

class AssetStore:
    """Asset state machine + 三段留痕. states: PENDING_REVIEW /
    CONFIRMED / OVERRIDDEN; 重载构造时从 state_file 恢复 (重启恢复)。"""

    def __init__(self, state_file="logs/assets.yaml",
                 audit_file="logs/assets_audit.log",
                 classifier=None):
        self.state_file = Path(state_file)
        self.audit_file = Path(audit_file)
        self.classifier = classifier
        self.assets = {}   # asset_id -> record
        self._load()

    # ---- persistence ----

    def _load(self):
        import yaml
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    cfg = yaml.safe_load(f) or {}
                self.assets = cfg.get('assets', {}) or {}
                print(f"  [Assets] 状态已恢复: {len(self.assets)} 个资产 "
                      f"({self.state_file})")
                return
            except (OSError, yaml.YAMLError) as e:
                print(f"  [!] Assets 状态文件损坏, 重置: {e}",
                      file=__import__('sys').stderr)
        self.assets = {}

    def save(self):
        """原子落盘 (tmp+rename) — 防写一半崩溃毁掉状态文件。"""
        payload = {"version": 1, "updated_at":
                   datetime.now().isoformat(timespec='seconds'),
                   "assets": self.assets}
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(self.state_file.parent),
                                       prefix="assets-", suffix=".tmp")
            try:
                with os.fdopen(fd, 'w') as f:
                    import yaml
                    yaml.safe_dump(payload, f, allow_unicode=True,
                                   sort_keys=False)
                os.replace(tmp, self.state_file)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError as e:
            print(f"  [!] Assets 状态落盘失败: {e}", file=__import__('sys').stderr)

    # ---- audit trail (三段留痕 JSONL) ----

    def _audit(self, asset_id, atype, detail: dict):
        row = {
            "ts": datetime.now().isoformat(timespec='milliseconds'),
            "type": atype,       # auto_inference | human_decision | status_transition
            "asset": asset_id,
            "detail": detail,
        }
        try:
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_file, 'a') as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError as e:
            print(f"  [!] Assets 留痕写入失败: {e}", file=__import__('sys').stderr)
        return row

    def audit_log(self, asset_id=None, limit=100):
        """三段留痕可查: 全部或按资产过滤 (v0.6.4 前端接入)。"""
        rows = []
        if self.audit_file.exists():
            try:
                with open(self.audit_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rows.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                pass
        if asset_id:
            rows = [r for r in rows if r.get('asset') == asset_id]
        return rows[-limit:]

    # ---- state machine ----

    def ensure_asset(self, asset: dict) -> dict:
        """首次见到 → 自动推断 + PENDING_REVIEW + auto_inference 留痕。
        已存在 → 只更新 name/image (动态信息), 状态与级别不动。"""
        aid = asset.get('id')
        if not aid:
            return {}
        rec = self.assets.get(aid)
        if rec is None:
            level, rule, note = (self.classifier.classify(asset)
                                 if self.classifier else
                                 ('medium', None, None))
            rec = {
                'id': aid,
                'name': asset.get('name', ''),
                'image': asset.get('image', ''),
                'namespace': asset.get('namespace', ''),
                'level': level,
                'level_source': 'auto',
                'rule': rule,
                'state': 'PENDING_REVIEW',
                'first_seen': datetime.now().isoformat(timespec='seconds'),
                'updated_at': datetime.now().isoformat(timespec='seconds'),
                'audit_count': 0,
            }
            self.assets[aid] = rec
            self._audit(aid, 'auto_inference', {
                'level': level, 'rule': rule, 'note': note,
                'name': rec['name'], 'image': rec['image'],
            })
            rec['audit_count'] += 1
            self.save()
            return rec
        # 已存在: 同步动态字段; 名称变化也留痕 (rename 是状态相关事实)
        changed = False
        for k in ('name', 'image'):
            v = asset.get(k)
            if v and rec.get(k) != v:
                rec[k] = v
                changed = True
        if changed:
            rec['updated_at'] = datetime.now().isoformat(timespec='seconds')
            self._audit(aid, 'auto_inference', {
                'action': 'metadata_sync',
                'reason': '动态元数据更新 (运行时快照)',
            })
            rec['audit_count'] += 1
            self.save()
        return rec

    def get(self, asset_id):
        return self.assets.get(asset_id)

    def list(self):
        return list(self.assets.values())

    def confirm(self, asset_id, by_user, reason) -> dict:
        """PENDING_REVIEW → CONFIRMED — 人工确认资产真实可信。"""
        rec = self.assets.get(asset_id)
        if rec is None:
            raise KeyError(f"资产不存在: {asset_id}")
        if rec['state'] == 'CONFIRMED':
            return rec
        old = rec['state']
        rec['state'] = 'CONFIRMED'
        rec['updated_at'] = datetime.now().isoformat(timespec='seconds')
        self._audit(asset_id, 'human_decision',
                    {'action': 'confirm', 'by': by_user, 'reason': reason})
        self._audit(asset_id, 'status_transition',
                    {'from': old, 'to': 'CONFIRMED', 'by': by_user})
        rec['audit_count'] += 2
        self.save()
        return rec

    def override(self, asset_id, level, by_user, reason) -> dict:
        """级别覆盖 — 资产状态转 OVERRIDDEN, 级别以人工为准。"""
        if level not in AssetClassifier.LEVELS:
            raise ValueError(f"非法级别: {level}")
        rec = self.assets.get(asset_id)
        if rec is None:
            raise KeyError(f"资产不存在: {asset_id}")
        old_state = rec['state']
        old_level = rec['level']
        rec['level'] = level
        rec['level_source'] = 'override'
        rec['state'] = 'OVERRIDDEN'
        rec['updated_at'] = datetime.now().isoformat(timespec='seconds')
        self._audit(asset_id, 'human_decision',
                    {'action': 'override', 'level': level, 'by': by_user,
                     'reason': reason})
        self._audit(asset_id, 'status_transition',
                    {'from': old_state, 'to': 'OVERRIDDEN', 'by': by_user})
        self._audit(asset_id, 'status_transition',
                    {'from': 'auto', 'to': 'override', 'field': 'level',
                     'old_level': old_level, 'by': by_user})
        rec['audit_count'] += 3
        self.save()
        return rec