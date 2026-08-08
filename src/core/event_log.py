#!/usr/bin/env python3
"""
Structured JSON event logger for the 3-tier detection pipeline.

Writes one JSON object per line to events.log, covering every pipeline
decision — true positives, false positives, and AI verdicts.
"""

import json
import time
from typing import Optional


class EventLogger:
    """Append-only structured JSON event log."""

    def __init__(self, log_path: str = "events.log"):
        self.log_path = log_path

    def write(self, alert: dict, matrix_result=None, ai_result=None,
              action: str = "log_only", event_dict: dict = None):
        """Write a pipeline decision to the event log.

        Args:
            alert: Alert dict from rule engine (rule_name, severity, etc.).
            matrix_result: Attack matrix analysis result (optional).
            ai_result: AI judge analysis result (optional).
            action: Final response action taken.
            event_dict: Raw event dict (used when alert has no embedded event).
        """
        evt = alert.get('event', event_dict or {})
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'container_id': evt.get('container_id', 'unknown'),
            'event_type': evt.get('event_type', 'unknown'),
            'rule': alert.get('rule_name', 'none'),
            'severity': alert.get('severity', 'INFO'),
            # Tier 1
            'tier1_match': True,
            # Tier 2
            'tier2_vector': alert.get('attack_vector'),
            'tier2_confidence': alert.get('matrix_confidence'),
            'tier2_combo': matrix_result.boosted if matrix_result else False,
            'tier2_narrative': (matrix_result.combination_narrative
                                if matrix_result else ''),
            # Tier 3 (populated only if AI was called)
            'tier3_ai_verdict': None,
            'tier3_ai_confidence': None,
            'tier3_ai_technique': None,
            'tier3_ai_report': None,
            # Action
            'action': action,
            # Raw event
            'event': {
                'pid': evt.get('pid'),
                'comm': evt.get('comm'),
                'uid': evt.get('uid'),
                'fstype': evt.get('fstype'),
                'target_path': evt.get('target_path'),
                'target_pid': evt.get('target_pid'),
                'request': evt.get('request'),
                'daddr': evt.get('daddr'),
                'dport': evt.get('dport'),
            },
        }

        if ai_result:
            entry['tier3_ai_verdict'] = (
                'true_positive' if ai_result.is_attack else 'false_positive')
            entry['tier3_ai_confidence'] = ai_result.confidence
            entry['tier3_ai_technique'] = ai_result.technique
            entry['tier3_ai_report'] = ai_result.report
            entry['action'] = ai_result.suggested_action

        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
