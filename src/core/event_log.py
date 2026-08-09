#!/usr/bin/env python3
"""
Structured JSON event logger for the 3-tier detection pipeline.

Writes one JSON object per line to events.log, covering every pipeline
decision — true positives, false positives, and AI verdicts.
"""

import json
import time
from datetime import datetime
from typing import Optional

# Log format version — bump when schema changes (v0.2.5: +state, +escalation, +netblocked)
LOG_FORMAT_VERSION = 2


class EventLogger:
    """Append-only structured JSON event log."""

    def __init__(self, log_path: str = "events.log"):
        self.log_path = log_path

    def write(self, alert: dict, matrix_result=None, ai_result=None,
              action: str = "log_only", action_status: str = "executed",
              tier1_match: bool = True, event_dict: dict = None,
              netblocked: bool = False, event_ts: str = None):
        """Write a pipeline decision to the event log.

        Args:
            alert: Alert dict from rule engine (rule_name, severity, etc.).
            matrix_result: Attack matrix analysis result (optional).
            ai_result: AI judge analysis result (optional).
            action: Final response action taken.
            action_status: What actually happened: 'executed',
                'skipped_cooldown', 'skipped_host', 'queued_human', 'error'.
            tier1_match: Whether a rule matched (True for alerts).
            event_dict: Raw event dict (used when alert has no embedded event).
            netblocked: Whether malicious traffic was blocked (iptables DROP).
            event_ts: External ISO timestamp (v0.3.2 async AI matching —
                must match the one passed to AsyncAIAnalyzer.submit).
        """
        evt = alert.get('event', event_dict or {})
        now = datetime.now()
        ts = event_ts or now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]

        # Event state machine (v0.2.5, decision record #16):
        #   new → quarantine → pending_review → confirmed / dismissed
        if action_status == 'queued_human':
            state = 'pending_review'
        elif action_status in ('executed',):
            state = 'quarantine' if alert.get('escalation') else 'resolved'
        else:
            state = 'new'

        entry = {
            'version': LOG_FORMAT_VERSION,
            'timestamp': ts,
            'container_id': evt.get('container_id', 'unknown'),
            'event_type': evt.get('event_type', 'unknown'),
            'rule': alert.get('rule_name', 'none'),
            'severity': alert.get('severity', 'INFO'),
            'state': state,
            # Tier 1
            'tier1_match': tier1_match,
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
            # Escalation (v0.2.5)
            'escalation': alert.get('escalation'),
            'netblocked': netblocked,
            # Action (intended vs actually executed)
            'action': action,
            'action_status': action_status,
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
