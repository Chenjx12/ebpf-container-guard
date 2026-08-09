#!/usr/bin/env python3
"""
AI Threat Judge — DeepSeek API integration for Tier 3 analysis.

Receives rule engine + attack matrix results and provides:
  - Attack confirmation / false positive assessment
  - Technique identification
  - Suggested response action
  - Confidence score
  - Human-readable threat report
  - Unknown attack → suggested new rule generation
"""

import json
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict


# ================================================================
# Data structures
# ================================================================

@dataclass
class AIResult:
    """Output of AI threat analysis."""
    is_attack: bool
    technique: str
    suggested_action: str
    confidence: int
    report: str
    suggested_rule: Optional[dict] = None


# ================================================================
# Prompt templates
# ================================================================

SYSTEM_PROMPT = """You are an expert container security analyst. Your task is to
analyze suspicious events detected by an eBPF-based container escape detection
system and determine whether they represent real attacks.

For each alert, provide a structured JSON response with these fields:
{
  "is_attack": true/false,
  "technique": "e.g., CVE-2019-5736 runc escape, container breakout via nsenter, reverse shell",
  "suggested_action": "pause_container | isolate_network | kill_process | kill_container | log_only",
  "confidence": 0-100 (how confident are you this is a real attack),
  "report": "A 2-3 sentence analysis explaining your decision in Chinese",
  "suggested_rule": null (or a new detection rule object if you discover an unknown attack pattern)
}

Response format: valid JSON only, no markdown, no extra text."""

EVENT_CONTEXT_TEMPLATE = """Alert from container {container_id}:

Rule matched: {rule_name}
Severity: {severity}
Attack vector: {attack_vector}
Behavior description: {behavior_desc}
Associated CVEs: {cves}
Base confidence: {base_conf}%

Event details:
- PID: {pid}
- Process: {comm}
- Event type: {event_type}
{fstype_line}{target_line}{ptrace_line}

Recent attack vectors from same container (last 10s): {recent_vectors}

Analyze this alert and return your verdict as JSON."""


# ================================================================
# AI Analyzer
# ================================================================

class AIAnalyzer:
    """OpenAI-compatible API integration for threat analysis.

    Works with any OpenAI-compatible chat completion endpoint:
      - DeepSeek:      https://api.deepseek.com/v1
      - OpenAI:        https://api.openai.com/v1
      - vLLM/Ollama:   http://localhost:8000/v1 (local models)
    Configure via base_url in ai_config.yaml.
    """

    # OpenAI-compatible chat completions endpoint (appended to base_url)
    CHAT_PATH = "/chat/completions"

    def __init__(self, config_path: str = "config/ai_config.yaml"):
        self.api_key = None
        self.model = "deepseek-chat"
        self.base_url = "https://api.deepseek.com/v1"
        self.enabled = False

        # Try to load API key from config
        if os.path.exists(config_path):
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            self.api_key = config.get("api_key", "")
            self.model = config.get("model", "deepseek-chat")
            self.base_url = config.get("base_url", self.base_url).rstrip('/')
            self.enabled = bool(self.api_key)

        if not self.enabled:
            print("[AI] API key not configured — AI analysis disabled")
            print("[AI] Create config/ai_config.yaml with: api_key: sk-xxx")

    def analyze(self, alert: dict, context_vectors: List[str],
                base_confidence: int) -> Optional[AIResult]:
        """Send alert to DeepSeek for AI-powered threat analysis.

        Args:
            alert: The alert dict from rule engine (rule_name, severity, event, etc.)
            context_vectors: Recent attack vectors from same container
            base_confidence: Confidence from the attack matrix

        Returns:
            AIResult if analysis succeeded, None if AI disabled or API error.
        """
        if not self.enabled:
            return self._fallback_analysis(alert, base_confidence)

        prompt = self._build_prompt(alert, context_vectors, base_confidence)

        try:
            response = self._call_deepseek(prompt)
            return self._parse_response(response, alert, base_confidence)
        except Exception as e:
            print(f"[AI] API call failed: {e}, using fallback analysis")
            return self._fallback_analysis(alert, base_confidence)

    # -----------------------------------------------------------
    # Internal methods
    # -----------------------------------------------------------

    def _build_prompt(self, alert: dict, context_vectors: List[str],
                      base_conf: int) -> str:
        """Build the analysis prompt from alert + context."""
        evt = alert.get("event", {})
        rule_name = alert.get("rule_name", "unknown")
        severity = alert.get("severity", "UNKNOWN")
        attack_vector = alert.get("attack_vector", "unknown")
        behavior_desc = alert.get("description", "")
        cves = ", ".join(alert.get("cve_refs", [])) or "none"

        # Event-specific detail lines
        fstype_line = ""
        target_line = ""
        ptrace_line = ""

        if "fstype" in evt:
            fstype = evt.get("fstype", "") or "(empty)"
            fstype_line = f"- Filesystem type: {fstype}\n"
        if "target_path" in evt:
            target_line = f"- Target path: {evt.get('target_path', '')}\n"
        elif "daddr" in evt:
            target_line = f"- Destination: {evt.get('daddr', '')}:{evt.get('dport', '')}\n"
        if "target_pid" in evt:
            ptrace_line = (f"- Ptrace target PID: {evt.get('target_pid', '')}\n"
                           f"- Ptrace request: {evt.get('request', '')}\n")

        recent_str = ", ".join(context_vectors) if context_vectors else "none"

        return EVENT_CONTEXT_TEMPLATE.format(
            container_id=evt.get("container_id", "unknown"),
            rule_name=rule_name,
            severity=severity,
            attack_vector=attack_vector,
            behavior_desc=behavior_desc,
            cves=cves,
            base_conf=base_conf,
            pid=evt.get("pid", "?"),
            comm=evt.get("comm", "?"),
            event_type=evt.get("event_type", "?"),
            fstype_line=fstype_line,
            target_line=target_line,
            ptrace_line=ptrace_line,
            recent_vectors=recent_str,
        )

    def _call_deepseek(self, prompt: str) -> dict:
        """Call OpenAI-compatible chat completions API and parse JSON response.

        Uses self.base_url (configurable), defaulting to DeepSeek.
        """
        import urllib.request

        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 500,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.base_url}{self.CHAT_PATH}",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            content = data["choices"][0]["message"]["content"]
            return json.loads(content)

    def _parse_response(self, response: dict, alert: dict,
                        base_conf: int) -> AIResult:
        """Parse DeepSeek JSON response into AIResult."""
        is_attack = response.get("is_attack", True)
        technique = response.get("technique", "Unknown")
        action = response.get("suggested_action", "log_only")
        confidence = int(response.get("confidence", base_conf))
        report = response.get("report", "")
        suggested_rule = response.get("suggested_rule")

        return AIResult(
            is_attack=is_attack,
            technique=technique,
            suggested_action=action,
            confidence=confidence,
            report=report,
            suggested_rule=suggested_rule,
        )

    def _fallback_analysis(self, alert: dict, base_conf: int) -> Optional[AIResult]:
        """Fallback when AI is disabled or API fails.

        Uses the attack matrix confidence to make a deterministic decision:
          > 85: auto-respond
          60-85: log as pending (need Web panel for human review)
          < 60: log only
        """
        if base_conf > 85:
            action = alert.get("suggested_action", "log_only")
            return AIResult(
                is_attack=True,
                technique="Matrix-scored threat",
                suggested_action=action,
                confidence=base_conf,
                report=f"Attack matrix confidence {base_conf}% — auto-response triggered",
            )
        elif base_conf >= 60:
            return AIResult(
                is_attack=True,
                technique="Matrix-scored threat (pending review)",
                suggested_action="log_only",
                confidence=base_conf,
                report=f"Attack matrix confidence {base_conf}% — flagged for human review",
            )
        else:
            return None  # Too low to report
