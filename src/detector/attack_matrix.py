#!/usr/bin/env python3
"""
Behavior→CVE mapping matrix with combination scoring.

Tier 2 of the 3-tier detection model:
  Tier 1: rule engine (deterministic, sub-ms)
  Tier 2: attack matrix (attack_vector → CVE, combination boost)  ← this file
  Tier 3: AI judge (DeepSeek, confidence-gated response)
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ================================================================
# Attack Vector → CVE Reference Table
# ================================================================

BEHAVIOR_MATRIX: Dict[str, dict] = {
    "procfs_mount": {
        "description": "Container mounted host procfs",
        "base_confidence": 85,
        "cve_refs": ["CVE-2019-5736", "CVE-2019-16884", "CVE-2020-15257"],
        "techniques": ["procfs mount escape", "container breakout"],
        "suggested_action": "pause_container",
    },
    "docker_socket_mount": {
        "description": "Container mounted Docker socket",
        "base_confidence": 90,
        "cve_refs": ["CVE-2019-5736"],
        "techniques": ["Docker socket escape", "privileged container escape"],
        "suggested_action": "pause_container",
    },
    "ptrace_host_init": {
        "description": "Container ptrace'd host PID 1",
        "base_confidence": 75,
        "cve_refs": ["CVE-2019-16884", "CVE-2022-0492"],
        "techniques": ["process injection", "host namespace escape"],
        "suggested_action": "isolate_network",
    },
    "nsenter_escape": {
        "description": "Container executed nsenter to escape namespaces",
        "base_confidence": 90,
        "cve_refs": ["CVE-2019-5736", "CVE-2022-0492"],
        "techniques": ["nsenter escape", "namespace breakout"],
        "suggested_action": "kill_container",
    },
    "privileged_exec": {
        "description": "Low-privilege process executed interactive shell",
        "base_confidence": 65,
        "cve_refs": ["CVE-2019-5736"],
        "techniques": ["privilege escalation", "post-exploitation"],
        "suggested_action": "kill_process",
    },
    "reverse_shell": {
        "description": "Container initiated external network connection",
        "base_confidence": 70,
        "cve_refs": ["T1059", "T1071"],
        "techniques": ["reverse shell", "C2 communication"],
        "suggested_action": "isolate_network",
    },
    "sensitive_file_access": {
        "description": "Container accessed host sensitive files",
        "base_confidence": 75,
        "cve_refs": ["CVE-2019-5736"],
        "techniques": ["credential theft", "information disclosure"],
        "suggested_action": "pause_container",
    },
    "host_directory_access": {
        "description": "Container accessed host-mounted directories",
        "base_confidence": 70,
        "cve_refs": ["CVE-2019-5736", "CVE-2020-15257"],
        "techniques": ["host filesystem access", "data exfiltration"],
        "suggested_action": "pause_container",
    },
}


# ================================================================
# Combination Boost Rules
# When multiple attack vectors hit the same container in a short
# window, confidence is boosted significantly.
# ================================================================

# (vector_a, vector_b) → (boosted_cve, confidence, description)
COMBINATION_BOOSTS = {
    ("procfs_mount", "nsenter_escape"): {
        "cve": "CVE-2019-5736",
        "confidence": 95,
        "description": "Procfs mount + nsenter escape → runc container breakout",
    },
    ("procfs_mount", "docker_socket_mount"): {
        "cve": "CVE-2019-5736",
        "confidence": 93,
        "description": "Procfs + Docker socket mount → full host compromise",
    },
    ("ptrace_host_init", "sensitive_file_access"): {
        "cve": "CVE-2022-0492",
        "confidence": 90,
        "description": "Ptrace host init + sensitive file read → targeted attack",
    },
    ("nsenter_escape", "reverse_shell"): {
        "cve": "CVE-2019-5736",
        "confidence": 92,
        "description": "Nsenter escape + reverse shell → active intrusion",
    },
    ("privileged_exec", "reverse_shell"): {
        "cve": "T1059",
        "confidence": 85,
        "description": "Shell exec + external connect → interactive reverse shell",
    },
    ("procfs_mount", "sensitive_file_access"): {
        "cve": "CVE-2019-5736",
        "confidence": 88,
        "description": "Procfs mount + sensitive file access → data exfiltration attempt",
    },
}

# Time window for combination detection (seconds)
COMBINATION_WINDOW = 10


# ================================================================
# Attack Matrix Engine
# ================================================================

@dataclass
class MatrixResult:
    """Output of the attack matrix analysis."""
    attack_vector: str
    base_confidence: int
    boosted: bool
    final_confidence: int
    cve_refs: List[str]
    techniques: List[str]
    suggested_action: str
    combination_narrative: str = ""
    escalate_to_ai: bool = False


class AttackMatrix:
    """Behavior→CVE mapping with same-container combination detection."""

    def __init__(self, combination_window: int = COMBINATION_WINDOW):
        self.window = combination_window
        # container_id → [(timestamp, attack_vector), ...]
        self._recent_hits: Dict[str, List[tuple]] = defaultdict(list)

    def analyze(self, attack_vector: str, container_id: str) -> MatrixResult:
        """Analyze a rule engine hit through the behavior matrix.

        Args:
            attack_vector: The attack_vector tag from the matched rule.
            container_id: Container that triggered the alert.

        Returns:
            MatrixResult with confidence scores, CVE references, and action.
        """
        now = time.time()
        vector_info = BEHAVIOR_MATRIX.get(
            attack_vector,
            {"base_confidence": 50, "cve_refs": [], "techniques": [],
             "suggested_action": "log_only",
             "description": "Unknown attack vector"},
        )

        base_conf = vector_info.get("base_confidence", 50)
        cve_refs = list(vector_info.get("cve_refs", []))
        techniques = list(vector_info.get("techniques", []))
        action = vector_info.get("suggested_action", "log_only")

        # Prune expired hits and record this one
        self._prune(container_id, now)
        self._recent_hits[container_id].append((now, attack_vector))

        # Check for combination boosts
        boosted = False
        final_conf = base_conf
        narration = ""

        recent_vectors = [v for (_, v) in self._recent_hits[container_id]
                          if v != attack_vector]
        for rv in recent_vectors:
            key1 = (attack_vector, rv)
            key2 = (rv, attack_vector)
            combo = COMBINATION_BOOSTS.get(key1) or COMBINATION_BOOSTS.get(key2)
            if combo:
                boosted = True
                final_conf = max(final_conf, combo["confidence"])
                if combo["cve"] not in cve_refs:
                    cve_refs.insert(0, combo["cve"])
                narration = combo["description"]

        # Escalate to AI if confidence is in the gray zone
        escalate = 60 <= final_conf <= 85

        return MatrixResult(
            attack_vector=attack_vector,
            base_confidence=base_conf,
            boosted=boosted,
            final_confidence=final_conf,
            cve_refs=cve_refs,
            techniques=techniques,
            suggested_action=action,
            combination_narrative=narration,
            escalate_to_ai=escalate,
        )

    def _prune(self, container_id: str, now: float):
        """Remove hits outside the combination window."""
        cutoff = now - self.window
        self._recent_hits[container_id] = [
            (ts, vec) for (ts, vec) in self._recent_hits[container_id]
            if ts > cutoff
        ]
        if not self._recent_hits[container_id]:
            del self._recent_hits[container_id]

    def get_context_events(self, container_id: str) -> List[str]:
        """Return recent attack vectors for this container (for AI context)."""
        self._prune(container_id, time.time())
        return [vec for (_, vec) in self._recent_hits.get(container_id, [])]
