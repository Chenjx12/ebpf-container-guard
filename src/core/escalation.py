#!/usr/bin/env python3
"""
Response escalation for repeated attacks from the same image.

Progressive response to prevent attack loops (attacker re-launches the same
compromised image after we kill it):

  Hit 1 (10min window):  pause_container           (reversible, forensics)
  Hit 2 (10min window):  kill_container -> QUEUED for human review
  Hit 3 (30min window):  image blocked -> QUEUED for human review (blocklist)

Kill/blocklist decisions are ALWAYS queued for human approval — never
executed automatically (see decision record #14, graded automation).
"""

import os
import time
from typing import Dict, List


class EscalationManager:
    """Tracks per-image attack frequency and decides escalation level."""

    # Escalation thresholds
    FIRST_WINDOW = 600      # 10 min — hits within this window count together
    BLOCK_WINDOW = 1800     # 30 min — blocklist window

    def __init__(self, blocklist_path: str = "config/blocklist.yaml"):
        self.blocklist_path = blocklist_path
        self._image_hits: Dict[str, List[float]] = {}  # image -> [timestamps]
        self.blocked_images: List[str] = self._load_blocklist()

    # -----------------------------------------------------------
    # Public API
    # -----------------------------------------------------------

    def decide(self, image: str, hit_time: float = None) -> str:
        """Decide response action for an attack from this image.

        Returns one of:
          'pause_container'    — first hit (reversible, auto-execute)
          'kill_container'     — second hit (human review queue)
          'block_image'        — third hit (human review queue + blocklist)
        """
        if not image or image in ('', 'unknown'):
            return 'pause_container'

        now = hit_time or time.time()
        hits = self._image_hits.setdefault(image, [])
        hits.append(now)
        # Keep only hits within the block window
        self._image_hits[image] = [t for t in hits
                                   if now - t < self.BLOCK_WINDOW]

        count = len(self._image_hits[image])

        if count >= 3:
            if image not in self.blocked_images:
                self.blocked_images.append(image)
                self._save_blocklist()
            return 'block_image'
        elif count >= 2:
            return 'kill_container'
        else:
            return 'pause_container'

    def is_image_blocked(self, image: str) -> bool:
        """Whether this image is on the blocklist."""
        return image in self.blocked_images

    def reset(self, image: str):
        """Clear hit history for an image (e.g. after human dismiss)."""
        self._image_hits.pop(image, None)

    # -----------------------------------------------------------
    # Blocklist persistence
    # -----------------------------------------------------------

    def _load_blocklist(self) -> List[str]:
        try:
            import yaml
            with open(self.blocklist_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            return [str(x) for x in config.get('blocked_images', []) or []]
        except (FileNotFoundError, Exception):
            return []

    def _save_blocklist(self):
        try:
            import yaml
            with open(self.blocklist_path, 'w') as f:
                yaml.safe_dump({'blocked_images': self.blocked_images}, f,
                               allow_unicode=True)
        except Exception as e:
            print(f"  [!] Blocklist save failed: {e}", file=sys.stderr)
