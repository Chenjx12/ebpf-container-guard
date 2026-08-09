#!/usr/bin/env python3
"""
Container monitoring scope — include/exclude filtering.

Decides which containers the detection pipeline monitors:
  - include non-empty → monitor ONLY listed containers (whitelist mode)
  - include empty     → monitor all containers (exclude still applies)
  - exclude match     → always skip (takes priority over include)
  - fnmatch wildcards supported (e.g. "app-*", "test-*")
"""

import fnmatch
from typing import List, Optional


class ContainerScope:
    """Configurable container monitoring scope."""

    def __init__(self, config_path: str = "config/monitor.yaml"):
        self.config_path = config_path
        self.include: List[str] = []
        self.exclude: List[str] = []
        self.match_by: str = "name"  # 'name' or 'id'

        self._load()

        n_inc = len(self.include)
        n_exc = len(self.exclude)
        if n_inc or n_exc:
            print(f"  [Scope] include={n_inc} exclude={n_exc} "
                  f"match_by={self.match_by}")
            if n_inc:
                print(f"    include: {', '.join(self.include)}")
            if n_exc:
                print(f"    exclude: {', '.join(self.exclude)}")
        else:
            print("  [Scope] monitoring all containers (no filters)")

    def _load(self):
        """Load include/exclude lists from YAML config."""
        try:
            import yaml
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            self.include = [str(x) for x in config.get('include', []) or []]
            self.exclude = [str(x) for x in config.get('exclude', []) or []]
            mb = config.get('match_by', 'name')
            self.match_by = mb if mb in ('name', 'id') else 'name'
        except FileNotFoundError:
            # No config file → monitor everything (default behavior)
            self.include, self.exclude = [], []
        except Exception as e:
            print(f"  [!] Scope config load failed ({e}), "
                  f"monitoring all containers")
            self.include, self.exclude = [], []

    def should_monitor(self, container_id: str,
                       container_name: str = "") -> bool:
        """Decide whether to monitor this container.

        Args:
            container_id: Container short ID (12 chars) or 'host'.
            container_name: Container name (used when match_by=name).

        Returns:
            True if the container should be monitored, False to skip.
        """
        # Host processes are always filtered out downstream; treat as in-scope
        if container_id in ('host', '', 'unknown'):
            return True

        # Pick the match target per match_by setting
        target = container_name or container_id
        if self.match_by == 'id':
            target = container_id

        # Exclude takes priority over include
        for pattern in self.exclude:
            if fnmatch.fnmatch(target, pattern) or \
               fnmatch.fnmatch(container_id, pattern):
                return False

        # Include non-empty → whitelist mode
        if self.include:
            for pattern in self.include:
                if fnmatch.fnmatch(target, pattern) or \
                   fnmatch.fnmatch(container_id, pattern):
                    return True
            return False

        return True

    def is_scoped(self) -> bool:
        """Whether any filter rules are active (for dashboard display)."""
        return bool(self.include or self.exclude)

    def describe(self) -> str:
        """Human-readable scope description."""
        if self.include:
            return f"whitelist ({', '.join(self.include)})"
        if self.exclude:
            return f"all except ({', '.join(self.exclude)})"
        return "all containers"
