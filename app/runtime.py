from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

from .alerter import Alerter
from .detectors import Detector
from .feeds import ThreatLists


@dataclass
class Runtime:
    """Shared state between monitor loop and web UI."""

    config_path: str
    cfg: dict
    threats: Optional[ThreatLists] = None
    detector: Optional[Detector] = None
    alerter: Optional[Alerter] = None
    cooldowns: Dict[str, float] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)

    started_at: float = field(default_factory=time.time)
    lines_processed: int = 0
    alerts_sent: int = 0
    last_line_at: float = 0.0
    last_reload_at: float = 0.0
    last_error: str = ""
    watching: str = ""
    log_files: List[str] = field(default_factory=list)

    recent_alerts: Deque[dict] = field(default_factory=lambda: deque(maxlen=100))
    reload_requested: bool = False
    lists_reload_requested: bool = False

    def request_reload(self) -> None:
        with self.lock:
            self.reload_requested = True

    def request_lists_reload(self) -> None:
        with self.lock:
            self.lists_reload_requested = True

    def note_alert(self, severity: str, title: str, body: str) -> None:
        with self.lock:
            self.alerts_sent += 1
            self.recent_alerts.appendleft(
                {
                    "ts": time.time(),
                    "severity": severity,
                    "title": title,
                    "body": body[:800],
                }
            )

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            sources = {}
            net_count = 0
            if self.threats:
                sources = dict(self.threats.sources)
                net_count = len(self.threats.block_nets)
            return {
                "started_at": self.started_at,
                "lines_processed": self.lines_processed,
                "alerts_sent": self.alerts_sent,
                "last_line_at": self.last_line_at,
                "last_reload_at": self.last_reload_at,
                "last_error": self.last_error,
                "watching": self.watching,
                "log_files": list(self.log_files),
                "threat_sources": sources,
                "threat_networks": net_count,
                "recent_alerts": list(self.recent_alerts)[:50],
                "config_path": self.config_path,
            }


# Global filled by main
RUNTIME: Optional[Runtime] = None
