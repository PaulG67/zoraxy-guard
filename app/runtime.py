from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

from .alerter import Alerter
from .detectors import Alert, Detector
from .feeds import ThreatLists, find_list_match
from .history import AccessHistory, DEFAULT_MAX_EVENTS
from .geoip import GeoCache
from .iputil import parse_ip
from .parser import LogEvent


def _ip_class(ip_str: str) -> str:
    ip = parse_ip(ip_str or "")
    if not ip:
        return "unbekannt"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "privates LAN / RFC1918"
    if ip.is_link_local:
        return "link-local"
    if getattr(ip, "is_global", None) is False:
        return "nicht-global"
    return "öffentliches Internet"


def _origin_kind(origin: str) -> str:
    o = (origin or "").strip()
    if not o:
        return "unbekannt / Default-Site"
    if parse_ip(o):
        return "IP als Origin (Log)"
    if "." in o:
        return "Hostname / Proxy-Host"
    return "Origin"


def build_alert_record(alert: Alert, threats: Optional[ThreatLists] = None) -> dict:
    """Rich structure for UI + expandable details."""
    ev: Optional[LogEvent] = alert.event
    client = (ev.client if ev else "") or ""
    origin = (ev.origin if ev else "") or ""
    path = (ev.path if ev else "") or ""
    method = (ev.method if ev else "") or ""
    status = int(ev.status) if ev and ev.status else None
    router = (ev.router if ev else "") or ""
    ua = (ev.user_agent if ev else "") or ""
    raw = (ev.raw if ev else "") or ""
    log_ts = None
    if ev and ev.timestamp:
        log_ts = ev.timestamp.isoformat(sep=" ", timespec="seconds")

    client_ip_obj = parse_ip(client)
    client_version = f"IPv{client_ip_obj.version}" if client_ip_obj else "—"
    threat_list = find_list_match(str(client_ip_obj), threats) if threats and client_ip_obj else None
    if not threat_list and threats and client:
        threat_list = find_list_match(client.split("%")[0], threats)

    # short summary line for table
    summary_bits = []
    if client:
        summary_bits.append(f"von {client}")
    if origin:
        summary_bits.append(f"→ {origin}")
    if method and path:
        summary_bits.append(f"{method} {path[:80]}")
    if status is not None:
        summary_bits.append(f"HTTP {status}")
    summary = " · ".join(summary_bits) if summary_bits else (alert.body or "")[:160]

    details = {
        "Zeit (Alarm)": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "Zeit (Log)": log_ts or "—",
        "Severity": alert.severity,
        "Fingerprint": alert.fingerprint,
        "Quell-IP (Client)": client or "—",
        "Quell-IP-Klasse": _ip_class(client),
        "IP-Version": client_version,
        "Ziel-Host (Origin / App-URL)": origin or "—",
        "Ziel-Art": _origin_kind(origin),
        "HTTP-Methode": method or "—",
        "Pfad": path or "—",
        "HTTP-Status": status if status is not None else "—",
        "Zoraxy-Router": router or "—",
        "User-Agent": ua or "—",
        "Threat-Liste (Treffer)": threat_list or "—",
        "Nachricht": alert.body or "—",
        "Log-Zeile": raw[:900] if raw else "—",
    }

    return {
        "ts": time.time(),
        "severity": alert.severity,
        "title": alert.title,
        "body": (alert.body or "")[:800],
        "summary": summary,
        "client": client,
        "origin": origin,
        "method": method,
        "path": path,
        "status": status,
        "router": router,
        "user_agent": ua,
        "threat_list": threat_list,
        "client_class": _ip_class(client),
        "details": details,
        "raw": raw[:900],
    }


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
    history: AccessHistory = field(
        default_factory=lambda: AccessHistory(max_events=DEFAULT_MAX_EVENTS)
    )
    geo: GeoCache = field(default_factory=GeoCache)
    reload_requested: bool = False
    lists_reload_requested: bool = False
    # On-demand disk → history memory (no alerts)
    backfill: dict = field(
        default_factory=lambda: {
            "running": False,
            "hours": 0,
            "started_at": 0.0,
            "finished_at": 0.0,
            "files": 0,
            "lines_read": 0,
            "lines_loaded": 0,
            "lines_skipped_old": 0,
            "error": "",
            "message": "",
        }
    )

    def request_reload(self) -> None:
        with self.lock:
            self.reload_requested = True

    def request_lists_reload(self) -> None:
        with self.lock:
            self.lists_reload_requested = True

    def note_alert(self, alert: Alert) -> None:
        record = build_alert_record(alert, self.threats)
        with self.lock:
            self.alerts_sent += 1
            self.recent_alerts.appendleft(record)

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
                "history_buffer": self.history.buffer_info(),
                "backfill": dict(self.backfill),
            }


# Global filled by main
RUNTIME: Optional[Runtime] = None
