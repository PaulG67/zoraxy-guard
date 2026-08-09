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
from .risk import assess_access


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

    risk = assess_access(
        path=path,
        status=int(status or 0),
        method=method,
        router=router,
        user_agent=ua,
        origin=origin,
        threat_list=threat_list,
    )

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
    summary_bits.append(risk.title)
    summary = " · ".join(summary_bits) if summary_bits else (alert.body or "")[:160]

    details = {
        "Zeit (Alarm)": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "Zeit (Log)": log_ts or "—",
        "Severity": alert.severity,
        "Fingerprint": alert.fingerprint,
        "Risiko-Einschätzung": risk.title,
        "Handlung nötig?": "Ja" if risk.action_needed else "Nein (eher Scanner-Lärm / unbedenklich)",
        "Bewertung": risk.detail,
        "Risiko-Level": risk.level,
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
        "risk": risk.as_dict(),
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

    def memory_state(self) -> dict[str, Any]:
        """
        Single source of truth for Memory (History ring) + process analysis clocks.
        Used by Status and History tabs so both show the same numbers.
        """
        with self.lock:
            now = time.time()
            hb = self.history.buffer_info()
            backfill = dict(self.backfill)
            started = self.started_at
            last_line = self.last_line_at or 0.0
            lines = self.lines_processed
            alerts_sent = self.alerts_sent
            watching = self.watching
            try:
                min_sev = str((self.cfg or {}).get("alerts", {}) or {}).get("min_severity") or "medium"
            except Exception:
                min_sev = "medium"

        age_line = (now - last_line) if last_line else None
        if last_line and age_line is not None and age_line < 120:
            analysis_state = "live"
            analysis_label = "Live — Logs werden gelesen"
        elif last_line and age_line is not None and age_line < 900:
            analysis_state = "quiet"
            analysis_label = "Ruhig — keine neuen Zeilen seit ein paar Minuten"
        elif last_line:
            analysis_state = "stale"
            analysis_label = "Stille — lange keine neuen Log-Zeilen"
        elif lines == 0:
            analysis_state = "waiting"
            analysis_label = "Wartend — noch keine Log-Zeilen in dieser Laufzeit"
        else:
            analysis_state = "idle"
            analysis_label = "Kein aktueller Traffic"

        fill = hb.get("fill_mode") or "live"
        fill_label = {
            "live": "Live-Tail (nur neue Logs seit Session)",
            "backfill": "Disk-Nachladen",
            "backfill+live": "Disk-Nachladen + Live-Tail",
        }.get(fill, fill)

        size = int(hb.get("size") or 0)
        if size == 0:
            mem_label = "Memory-Ring leer (gleiche Quelle für Status & History)"
        else:
            mem_label = f"{size} Requests im gemeinsamen Memory-Ring"

        return {
            "now": now,
            "analysis_state": analysis_state,
            "analysis_label": analysis_label,
            "process": {
                "started_at": started,
                "uptime_sec": max(0, int(now - started)),
                "lines_processed": lines,
                "last_line_at": last_line,
                "alerts_sent": alerts_sent,
                "min_severity": min_sev,
                "watching": watching,
            },
            "memory": {
                "size": size,
                "max": hb.get("max"),
                "oldest_ts": hb.get("oldest_ts") or 0,
                "newest_ts": hb.get("newest_ts") or 0,
                "session_started_at": hb.get("session_started_at") or started,
                "session_generation": hb.get("session_generation") or 1,
                "session_recorded": hb.get("session_recorded") or 0,
                "recorded_total": hb.get("recorded_total") or 0,
                "retention_hours": hb.get("retention_hours") or 24,
                "fill_mode": fill,
                "fill_label": fill_label,
                "label": mem_label,
                "shared": True,
                "note": (
                    "Status und History nutzen denselben Access-History-Ring im RAM. "
                    "Alarme sind eine separate Liste (nur bei Severity-Schwelle)."
                ),
            },
            "backfill": backfill,
        }

    def snapshot(self) -> dict[str, Any]:
        mem = self.memory_state()
        with self.lock:
            sources = {}
            net_count = 0
            if self.threats:
                sources = dict(self.threats.sources)
                net_count = len(self.threats.block_nets)
            return {
                **mem,
                "started_at": mem["process"]["started_at"],
                "uptime_sec": mem["process"]["uptime_sec"],
                "lines_processed": mem["process"]["lines_processed"],
                "alerts_sent": mem["process"]["alerts_sent"],
                "last_line_at": mem["process"]["last_line_at"],
                "last_reload_at": self.last_reload_at,
                "last_error": self.last_error,
                "watching": self.watching,
                "log_files": list(self.log_files),
                "threat_sources": sources,
                "threat_networks": net_count,
                "recent_alerts": list(self.recent_alerts)[:50],
                "config_path": self.config_path,
                "history_buffer": self.history.buffer_info(),
                "min_severity": mem["process"]["min_severity"],
            }


# Global filled by main
RUNTIME: Optional[Runtime] = None
