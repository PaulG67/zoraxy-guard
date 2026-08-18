from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

from .acks import AckStore, DEFAULT_ACK_PATH, normalize_review_id, review_id
from .notify import notify_summary
from .selfcheck import CheckExpectStore
from .alerter import Alerter
from .detectors import Alert, Detector
from .checkurl import build_check_url
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
        "Prüf-ID": review_id(alert.fingerprint) or "—",
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
        "fingerprint": alert.fingerprint,
        "review_id": review_id(alert.fingerprint),
        "acked": False,
        "check_url": build_check_url(origin, path),
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
    acks: AckStore = field(default_factory=lambda: AckStore(DEFAULT_ACK_PATH))
    selfchecks: CheckExpectStore = field(default_factory=CheckExpectStore)

    def request_reload(self) -> None:
        with self.lock:
            self.reload_requested = True

    def request_lists_reload(self) -> None:
        with self.lock:
            self.lists_reload_requested = True

    def set_alerts_muted(self, muted: bool) -> None:
        muted = bool(muted)
        with self.lock:
            alerts = self.cfg.setdefault("alerts", {})
            if not isinstance(alerts, dict):
                alerts = {}
                self.cfg["alerts"] = alerts
            alerts["muted"] = muted
            alt = self.alerter
        if alt is not None:
            alt.set_muted(muted)

    def note_alert(self, alert: Alert) -> None:
        record = build_alert_record(alert, self.threats)
        fp = alert.fingerprint
        if fp:
            self.acks.register_id(
                fp,
                title=alert.title,
                origin=record.get("origin") or "",
                path=record.get("path") or "",
            )
        acked_meta = self.acks.get(fp) if fp else None
        if acked_meta:
            record["acked"] = True
            record["acked_at"] = acked_meta.get("ts")
            record["ack_note"] = acked_meta.get("note") or ""
            if record.get("risk"):
                record["risk"] = dict(record["risk"])
                record["risk"]["action_needed"] = False
                record["risk"]["level"] = "safe"
                record["risk"]["title"] = "Geprüft"
                record["risk"]["detail"] = "Manuell als geprüft markiert."
            if isinstance(record.get("details"), dict):
                record["details"] = dict(record["details"])
                record["details"]["Handlung nötig?"] = "Nein (geprüft)"
                record["details"]["Risiko-Einschätzung"] = "Geprüft"
        else:
            record["acked"] = False
        with self.lock:
            self.alerts_sent += 1
            self.recent_alerts.appendleft(record)

    def mark_alert_acked(self, fingerprint: str) -> bool:
        """Update in-memory recent_alerts after disk ack."""
        found = False
        with self.lock:
            for rec in self.recent_alerts:
                if rec.get("fingerprint") == fingerprint or (
                    rec.get("details") or {}
                ).get("Fingerprint") == fingerprint:
                    rec["acked"] = True
                    rec["acked_at"] = time.time()
                    if rec.get("risk"):
                        rec["risk"] = dict(rec["risk"])
                        rec["risk"]["action_needed"] = False
                        rec["risk"]["level"] = "safe"
                        rec["risk"]["title"] = "Geprüft"
                        rec["risk"]["detail"] = "Manuell als geprüft markiert."
                    if isinstance(rec.get("details"), dict):
                        rec["details"] = dict(rec["details"])
                        rec["details"]["Handlung nötig?"] = "Nein (geprüft)"
                        rec["details"]["Risiko-Einschätzung"] = "Geprüft"
                    found = True
        return found

    def resolve_review_id(self, value: str) -> Optional[dict]:
        """Find fingerprint + meta for a short Prüf-ID (ZG-…)."""
        hit = self.acks.lookup_id(value)
        if hit:
            fp, meta = hit
            return {"fingerprint": fp, **meta, "review_id": review_id(fp)}
        rid = normalize_review_id(value)
        if not rid:
            return None
        with self.lock:
            for rec in self.recent_alerts:
                if (rec.get("review_id") or review_id(rec.get("fingerprint") or "")) == rid:
                    return {
                        "fingerprint": rec.get("fingerprint") or "",
                        "title": rec.get("title") or "",
                        "origin": rec.get("origin") or "",
                        "path": rec.get("path") or "",
                        "review_id": rid,
                    }
        return None

    def is_alert_acked(self, fingerprint: str) -> bool:
        return self.acks.is_acked(fingerprint) if fingerprint else False

    def reviewed_view(
        self,
        *,
        q: str = "",
        origin: str = "",
        path: str = "",
        title: str = "",
        review_id_q: str = "",
    ) -> dict[str, Any]:
        data = self.acks.query(
            q=q, origin=origin, path=path, title=title, review_id_q=review_id_q
        )
        by_fp: dict[str, dict] = {}
        with self.lock:
            for rec in self.recent_alerts:
                fp = rec.get("fingerprint") or ""
                if fp:
                    by_fp[fp] = rec
        for row in data["rows"]:
            rec = by_fp.get(row.get("fingerprint") or "") or {}
            if not row.get("origin"):
                row["origin"] = rec.get("origin") or ""
            if not row.get("path"):
                row["path"] = rec.get("path") or ""
            if not row.get("title"):
                row["title"] = rec.get("title") or ""
            if not row.get("client"):
                row["client"] = rec.get("client") or ""
            row["check_url"] = (
                row.get("check_url")
                or rec.get("check_url")
                or build_check_url(row.get("origin") or "", row.get("path") or "")
            )
            fp = row.get("fingerprint") or ""
            row["kind"] = fp.split(":", 1)[0] if fp else ""
        return data

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
                alerts_cfg = (self.cfg or {}).get("alerts") or {}
                if not isinstance(alerts_cfg, dict):
                    alerts_cfg = {}
                min_sev = str(alerts_cfg.get("min_severity") or "medium")
                notify_label = notify_summary(alerts_cfg)
            except Exception:
                min_sev = "medium"
                notify_label = "nur Handlungsbedarf"
                alerts_cfg = {}

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
                "notify_summary": notify_label,
                "alerts_muted": bool(alerts_cfg.get("muted")),
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
            recent = []
            for rec in list(self.recent_alerts)[:50]:
                r = dict(rec)
                fp = r.get("fingerprint") or ""
                if fp:
                    r.setdefault("review_id", review_id(fp))
                if fp and self.acks.is_acked(fp):
                    r["acked"] = True
                    meta = self.acks.get(fp) or {}
                    r["acked_at"] = meta.get("ts")
                    if r.get("risk"):
                        r["risk"] = dict(r["risk"])
                        r["risk"]["action_needed"] = False
                        r["risk"]["level"] = "safe"
                        r["risk"]["title"] = "Geprüft"
                else:
                    r.setdefault("acked", False)
                recent.append(r)
            open_ids = []
            seen_ids = set()
            for r in recent:
                if r.get("acked"):
                    continue
                rid = r.get("review_id") or review_id(r.get("fingerprint") or "")
                if not rid or rid in seen_ids:
                    continue
                risk = r.get("risk") or {}
                if risk.get("title") == "Geprüft":
                    continue
                seen_ids.add(rid)
                origin = (r.get("origin") or "").strip()
                path = (r.get("path") or "/").strip() or "/"
                title = (r.get("title") or "").strip()
                path_short = path if len(path) <= 42 else path[:39] + "…"
                loc = f"{origin}{path_short}" if origin else title or path_short
                open_ids.append(
                    {
                        "id": rid,
                        "label": f"{rid}  ·  {loc}",
                        "title": title,
                        "origin": origin,
                        "path": path,
                        "severity": r.get("severity") or "",
                    }
                )
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
                "recent_alerts": recent,
                "config_path": self.config_path,
                "history_buffer": self.history.buffer_info(),
                "min_severity": mem["process"]["min_severity"],
                "notify_summary": mem["process"].get("notify_summary") or "",
                "alerts_muted": bool(mem["process"].get("alerts_muted")),
                "acked_count": self.acks.count(),
                "open_review_ids": open_ids,
            }


# Global filled by main
RUNTIME: Optional[Runtime] = None
