"""Which detector alerts are pushed to Pushover / Discord / Telegram."""

from __future__ import annotations

from typing import Any, Optional

from .detectors import Alert, severity_at_least
from .risk import assess_access

# id, label, hint
NOTIFY_KINDS: list[tuple[str, str, str]] = [
    ("exploit_success", "Exploit-Pfad mit Erfolg (HTTP 2xx)", "Verdächtiger Pfad hat Inhalt geliefert — prüfen."),
    ("exploit_scan", "Exploit-Scan (wiederholt)", "Mehrere Probe-Pfade in kurzer Zeit."),
    ("exploit_probe", "Einzelne Exploit-Probe", "Ein abgewiesener Scan-Versuch."),
    ("blocklist", "Bekannte schlechte IP", "Treffer in Threat-Liste oder Blocklist."),
    ("block_rate", "Hohe Block-Rate (403)", "Viele geblockte Requests von einer IP."),
    ("brute_force", "Brute-Force auf sensible Hosts", "Viele 401/403 auf markierte Hosts."),
    ("bad_ua", "Verdächtiger User-Agent", "Scanner-UA (nuclei, sqlmap, …)."),
    ("sensitive_ok", "Zugriff auf sensible Hosts (Erfolg)", "HTTP 2xx/3xx auf markierte Hosts."),
]

DEFAULT_NOTIFY_KINDS = [k[0] for k in NOTIFY_KINDS]
NOTIFY_MODES = ("action", "action_watch", "severity")
BLOCKED_STATUSES = frozenset({401, 403, 429, 451})
BLOCKED_ROUTERS = frozenset({"blacklist", "whitelist"})

NOTIFY_MODE_LABELS = {
    "action": "nur Handlungsbedarf",
    "action_watch": "Handlung + Beobachten",
    "severity": "nach Mindest-Severity",
}


def normalize_mode(value: Any) -> str:
    mode = str(value or "action").strip().lower()
    return mode if mode in NOTIFY_MODES else "action"


def enabled_kinds(alerts_cfg: dict) -> set[str]:
    raw = alerts_cfg.get("notify_kinds")
    if raw is None:
        return set(DEFAULT_NOTIFY_KINDS)
    if isinstance(raw, str):
        items = [x.strip() for x in raw.replace(";", ",").split(",")]
    elif isinstance(raw, (list, tuple, set)):
        items = [str(x).strip() for x in raw]
    else:
        return set(DEFAULT_NOTIFY_KINDS)
    return {x for x in items if x}


def is_blocked_event(event: Any) -> bool:
    if not event:
        return False
    status = getattr(event, "status", 0) or 0
    router = (getattr(event, "router", "") or "").lower()
    if status in BLOCKED_STATUSES:
        return True
    if router in BLOCKED_ROUTERS:
        return True
    return False


def _risk_for_alert(alert: Alert):
    ev = alert.event
    if not ev:
        return None
    extra = []
    return assess_access(
        path=ev.path or "/",
        status=int(ev.status or 0),
        method=ev.method or "GET",
        router=ev.router or "",
        user_agent=ev.user_agent or "",
        origin=ev.origin or "",
        extra_exploit_paths=extra,
    )


def notify_summary(alerts_cfg: Optional[dict] = None) -> str:
    cfg = alerts_cfg or {}
    mode = normalize_mode(cfg.get("notify_mode"))
    label = NOTIFY_MODE_LABELS.get(mode, NOTIFY_MODE_LABELS["action"])
    if mode == "severity":
        label = f"ab {cfg.get('min_severity') or 'medium'}"
    extras = []
    if cfg.get("notify_skip_acked", True):
        extras.append("geprüft aus")
    if cfg.get("notify_skip_blocked", True):
        extras.append("403 aus")
    try:
        window = int(cfg.get("digest_window_seconds", 180) or 0)
    except (TypeError, ValueError):
        window = 180
    if window > 0:
        if window >= 60:
            extras.append(f"Sammel {max(1, round(window / 60))} min")
        else:
            extras.append(f"Sammel {window}s")
    if extras:
        return f"{label} · {', '.join(extras)}"
    return label


def should_notify(alert: Alert, alerts_cfg: Optional[dict] = None, *, acked: bool = False) -> bool:
    """
    True if this alert should go out on push channels.
    Test alerts (kind=test) still obey force= in Alerter.send, not this helper.
    """
    cfg = alerts_cfg or {}
    kind = (getattr(alert, "kind", None) or "").strip() or "other"
    if kind == "test":
        return True

    if acked and bool(cfg.get("notify_skip_acked", True)):
        return False

    kinds = enabled_kinds(cfg)
    if kind not in kinds:
        return False

    min_sev = str(cfg.get("min_severity") or "medium")
    if not severity_at_least(alert.severity, min_sev):
        return False

    risk = _risk_for_alert(alert)
    action_needed = bool(risk.action_needed) if risk else False
    level = (risk.level if risk else "") or ""

    if bool(cfg.get("notify_skip_blocked", True)) and is_blocked_event(alert.event) and not action_needed:
        return False

    mode = normalize_mode(cfg.get("notify_mode"))
    if mode == "severity":
        return True
    if mode == "action_watch":
        return action_needed or level == "watch"
    return action_needed
