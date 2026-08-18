from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

from .acks import review_id
from .checkurl import build_check_url
from .detectors import SEVERITY_RANK, Alert
from .notify import NOTIFY_KINDS, should_notify
from .selfcheck import append_check_marker

log = logging.getLogger("zoraxy-guard.alert")

PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
PUSHOVER_BODY_LIMIT = 1024

# Default priority mapping (Pushover: -2 silent … 2 emergency)
SEVERITY_PRIORITY = {
    "info": -1,
    "low": -1,
    "medium": 0,
    "high": 1,
    "critical": 2,
}

KIND_LABELS = {kid: label for kid, label, _hint in NOTIFY_KINDS}

DEFAULT_DIGEST_WINDOW = 180
DEFAULT_DIGEST_IDLE = 15
DEFAULT_DIGEST_MAX_ITEMS = 40


def _cfg_int(src: dict, key: str, default: int, *, lo: int = 0, hi: int = 86400) -> int:
    try:
        value = int(src.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value))


def _span_label(seconds: float) -> str:
    sec = max(1, int(round(float(seconds))))
    if sec < 90:
        return f"{sec} s"
    mins = max(1, int(round(sec / 60.0)))
    return f"{mins} min"


def _join_limited(values: List[str], max_n: int = 5) -> str:
    shown = values[:max_n]
    extra = len(values) - len(shown)
    text = ", ".join(shown)
    if extra > 0:
        text += f" (+{extra})"
    return text


@dataclass
class PushPayload:
    ts: float
    severity: str
    title: str
    body: str
    check_url: str
    fingerprint: str
    kind: str
    origin: str
    path: str
    review_id: str
    alert: Alert


def format_digest(
    items: List[PushPayload], *, limit: int = PUSHOVER_BODY_LIMIT
) -> Tuple[str, str, str, str]:
    """One bundled push: title, body, highest severity, best check URL."""
    n = len(items)
    if n == 1:
        it = items[0]
        return it.title, it.body, it.severity, it.check_url

    sevs = [it.severity for it in items]
    top = max(sevs, key=lambda s: SEVERITY_RANK.get(s, 0))
    span = _span_label(items[-1].ts - items[0].ts)
    title = f"[Zoraxy Guard][{top.upper()}] {n} Alarme in {span}"

    kind_counts: Dict[str, int] = {}
    origins: List[str] = []
    paths: List[str] = []
    seen_o: set[str] = set()
    seen_p: set[str] = set()
    for it in items:
        k = it.kind or "other"
        kind_counts[k] = kind_counts.get(k, 0) + 1
        if it.origin and it.origin not in seen_o:
            seen_o.add(it.origin)
            origins.append(it.origin)
        if it.path and it.path not in seen_p:
            seen_p.add(it.path)
            paths.append(it.path)

    kind_lines = []
    for k, c in sorted(kind_counts.items(), key=lambda kv: -kv[1]):
        kind_lines.append(f"• {c}× {KIND_LABELS.get(k, k)}")

    header_parts = [
        f"{n} Meldungen gebündelt — höchste Stufe {top.upper()}",
        "",
        "Arten:",
        *kind_lines,
    ]
    if origins:
        header_parts += ["", "Hosts: " + _join_limited(origins)]
    if paths:
        header_parts += ["Pfade: " + _join_limited(paths)]
    header_parts += ["", "Auszug:"]
    header = "\n".join(header_parts) + "\n"

    ranked = sorted(items, key=lambda it: -SEVERITY_RANK.get(it.severity, 0))
    excerpt: List[str] = []
    leftover = n
    for it in ranked:
        bit = f"• [{it.severity.upper()}] {it.title}"
        loc = " ".join(x for x in (it.origin, it.path) if x)
        if loc:
            bit += f" — {loc}"
        if it.review_id:
            bit += f" ({it.review_id})"
        more_after = leftover - 1
        footer = f"\n(+{more_after} weitere in History)" if more_after > 0 else ""
        trial = header + "\n".join(excerpt + [bit])
        if len(trial) + len(footer) > limit:
            break
        excerpt.append(bit)
        leftover -= 1

    body = header + "\n".join(excerpt)
    if leftover > 0:
        footer = f"\n(+{leftover} weitere in History)"
        if len(body) + len(footer) <= limit:
            body += footer
        else:
            body = body[: max(0, limit - len(footer))] + footer
    if len(body) > limit:
        body = body[:limit]

    check_url = ""
    for it in ranked:
        if it.check_url:
            check_url = it.check_url
            break
    return title[:250], body, top, check_url


class Alerter:
    def __init__(self, cfg: dict, cooldowns: Dict[str, float]):
        a = cfg.get("alerts", {})
        if not isinstance(a, dict):
            a = {}
        self.alerts_cfg = a
        self.min_severity = a.get("min_severity", "medium")
        self.cooldown = int(a.get("cooldown_seconds", 300))
        self.discord = (a.get("discord_webhook") or "").strip()
        self.tg_token = (a.get("telegram_bot_token") or "").strip()
        self.tg_chat = (a.get("telegram_chat_id") or "").strip()
        self.generic = (a.get("generic_webhook") or "").strip()
        self.stdout = bool(a.get("stdout", True))
        self.cooldowns = cooldowns

        self.digest_window = _cfg_int(a, "digest_window_seconds", DEFAULT_DIGEST_WINDOW, hi=3600)
        self.digest_idle = _cfg_int(a, "digest_idle_seconds", DEFAULT_DIGEST_IDLE, hi=600)
        self.digest_max_items = _cfg_int(a, "digest_max_items", DEFAULT_DIGEST_MAX_ITEMS, lo=2, hi=200)
        self._pending: List[PushPayload] = []
        self._digest_lock = threading.Lock()

        po = a.get("pushover") or {}
        if not isinstance(po, dict):
            po = {}
        # Flat keys as fallback (handy for Unraid templates)
        self.po_user = (po.get("user_key") or a.get("pushover_user_key") or "").strip()
        self.po_token = (po.get("api_token") or a.get("pushover_api_token") or "").strip()
        self.po_device = (po.get("device") or a.get("pushover_device") or "").strip()
        self.po_sound = (po.get("sound") or a.get("pushover_sound") or "").strip()
        self.po_priority_map = dict(SEVERITY_PRIORITY)
        custom_map = po.get("priority_by_severity") or {}
        if isinstance(custom_map, dict):
            for k, v in custom_map.items():
                try:
                    self.po_priority_map[str(k).lower()] = int(v)
                except (TypeError, ValueError):
                    continue
        # Emergency priority requires retry/expire (seconds)
        self.po_retry = int(po.get("retry") or 60)
        self.po_expire = int(po.get("expire") or 600)
        self.po_html = bool(po.get("html", False))

    def _cooled(self, fingerprint: str, now: float) -> bool:
        last = self.cooldowns.get(fingerprint, 0)
        if now - last < self.cooldown:
            return True
        self.cooldowns[fingerprint] = now
        return False

    def _build_payload(self, alert: Alert, now: float) -> PushPayload:
        title = f"[Zoraxy Guard][{alert.severity.upper()}] {alert.title}"
        body = alert.body
        if alert.event and alert.event.raw:
            body = f"{body}\n\nLog: {alert.event.raw[:500]}"

        check_url = ""
        rid = review_id(alert.fingerprint)
        origin = ""
        path = ""
        if alert.event:
            origin = (alert.event.origin or "").strip()
            path = (alert.event.path or "").strip()
            check_url = append_check_marker(build_check_url(origin, path))
            if rid and check_url:
                sep = "&" if "?" in check_url else "?"
                check_url = f"{check_url}{sep}_zgid={rid[3:] if rid.startswith('ZG-') else rid}"

        extra_bits = []
        if rid:
            extra_bits.append(f"ID: {rid}")
        if check_url:
            extra_bits.append(f"Prüfen: {check_url}")
        if extra_bits:
            suffix = "\n\n" + "\n".join(extra_bits)
            if len(body) + len(suffix) <= PUSHOVER_BODY_LIMIT:
                body = body + suffix
            else:
                body = body[: max(0, PUSHOVER_BODY_LIMIT - len(suffix))] + suffix

        return PushPayload(
            ts=now,
            severity=alert.severity,
            title=title,
            body=body,
            check_url=check_url,
            fingerprint=alert.fingerprint,
            kind=(alert.kind or "").strip(),
            origin=origin,
            path=path,
            review_id=rid,
            alert=alert,
        )

    def send(self, alert: Alert, now: float, *, force: bool = False, acked: bool = False) -> bool:
        if not force:
            if not should_notify(alert, self.alerts_cfg, acked=acked):
                return False
            if self._cooled(alert.fingerprint, now):
                return False

        payload = self._build_payload(alert, now)

        if self.stdout:
            log.warning("%s | %s", payload.title, payload.body.replace("\n", " | "))

        if force or self.digest_window <= 0:
            self._dispatch(payload.title, payload.body, payload.severity, payload.check_url, payload.alert)
            return True

        with self._digest_lock:
            self._pending.append(payload)
            overflow = len(self._pending) >= self.digest_max_items
        if overflow:
            self.flush()
        return True

    def flush_due(self, now: float) -> None:
        """Send queued pushes after idle pause or max window. Call from the main loop."""
        if self.digest_window <= 0:
            return
        with self._digest_lock:
            if not self._pending:
                return
            first_ts = self._pending[0].ts
            last_ts = self._pending[-1].ts
            idle = self.digest_idle if self.digest_idle > 0 else 1
            due = (
                now - first_ts >= self.digest_window
                or now - last_ts >= idle
                or len(self._pending) >= self.digest_max_items
            )
            if not due:
                return
            batch = self._pending
            self._pending = []
        self._send_batch(batch)

    def flush(self) -> None:
        """Force-send anything still queued (config reload / overflow)."""
        with self._digest_lock:
            if not self._pending:
                return
            batch = self._pending
            self._pending = []
        self._send_batch(batch)

    def _send_batch(self, batch: List[PushPayload]) -> None:
        if not batch:
            return
        if len(batch) == 1:
            it = batch[0]
            self._dispatch(it.title, it.body, it.severity, it.check_url, it.alert)
            return
        title, body, severity, check_url = format_digest(batch)
        log.info("Push-Sammelmeldung: %s Alarme → %s", len(batch), title)
        self._dispatch(title, body, severity, check_url, batch[0].alert, digest_count=len(batch))

    def _dispatch(
        self,
        title: str,
        body: str,
        severity: str,
        check_url: str,
        alert: Alert,
        *,
        digest_count: int = 0,
    ) -> None:
        if self.discord:
            self._discord(title, body, severity)
        if self.tg_token and self.tg_chat:
            self._telegram(title, body)
        if self.po_user and self.po_token:
            self._pushover(title, body, severity, check_url)
        if self.generic:
            self._generic(title, body, alert, severity=severity, digest_count=digest_count)

    def _discord(self, title: str, body: str, severity: str) -> None:
        color = {
            "info": 0x808080,
            "low": 0x3498DB,
            "medium": 0xF1C40F,
            "high": 0xE67E22,
            "critical": 0xE74C3C,
        }.get(severity, 0xE67E22)
        payload = {
            "embeds": [
                {
                    "title": title[:256],
                    "description": body[:3900],
                    "color": color,
                }
            ]
        }
        try:
            r = requests.post(self.discord, json=payload, timeout=10)
            r.raise_for_status()
        except Exception as exc:
            log.error("Discord webhook failed: %s", exc)

    def _telegram(self, title: str, body: str) -> None:
        text = f"*{title}*\n{body}"[:4000]
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        try:
            r = requests.post(
                url,
                json={"chat_id": self.tg_chat, "text": text, "parse_mode": "Markdown"},
                timeout=10,
            )
            r.raise_for_status()
        except Exception as exc:
            log.error("Telegram send failed: %s", exc)

    def _pushover(self, title: str, body: str, severity: str, check_url: str = "") -> None:
        priority = self.po_priority_map.get(severity, 0)
        # Keep within Pushover limits
        priority = max(-2, min(2, int(priority)))

        message = body[:PUSHOVER_BODY_LIMIT]

        data: Dict[str, Any] = {
            "token": self.po_token,
            "user": self.po_user,
            "title": title[:250],
            "message": message,
            "priority": priority,
        }
        if check_url:
            data["url"] = check_url[:512]
            data["url_title"] = "Prüfen"
        if self.po_device:
            data["device"] = self.po_device
        if self.po_sound:
            data["sound"] = self.po_sound
        if self.po_html:
            data["html"] = 1
        if priority == 2:
            # Emergency: retry at least every 30s, expire max 10800
            data["retry"] = max(30, self.po_retry)
            data["expire"] = max(self.po_retry, min(10800, self.po_expire))

        try:
            r = requests.post(PUSHOVER_URL, data=data, timeout=15)
            if r.status_code >= 400:
                log.error("Pushover failed (%s): %s", r.status_code, r.text[:300])
            else:
                log.info("Pushover sent (priority=%s)", priority)
        except Exception as exc:
            log.error("Pushover send failed: %s", exc)

    def _generic(
        self,
        title: str,
        body: str,
        alert: Alert,
        *,
        severity: str,
        digest_count: int = 0,
    ) -> None:
        payload: Dict[str, Any] = {
            "title": title,
            "body": body,
            "severity": severity,
            "fingerprint": alert.fingerprint,
        }
        if digest_count:
            payload["digest"] = True
            payload["count"] = digest_count
        try:
            r = requests.post(self.generic, json=payload, timeout=10)
            r.raise_for_status()
        except Exception as exc:
            log.error("Generic webhook failed: %s", exc)
