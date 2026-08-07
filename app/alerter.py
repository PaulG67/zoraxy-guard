from __future__ import annotations

import logging
from typing import Any, Dict

import requests

from .detectors import Alert, severity_at_least

log = logging.getLogger("zoraxy-guard.alert")

PUSHOVER_URL = "https://api.pushover.net/1/messages.json"

# Default priority mapping (Pushover: -2 silent … 2 emergency)
SEVERITY_PRIORITY = {
    "info": -1,
    "low": -1,
    "medium": 0,
    "high": 1,
    "critical": 2,
}


class Alerter:
    def __init__(self, cfg: dict, cooldowns: Dict[str, float]):
        a = cfg.get("alerts", {})
        self.min_severity = a.get("min_severity", "medium")
        self.cooldown = int(a.get("cooldown_seconds", 300))
        self.discord = (a.get("discord_webhook") or "").strip()
        self.tg_token = (a.get("telegram_bot_token") or "").strip()
        self.tg_chat = (a.get("telegram_chat_id") or "").strip()
        self.generic = (a.get("generic_webhook") or "").strip()
        self.stdout = bool(a.get("stdout", True))
        self.cooldowns = cooldowns

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

    def send(self, alert: Alert, now: float) -> None:
        if not severity_at_least(alert.severity, self.min_severity):
            return
        if self._cooled(alert.fingerprint, now):
            return

        title = f"[Zoraxy Guard][{alert.severity.upper()}] {alert.title}"
        body = alert.body
        if alert.event and alert.event.raw:
            body = f"{body}\n\nLog: {alert.event.raw[:500]}"

        if self.stdout:
            log.warning("%s | %s", title, body.replace("\n", " | "))

        if self.discord:
            self._discord(title, body, alert.severity)
        if self.tg_token and self.tg_chat:
            self._telegram(title, body)
        if self.po_user and self.po_token:
            self._pushover(title, body, alert.severity)
        if self.generic:
            self._generic(title, body, alert)

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

    def _pushover(self, title: str, body: str, severity: str) -> None:
        priority = self.po_priority_map.get(severity, 0)
        # Keep within Pushover limits
        priority = max(-2, min(2, int(priority)))

        data: Dict[str, Any] = {
            "token": self.po_token,
            "user": self.po_user,
            "title": title[:250],
            "message": body[:1024],
            "priority": priority,
        }
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

    def _generic(self, title: str, body: str, alert: Alert) -> None:
        payload: Dict[str, Any] = {
            "title": title,
            "body": body,
            "severity": alert.severity,
            "fingerprint": alert.fingerprint,
        }
        try:
            r = requests.post(self.generic, json=payload, timeout=10)
            r.raise_for_status()
        except Exception as exc:
            log.error("Generic webhook failed: %s", exc)
