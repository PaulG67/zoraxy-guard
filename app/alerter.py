from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import requests

from .detectors import Alert, severity_at_least

log = logging.getLogger("zoraxy-guard.alert")


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