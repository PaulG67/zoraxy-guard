"""Parse CrowdSec bouncer lines from Zoraxy plugin-manager logs."""

from __future__ import annotations

import re
from typing import Optional

from .parser import LogEvent

# Plugin stdout is wrapped as:
# [ts] [plugin-manager] [system:info] [Crowdsec Bouncer Plugin for Zoraxy:7811] Request blocked: /x
RE_PLUGIN_TAG = re.compile(r"crowd\s*sec", re.I)
RE_LOGRUS_MSG = re.compile(r'\bmsg="([^"]*)"', re.I)
RE_DECISION = re.compile(
    r"Decision found for IP:\s*([0-9a-fA-F:.]+)",
    re.I,
)
RE_NO_DECISION = re.compile(r"No decision found for IP:", re.I)
RE_BLOCKED = re.compile(r"Request blocked:\s*(\S+)", re.I)
RE_SNIFF = re.compile(r"Request captured by dynamic sniff", re.I)

CORRELATE_SEC = 3.0


def _payload(message: str) -> str:
    raw = (message or "").strip()
    m = RE_LOGRUS_MSG.search(raw)
    if m:
        raw = m.group(1)
    raw = re.sub(r"^\[[^\]]+\]\s*", "", raw)
    return raw.strip()


def is_crowdsec_plugin_line(event: LogEvent) -> bool:
    if event.kind != "internal":
        return False
    blob = f"{event.component} {event.message}"
    return bool(RE_PLUGIN_TAG.search(blob))


def is_crowdsec_access(event: LogEvent) -> bool:
    router = (event.router or "").lower()
    return "crowdsec" in router


class CrowdSecLogState:
    """Turn plugin-manager lines into synthetic request events (HTTP 403)."""

    def __init__(self) -> None:
        self.last_decision_ip = ""
        self.last_decision_ts: Optional[float] = None
        self.seen_plugin = False
        self.lines_seen = 0
        self.blocks_parsed = 0

    def ingest(self, event: LogEvent) -> Optional[LogEvent]:
        if is_crowdsec_access(event) and event.kind == "request":
            return None  # already a request; history records it as-is
        if not is_crowdsec_plugin_line(event):
            return None
        self.seen_plugin = True
        self.lines_seen += 1
        text = _payload(event.message or "")
        if RE_SNIFF.search(text) or RE_NO_DECISION.search(text):
            return None

        ts = None
        if event.timestamp is not None:
            try:
                ts = event.timestamp.timestamp()
            except (OSError, OverflowError, ValueError):
                ts = None

        m_dec = RE_DECISION.search(text)
        if m_dec:
            self.last_decision_ip = m_dec.group(1).rstrip(".,;")
            self.last_decision_ts = ts
            return None

        m_blk = RE_BLOCKED.search(text)
        if not m_blk:
            return None

        path = m_blk.group(1).strip() or "/"
        if not path.startswith("/") and "://" not in path:
            path = "/" + path
        client = "?"
        if self.last_decision_ip and ts is not None and self.last_decision_ts is not None:
            if abs(ts - self.last_decision_ts) <= CORRELATE_SEC:
                client = self.last_decision_ip
        elif self.last_decision_ip and self.last_decision_ts is None:
            client = self.last_decision_ip

        self.blocks_parsed += 1
        return LogEvent(
            raw=event.raw,
            timestamp=event.timestamp,
            kind="request",
            router="crowdsec",
            origin="",
            client=client,
            user_agent="",
            method="GET",
            path=path[:400],
            status=403,
            component=event.component,
            level=event.level,
            message=text[:300],
        )


def crowdsec_reason(path: str = "") -> str:
    if path and path not in ("/", "-"):
        return f"CrowdSec Bouncer · {path}"
    return "CrowdSec Bouncer"
