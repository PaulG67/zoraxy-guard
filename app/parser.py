from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Common Zoraxy router request line (with or without useragent):
# [2026-07-02 17:45:15.056696] [router:blacklist] [origin:host] [client: 1.2.3.4] [useragent: x] GET /path 403
LOG_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"\[router:(?P<router>[^\]]+)\]\s+"
    r"\[origin:(?P<origin>[^\]]*)\]\s+"
    r"\[client:\s*(?P<client>[^\]]+)\]\s+"
    r"(?:\[useragent:\s*(?P<ua>[^\]]*)\]\s+)?"
    r"(?P<method>[A-Z]+)\s+"
    r"(?P<path>\S+)\s+"
    r"(?P<status>\d{3})\s*$"
)

# Internal / non-traffic lines
INTERNAL_RE = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<component>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]\s+(?P<msg>.*)$")


@dataclass
class LogEvent:
    raw: str
    timestamp: Optional[datetime]
    kind: str  # request | internal | unknown
    router: str = ""
    origin: str = ""
    client: str = ""
    user_agent: str = ""
    method: str = ""
    path: str = ""
    status: int = 0
    component: str = ""
    level: str = ""
    message: str = ""


def parse_timestamp(value: str) -> Optional[datetime]:
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_line(line: str) -> LogEvent:
    line = line.rstrip("\n")
    m = LOG_RE.match(line)
    if m:
        return LogEvent(
            raw=line,
            timestamp=parse_timestamp(m.group("ts")),
            kind="request",
            router=m.group("router").strip(),
            origin=m.group("origin").strip(),
            client=m.group("client").strip(),
            user_agent=(m.group("ua") or "").strip(),
            method=m.group("method").strip(),
            path=m.group("path").strip(),
            status=int(m.group("status")),
        )

    m2 = INTERNAL_RE.match(line)
    if m2:
        return LogEvent(
            raw=line,
            timestamp=parse_timestamp(m2.group("ts")),
            kind="internal",
            component=m2.group("component").strip(),
            level=m2.group("level").strip(),
            message=m2.group("msg").strip(),
        )

    return LogEvent(raw=line, timestamp=None, kind="unknown")