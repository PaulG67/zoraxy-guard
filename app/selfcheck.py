"""Ignore the operator's own «Prüfen» browser hit so it does not raise an alert."""

from __future__ import annotations

import time
from threading import Lock
from typing import Optional
from urllib.parse import parse_qs, urlsplit

# Query flag used on Pushover links (no JS to pre-register an expect).
CHECK_QUERY_KEY = "_zg"
CHECK_QUERY_VAL = "1"

# Drop a click-credit if the browser never follows through.
_UNUSED_CREDIT_TTL = 120.0


def origin_key(origin: str) -> str:
    return (origin or "").strip().lower().rstrip(".")


def path_key(path: str) -> str:
    p = (path or "/").strip() or "/"
    if "?" in p:
        p = p.split("?", 1)[0]
    if "#" in p:
        p = p.split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    return p or "/"


def is_self_check_path(path: str) -> bool:
    """True if the request path carries the Guard self-check query flag."""
    if not path or "?" not in path:
        return False
    qs = path.split("?", 1)[1]
    params = parse_qs(qs, keep_blank_values=True)
    vals = params.get(CHECK_QUERY_KEY)
    if not vals:
        return False
    return any(v in ("", CHECK_QUERY_VAL, "true", "yes") for v in vals)


def append_check_marker(url: str) -> str:
    """Append ?_zg=1 so a phone/Pushover open is recognized as self-check."""
    url = (url or "").strip()
    if not url:
        return ""
    parts = urlsplit(url)
    query = parts.query
    if CHECK_QUERY_KEY + "=" in query or query == CHECK_QUERY_KEY:
        return url
    extra = f"{CHECK_QUERY_KEY}={CHECK_QUERY_VAL}"
    new_q = f"{query}&{extra}" if query else extra
    return parts._replace(query=new_q).geturl()


SELF_CHECK_RISK = {
    "level": "safe",
    "score": 0,
    "title": "Eigene Prüfung",
    "detail": "Aufruf über den Prüfen-Link — kein Alarm, kein Handlungsbedarf.",
    "action_needed": False,
    "tags": ["self-check"],
}


class CheckExpectStore:
    """
    One ignore-credit per Prüfen click for that origin+path.
    The next matching log line consumes the credit; later hits are alerts again.
    Unused credits expire so a blocked popup cannot suppress a later scanner.
    """

    def __init__(self, unused_ttl_sec: float = _UNUSED_CREDIT_TTL) -> None:
        self.unused_ttl = float(unused_ttl_sec)
        self._pending: dict[tuple[str, str], list[float]] = {}
        self._lock = Lock()

    def expect(self, origin: str, path: str, ttl_sec: Optional[float] = None) -> int:
        """Register one upcoming self-check. Returns remaining credits for this target."""
        ttl = self.unused_ttl if ttl_sec is None else float(ttl_sec)
        key = (origin_key(origin), path_key(path))
        expire = time.time() + ttl
        with self._lock:
            self._prune()
            self._pending.setdefault(key, []).append(expire)
            return len(self._pending[key])

    def consume(self, origin: str, path: str) -> bool:
        """
        True if this request is a self-check.
        Query-marker: this request only.
        Click-credit: consumes exactly one pending click for origin+path.
        """
        if is_self_check_path(path):
            return True
        key = (origin_key(origin), path_key(path))
        with self._lock:
            self._prune()
            q = self._pending.get(key)
            if not q:
                return False
            q.pop(0)
            if not q:
                del self._pending[key]
            return True

    # Back-compat name used by the tail loop
    def matches(self, origin: str, path: str) -> bool:
        return self.consume(origin, path)

    def _prune(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        dead_keys = []
        for key, q in self._pending.items():
            kept = [t for t in q if t > now]
            if kept:
                self._pending[key] = kept
            else:
                dead_keys.append(key)
        for key in dead_keys:
            del self._pending[key]
