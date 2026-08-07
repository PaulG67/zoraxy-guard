"""Lightweight Geo/ASN resolution with RAM cache (ip-api.com batch)."""

from __future__ import annotations

import logging
import time
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional

import requests

from .iputil import parse_ip

log = logging.getLogger("zoraxy-guard.geoip")

# Free, no API key. Limit: 15 batch requests / minute, max 100 IPs each.
IP_API_BATCH = "http://ip-api.com/batch"
FIELDS = "status,message,query,country,countryCode,as,org,isp,reverse"

UNKNOWN: Dict[str, Any] = {
    "country": "—",
    "country_code": "",
    "org": "—",
    "asn": "",
    "isp": "",
    "as_full": "",
    "label": "—",
    "ok": False,
}

LAN: Dict[str, Any] = {
    "country": "LAN / privat",
    "country_code": "LAN",
    "org": "Privates Netzwerk",
    "asn": "",
    "isp": "",
    "as_full": "",
    "label": "LAN · privat",
    "ok": True,
}


def _is_private(ip_str: str) -> bool:
    ip = parse_ip(ip_str)
    if not ip:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


def _from_api_row(row: dict) -> Dict[str, Any]:
    if not isinstance(row, dict) or row.get("status") != "success":
        return dict(UNKNOWN)
    asn_raw = (row.get("as") or "").strip()  # e.g. "AS15169 GOOGLE"
    asn = asn_raw.split()[0] if asn_raw else ""
    org = (row.get("org") or row.get("isp") or "").strip() or "—"
    isp = (row.get("isp") or "").strip()
    country = (row.get("country") or "").strip() or "—"
    code = (row.get("countryCode") or "").strip()
    parts = []
    if code:
        parts.append(code)
    elif country and country != "—":
        parts.append(country)
    owner = org if org != "—" else (asn_raw or "—")
    if owner and owner != "—":
        parts.append(owner)
    return {
        "country": country,
        "country_code": code,
        "org": org,
        "asn": asn,
        "isp": isp,
        "as_full": asn_raw,
        "label": " · ".join(parts) if parts else "—",
        "ok": True,
    }


class GeoCache:
    """In-process cache; lookups only for IPs seen in the UI request."""

    def __init__(self, ttl_sec: int = 7 * 24 * 3600, max_entries: int = 4000) -> None:
        self.ttl_sec = ttl_sec
        self.max_entries = max_entries
        self._lock = Lock()
        self._cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
        self.hits = 0
        self.misses = 0
        self.api_calls = 0
        self.last_error = ""

    def get(self, ip: str) -> Dict[str, Any]:
        return self.resolve([ip]).get(ip, dict(UNKNOWN))

    def resolve(self, ips: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        """Return geo dict per IP (always includes all requested public/private keys)."""
        now = time.time()
        unique: List[str] = []
        seen = set()
        for raw in ips:
            ip = (raw or "").strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)
            unique.append(ip)

        result: Dict[str, Dict[str, Any]] = {}
        need_fetch: List[str] = []

        with self._lock:
            for ip in unique:
                if _is_private(ip):
                    result[ip] = dict(LAN)
                    continue
                ent = self._cache.get(ip)
                if ent and now - ent[0] < self.ttl_sec:
                    self.hits += 1
                    result[ip] = dict(ent[1])
                else:
                    self.misses += 1
                    need_fetch.append(ip)

        if need_fetch:
            fetched = self._fetch_batch(need_fetch)
            with self._lock:
                for ip, info in fetched.items():
                    self._cache[ip] = (now, info)
                    result[ip] = dict(info)
                self._evict_locked(now)

        for ip in unique:
            result.setdefault(ip, dict(UNKNOWN))
        return result

    def _evict_locked(self, now: float) -> None:
        if len(self._cache) <= self.max_entries:
            return
        # Drop oldest half of entries over limit
        ordered = sorted(self._cache.items(), key=lambda kv: kv[1][0])
        drop = len(self._cache) - self.max_entries + self.max_entries // 10
        for key, _ in ordered[: max(drop, 0)]:
            self._cache.pop(key, None)

    def _fetch_batch(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        # Cap per page refresh to stay nice to free API
        chunk_size = 100
        for i in range(0, min(len(ips), 300), chunk_size):
            chunk = ips[i : i + chunk_size]
            payload = [{"query": ip, "fields": FIELDS} for ip in chunk]
            try:
                resp = requests.post(
                    IP_API_BATCH,
                    json=payload,
                    timeout=6,
                    headers={"User-Agent": "zoraxy-guard/1.0"},
                )
                self.api_calls += 1
                if resp.status_code == 429:
                    self.last_error = "GeoIP Rate-Limit (ip-api)"
                    log.warning(self.last_error)
                    for ip in chunk:
                        out.setdefault(ip, dict(UNKNOWN))
                    break
                resp.raise_for_status()
                rows = resp.json()
                if not isinstance(rows, list):
                    raise ValueError("unexpected geo response")
                for ip, row in zip(chunk, rows):
                    if isinstance(row, dict):
                        row = dict(row)
                        row.setdefault("query", ip)
                        out[ip] = _from_api_row(row)
                    else:
                        out[ip] = dict(UNKNOWN)
                self.last_error = ""
            except Exception as exc:
                self.last_error = str(exc)[:200]
                log.warning("GeoIP lookup failed: %s", exc)
                for ip in chunk:
                    out.setdefault(ip, dict(UNKNOWN))
                break
        for ip in ips:
            out.setdefault(ip, dict(UNKNOWN))
        return out

    def stats(self) -> dict:
        with self._lock:
            return {
                "cached": len(self._cache),
                "hits": self.hits,
                "misses": self.misses,
                "api_calls": self.api_calls,
                "last_error": self.last_error,
            }
