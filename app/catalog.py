from __future__ import annotations

import json
import logging
import os
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from .fileio import write_text_atomic

log = logging.getLogger("zoraxy-guard.catalog")

# Bundled catalog in the image / git tree
BUNDLED_CATALOG = Path(__file__).resolve().parent.parent / "catalog" / "known_lists.json"
DEFAULT_REMOTE = (
    os.environ.get("CATALOG_URL")
    or "https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main/catalog/known_lists.json"
)
CACHE_PATH = Path(os.environ.get("CATALOG_CACHE", "/data/catalog/known_lists.json"))
META_PATH = Path(os.environ.get("CATALOG_META", "/data/catalog/meta.json"))


def _empty_catalog() -> dict:
    return {"version": 0, "updated": "", "notes": [], "sources": {"meta": []}, "lists": {}}


def _normalize(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Catalog root must be an object")
    lists = data.get("lists")
    if not isinstance(lists, dict) or not lists:
        raise ValueError("Catalog.lists missing or empty")
    for name, entry in lists.items():
        if not isinstance(entry, dict) or not entry.get("url"):
            raise ValueError(f"Invalid list entry: {name}")
        entry.setdefault("format", "plain_ip")
        entry.setdefault("kind", "ip")
        entry.setdefault("description", name)
        entry.setdefault("reliability", "medium")
        entry.setdefault("status", "active")
        entry.setdefault("false_positive_risk", "medium")
        entry.setdefault("notes", "")
    data.setdefault("version", 1)
    data.setdefault("updated", "")
    data.setdefault("notes", [])
    data.setdefault("sources", {"meta": []})
    return data


def load_bundled() -> dict:
    if BUNDLED_CATALOG.is_file():
        with open(BUNDLED_CATALOG, "r", encoding="utf-8") as fh:
            return _normalize(json.load(fh))
    log.warning("Bundled catalog missing at %s", BUNDLED_CATALOG)
    return _empty_catalog()


def load_cached() -> Optional[dict]:
    if not CACHE_PATH.is_file():
        return None
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as fh:
            return _normalize(json.load(fh))
    except Exception as exc:
        log.error("Bad catalog cache: %s", exc)
        return None


def save_cache(data: dict) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    write_text_atomic(str(CACHE_PATH), text)


def load_meta() -> dict:
    if META_PATH.is_file():
        try:
            with open(META_PATH, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {}


def save_meta(meta: dict) -> None:
    write_text_atomic(str(META_PATH), json.dumps(meta, indent=2))


def get_active_catalog() -> dict:
    """Prefer upgraded cache, else bundled."""
    cached = load_cached()
    if cached:
        return cached
    return load_bundled()


def catalog_as_feed_map(data: Optional[dict] = None) -> Dict[str, dict]:
    """Shape expected by feeds loader (url/format/kind/description + extras)."""
    data = data or get_active_catalog()
    out: Dict[str, dict] = {}
    for name, entry in (data.get("lists") or {}).items():
        status = (entry.get("status") or "active").lower()
        # Deprecated lists stay visible in UI but must not be downloadable unless forced
        out[name] = {
            "description": entry.get("description", name),
            "url": entry.get("url"),
            "format": entry.get("format", "plain_ip"),
            "kind": entry.get("kind", "ip"),
            "reliability": entry.get("reliability", "medium"),
            "status": status,
            "false_positive_risk": entry.get("false_positive_risk", "medium"),
            "maintainer": entry.get("maintainer", ""),
            "notes": entry.get("notes", ""),
        }
    return out


def get_enabled_downloadable(enabled_names: List[str], catalog: Optional[dict] = None) -> List[Tuple[str, dict]]:
    cmap = catalog_as_feed_map(catalog)
    jobs = []
    for name in enabled_names:
        entry = cmap.get(str(name))
        if not entry:
            log.warning("Unknown list name in config: %s", name)
            continue
        if (entry.get("status") or "").lower() == "deprecated":
            log.warning("Skipping deprecated list: %s", name)
            continue
        if (entry.get("reliability") or "").lower() == "avoid":
            log.warning("Skipping avoid-rated list: %s", name)
            continue
        jobs.append((str(name), entry))
    return jobs


def probe_url(url: str, timeout: int = 15) -> Tuple[bool, str]:
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "zoraxy-guard-catalog/1.0"}, stream=True)
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}"
        # read a small chunk to ensure body exists
        chunk = next(r.iter_content(512), b"")
        if not chunk and r.status_code != 200:
            return False, "empty body"
        return True, f"HTTP {r.status_code}"
    except Exception as exc:
        return False, str(exc)


def update_catalog_from_remote(
    remote_url: Optional[str] = None,
    probe: bool = True,
) -> dict:
    """
    Download the master catalog from GitHub (or CATALOG_URL), save cache,
    optionally probe each active list URL.
    Returns summary for UI.
    """
    url = (remote_url or DEFAULT_REMOTE).strip()
    before = catalog_as_feed_map(get_active_catalog())
    headers = {"User-Agent": "zoraxy-guard-catalog/1.0", "Accept": "application/json"}
    r = requests.get(url, timeout=45, headers=headers)
    r.raise_for_status()
    data = _normalize(r.json() if "json" in (r.headers.get("content-type") or "") else json.loads(r.text))

    after = catalog_as_feed_map(data)
    before_names = set(before)
    after_names = set(after)
    added = sorted(after_names - before_names)
    removed = sorted(before_names - after_names)
    deprecated = sorted(
        n for n, e in after.items() if (e.get("status") or "").lower() == "deprecated"
    )
    changed_url = sorted(
        n
        for n in (before_names & after_names)
        if before[n].get("url") != after[n].get("url")
    )

    probe_results: Dict[str, dict] = {}
    if probe:
        for name, entry in after.items():
            if (entry.get("status") or "").lower() == "deprecated":
                continue
            ok, msg = probe_url(entry["url"])
            probe_results[name] = {"ok": ok, "message": msg}
            if not ok:
                log.warning("Catalog probe failed %s: %s", name, msg)

    save_cache(data)
    meta = {
        "last_update_at": time.time(),
        "source": url,
        "version": data.get("version"),
        "updated_field": data.get("updated"),
        "added": added,
        "removed": removed,
        "deprecated": deprecated,
        "url_changed": changed_url,
        "probe": probe_results,
        "list_count": len(after),
    }
    save_meta(meta)
    log.info(
        "Catalog updated v%s: +%s -%s deprecated=%s",
        data.get("version"),
        len(added),
        len(removed),
        len(deprecated),
    )
    return meta


def prune_config_enabled(enabled: List[str], catalog: Optional[dict] = None) -> Tuple[List[str], List[str]]:
    """Drop enabled names that are unknown or deprecated. Returns (kept, dropped)."""
    cmap = catalog_as_feed_map(catalog)
    kept, dropped = [], []
    for name in enabled:
        e = cmap.get(name)
        if not e or (e.get("status") or "").lower() == "deprecated" or (e.get("reliability") or "") == "avoid":
            dropped.append(name)
        else:
            kept.append(name)
    return kept, dropped
