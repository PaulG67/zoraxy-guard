from __future__ import annotations

import csv
import io
import ipaddress
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests

from .iputil import IpNetwork, load_networks_file, parse_network
from .catalog import get_enabled_downloadable

log = logging.getLogger("zoraxy-guard.feeds")


_IP_RE = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|"
    r"[0-9a-fA-F:]+(?:/\d{1,3})?)"
)


@dataclass
class ThreatLists:
    """Combined IP networks plus optional UA/path extras from custom lists."""

    block_nets: List[IpNetwork] = field(default_factory=list)
    sources: Dict[str, int] = field(default_factory=dict)  # name -> count
    extra_user_agents: List[str] = field(default_factory=list)
    extra_paths: List[str] = field(default_factory=list)
    loaded_at: float = 0.0

    # For alerting: which list name matched an IP (best-effort via set of exact IPs)
    exact_ip_sources: Dict[str, Set[str]] = field(default_factory=dict)


def _tokens_from_plain(text: str) -> List[str]:
    tokens: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
            continue
        # spamhaus / comments after ;
        if ";" in line and not line.lower().startswith(";" ):
            line = line.split(";", 1)[0].strip()
        token = line.split()[0].strip().strip(",")
        if token:
            tokens.append(token)
    return tokens


def _tokens_from_spamhaus(text: str) -> List[str]:
    return _tokens_from_plain(text)


def _tokens_from_abusech_csv(text: str) -> List[str]:
    tokens: List[str] = []
    # Skip comment lines starting with #
    cleaned = "\n".join(
        ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")
    )
    reader = csv.reader(io.StringIO(cleaned))
    for row in reader:
        if not row:
            continue
        # sslipblacklist.csv: Firstseen,DstIP,DstPort
        for cell in row:
            cell = cell.strip()
            if parse_network(cell):
                tokens.append(cell)
                break
            m = _IP_RE.search(cell)
            if m:
                tokens.append(m.group("ip"))
                break
    return tokens


def parse_feed_tokens(text: str, fmt: str) -> List[str]:
    fmt = (fmt or "plain_ip").lower()
    if fmt in ("plain_ip", "plain", "ipset", "netset", "text"):
        return _tokens_from_plain(text)
    if fmt in ("spamhaus",):
        return _tokens_from_spamhaus(text)
    if fmt in ("abusech_csv", "csv"):
        return _tokens_from_abusech_csv(text)
    # Fallback: extract IPs anywhere in line
    tokens: List[str] = []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        for m in _IP_RE.finditer(line):
            tokens.append(m.group("ip"))
    return tokens


def networks_from_tokens(tokens: Iterable[str], source_name: str) -> Tuple[List[IpNetwork], Set[str]]:
    nets: List[IpNetwork] = []
    exacts: Set[str] = set()
    for token in tokens:
        net = parse_network(token)
        if not net:
            continue
        nets.append(net)
        # track /32 and /128 for source attribution
        if net.prefixlen == net.max_prefixlen:
            exacts.add(str(net.network_address))
    return nets, exacts


def download_url(url: str, timeout: int = 45) -> str:
    headers = {"User-Agent": "zoraxy-guard/1.0 (+https://github.com/PaulG67/zoraxy-guard)"}
    r = requests.get(url, timeout=timeout, headers=headers)
    r.raise_for_status()
    return r.text


def load_local_list_dir(directory: str) -> ThreatLists:
    """Load every *.txt / *.list / *.netset / *.ipset from a folder."""
    result = ThreatLists()
    if not directory or not os.path.isdir(directory):
        return result
    for name in sorted(os.listdir(directory)):
        low = name.lower()
        if not low.endswith((".txt", ".list", ".netset", ".ipset", ".csv")):
            continue
        path = os.path.join(directory, name)
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.error("Cannot read local list %s: %s", path, exc)
            continue
        fmt = "abusech_csv" if low.endswith(".csv") else "plain_ip"
        # special: useragents / paths files
        stem = Path(name).stem.lower()
        if "useragent" in stem or "user-agent" in stem or stem.endswith("_ua"):
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    result.extra_user_agents.append(line)
            result.sources[f"local:{name}"] = len(result.extra_user_agents)
            continue
        if "path" in stem or "exploit" in stem:
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    result.extra_paths.append(line)
            result.sources[f"local:{name}"] = len(result.extra_paths)
            continue

        tokens = parse_feed_tokens(text, fmt)
        nets, exacts = networks_from_tokens(tokens, name)
        result.block_nets.extend(nets)
        result.sources[f"local:{name}"] = len(nets)
        if exacts:
            result.exact_ip_sources[f"local:{name}"] = exacts
        log.info("Local list %s: %d entries", name, len(nets))
    return result


def load_all_threat_lists(cfg: dict, cache_dir: str = "/data/feed-cache") -> ThreatLists:
    """
    Merge:
      - blocklist_ips
      - blocklist_file
      - lists_dir (folder of text files)
      - known_lists (catalog names)
      - threat_feeds.urls (custom URLs)
      - custom_lists: [{name, url, format, kind}]
    """
    merged = ThreatLists(loaded_at=time.time())

    # Static config IPs
    from .iputil import load_networks

    static = load_networks(cfg.get("blocklist_ips") or [])
    if static:
        merged.block_nets.extend(static)
        merged.sources["config:blocklist_ips"] = len(static)

    bl_file = cfg.get("blocklist_file")
    if bl_file:
        nets = load_networks_file(bl_file)
        merged.block_nets.extend(nets)
        merged.sources["config:blocklist_file"] = len(nets)

    # Directory of user-supplied databases
    lists_dir = cfg.get("lists_dir") or "/data/lists"
    local = load_local_list_dir(lists_dir)
    merged.block_nets.extend(local.block_nets)
    merged.extra_user_agents.extend(local.extra_user_agents)
    merged.extra_paths.extend(local.extra_paths)
    merged.sources.update(local.sources)
    for k, v in local.exact_ip_sources.items():
        merged.exact_ip_sources.setdefault(k, set()).update(v)

    Path(cache_dir).mkdir(parents=True, exist_ok=True)

    # Build work queue of remote sources
    remote_jobs: List[dict] = []

    known = cfg.get("known_lists") or {}
    enabled_names = known.get("enabled") or []
    # allow: known_lists: [name, name] shorthand
    if isinstance(known, list):
        enabled_names = known
        known = {"enabled": enabled_names}

    for name, entry in get_enabled_downloadable(list(enabled_names)):
        remote_jobs.append(
            {
                "name": f"known:{name}",
                "url": entry["url"],
                "format": entry.get("format", "plain_ip"),
                "kind": entry.get("kind", "ip"),
            }
        )

    for item in cfg.get("custom_lists") or []:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        if item.get("enabled") is False:
            continue
        remote_jobs.append(
            {
                "name": f"custom:{item.get('name') or item['url']}",
                "url": item["url"],
                "format": item.get("format", "plain_ip"),
                "kind": item.get("kind", "ip"),
            }
        )

    feeds = cfg.get("threat_feeds") or {}
    # backward compatible: threat_feeds.enabled + urls
    if feeds.get("enabled") or feeds.get("urls"):
        for url in feeds.get("urls") or []:
            remote_jobs.append(
                {
                    "name": f"feed:{url}",
                    "url": url,
                    "format": feeds.get("format", "plain_ip"),
                    "kind": "ip",
                }
            )

    use_cache = bool((known.get("use_cache", True) if isinstance(known, dict) else True))
    max_age = float((cfg.get("lists_refresh_hours") or feeds.get("refresh_hours") or 24)) * 3600

    for job in remote_jobs:
        name = job["name"]
        url = job["url"]
        fmt = job["format"]
        kind = job.get("kind", "ip")
        cache_key = re.sub(r"[^a-zA-Z0-9._-]+", "_", name)[:120]
        cache_path = os.path.join(cache_dir, f"{cache_key}.txt")

        text: Optional[str] = None
        if use_cache and os.path.isfile(cache_path):
            age = time.time() - os.path.getmtime(cache_path)
            if age < max_age:
                try:
                    text = Path(cache_path).read_text(encoding="utf-8", errors="replace")
                    log.info("Cache hit %s (%.0fh old)", name, age / 3600)
                except OSError:
                    text = None

        if text is None:
            try:
                text = download_url(url)
                Path(cache_path).write_text(text, encoding="utf-8")
                log.info("Downloaded %s", name)
            except Exception as exc:
                log.error("Failed to load %s (%s): %s", name, url, exc)
                # try stale cache
                if os.path.isfile(cache_path):
                    try:
                        text = Path(cache_path).read_text(encoding="utf-8", errors="replace")
                        log.warning("Using stale cache for %s", name)
                    except OSError:
                        continue
                else:
                    continue

        if kind == "user_agent":
            count = 0
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    merged.extra_user_agents.append(line)
                    count += 1
            merged.sources[name] = count
            continue
        if kind == "path":
            count = 0
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    merged.extra_paths.append(line)
                    count += 1
            merged.sources[name] = count
            continue

        tokens = parse_feed_tokens(text, fmt)
        nets, exacts = networks_from_tokens(tokens, name)
        merged.block_nets.extend(nets)
        merged.sources[name] = len(nets)
        if exacts:
            merged.exact_ip_sources[name] = exacts
        log.info("%s: %d IP/CIDR entries", name, len(nets))

    return merged


def find_list_match(ip_str: str, threat: ThreatLists) -> Optional[str]:
    """Return first list name that contains exact IP if tracked."""
    for name, ips in threat.exact_ip_sources.items():
        if ip_str in ips:
            return name
    return None


def catalog_as_markdown() -> str:
    from .catalog import catalog_as_feed_map

    lines = ["| Name | Reliability | Status | Description |", "|---|---|---|---|"]
    for name, meta in sorted(catalog_as_feed_map().items()):
        lines.append(
            f"| `{name}` | {meta.get('reliability', '')} | {meta.get('status', '')} | {meta['description']} |"
        )
    return "\n".join(lines)
