#!/usr/bin/env python3
"""Offline self-test against sample Zoraxy lines."""
from app.parser import parse_line
from app.detectors import Detector
from app.iputil import load_networks

CFG = {
    "allowlist_ips": ["192.168.0.0/16", "10.0.0.0/8"],
    "blocklist_ips": ["45.148.10.200"],
    "sensitive_hosts": ["ps.gehring.li", "unr.gehring.li"],
    "exploit_paths": [".env", "/.git", "wp-admin"],
    "exploit_path_ignore": [],
    "bad_user_agents": ["l9explore", "sqlmap"],
    "thresholds": {
        "exploit_hits_for_alert": 2,
        "exploit_window_seconds": 120,
        "block_hits_for_alert": 30,
        "block_window_seconds": 300,
        "auth_fail_for_alert": 15,
        "auth_fail_window_seconds": 300,
    },
    "alert_sensitive_success": True,
}
CFG["_allow_nets"] = load_networks(CFG["allowlist_ips"])
CFG["_block_nets"] = load_networks(CFG["blocklist_ips"])

lines = [
    "[2026-07-02 17:45:15.056696] [router:blacklist] [origin:144.2.102.215] [client: 45.148.10.200] [useragent: l9explore/1.2.2] GET /.env 403",
    "[2026-07-02 17:45:15.135491] [router:blacklist] [origin:144.2.102.215] [client: 45.148.10.200] [useragent: l9explore/1.2.2] GET /public/.env 403",
    "[2026-07-02 17:39:48.565507] [router:host-http] [origin:ps.gehring.li] [client: 203.0.113.50] [useragent: Mozilla/5.0] GET / 200",
    "[2026-07-02 17:39:48.565507] [router:host-http] [origin:home.gehring.li] [client: 192.168.0.10] [useragent: Mozilla/5.0] GET / 200",
]

det = Detector(CFG)
for line in lines:
    ev = parse_line(line)
    alerts = det.process(ev)
    print(f"LINE: {line[:80]}...")
    print(f"  kind={ev.kind} client={ev.client} path={ev.path} status={ev.status}")
    for a in alerts:
        print(f"  ALERT [{a.severity}] {a.title}: {a.body}")
    if not alerts:
        print("  (no alert)")
    print()