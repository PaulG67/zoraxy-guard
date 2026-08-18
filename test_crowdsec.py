#!/usr/bin/env python3
from app.crowdsec import CrowdSecLogState
from app.parser import parse_line


def test_plugin_block_with_ip():
    st = CrowdSecLogState()
    a = parse_line(
        "[2026-08-18 12:00:00.000000] [plugin-manager] [system:info] "
        "[Crowdsec Bouncer Plugin for Zoraxy:7811] Decision found for IP: 203.0.113.50"
    )
    assert st.ingest(a) is None
    b = parse_line(
        "[2026-08-18 12:00:00.120000] [plugin-manager] [system:info] "
        "[Crowdsec Bouncer Plugin for Zoraxy:7811] Request blocked: /.env"
    )
    ev = st.ingest(b)
    assert ev is not None
    assert ev.kind == "request"
    assert ev.router == "crowdsec"
    assert ev.status == 403
    assert ev.client == "203.0.113.50"
    assert ev.path == "/.env"


def test_skip_no_decision():
    st = CrowdSecLogState()
    line = parse_line(
        "[2026-08-18 12:00:00.000000] [plugin-manager] [system:info] "
        "[Crowdsec Bouncer Plugin for Zoraxy:7811] No decision found for IP: 1.2.3.4"
    )
    assert st.ingest(line) is None
    assert st.seen_plugin is True


def test_blocked_without_ip():
    st = CrowdSecLogState()
    ev = st.ingest(
        parse_line(
            "[2026-08-18 12:00:01.000000] [plugin-manager] [system:info] "
            "[Crowdsec Bouncer Plugin for Zoraxy:9] Request blocked: /wp-admin"
        )
    )
    assert ev is not None
    assert ev.client == "?"
    assert ev.path == "/wp-admin"


if __name__ == "__main__":
    test_plugin_block_with_ip()
    test_skip_no_decision()
    test_blocked_without_ip()
    print("crowdsec tests ok")
