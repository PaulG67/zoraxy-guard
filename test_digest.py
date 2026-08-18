#!/usr/bin/env python3
"""Digest helpers: many alerts → one push payload."""
from app.alerter import Alerter, PushPayload, format_digest
from app.detectors import Alert
from app.parser import LogEvent


def _item(i: int, *, severity: str = "high", kind: str = "exploit_scan", origin: str = "auth.example.com") -> PushPayload:
    alert = Alert(
        severity=severity,
        title=f"Scan {i}",
        body="probe",
        fingerprint=f"exploit_scan:{origin}:/.env{i}",
        kind=kind,
        event=LogEvent(
            raw="",
            timestamp=None,
            kind="request",
            router="host-http",
            origin=origin,
            client="1.2.3.4",
            user_agent="x",
            method="GET",
            path=f"/.env{i}",
            status=200,
        ),
    )
    return PushPayload(
        ts=1000.0 + i,
        severity=severity,
        title=f"[Zoraxy Guard][{severity.upper()}] Scan {i}",
        body="probe",
        check_url=f"https://{origin}/.env{i}",
        fingerprint=alert.fingerprint,
        kind=kind,
        origin=origin,
        path=f"/.env{i}",
        review_id=f"ZG-0000000{i}",
        alert=alert,
    )


def test_single_passthrough():
    one = _item(1)
    title, body, sev, url = format_digest([one])
    assert title == one.title
    assert body == one.body
    assert sev == "high"
    assert url == one.check_url


def test_bundle():
    items = [
        _item(1, kind="exploit_scan"),
        _item(2, kind="exploit_scan", origin="ps.example.com"),
        _item(3, kind="exploit_success", severity="critical"),
    ]
    title, body, sev, url = format_digest(items)
    assert "3 Alarme" in title
    assert "CRITICAL" in title
    assert sev == "critical"
    assert "gebündelt" in body
    assert "Exploit-Scan" in body
    assert "auth.example.com" in body
    assert "ps.example.com" in body
    assert len(body) <= 1024
    assert url.startswith("https://")


def test_body_limit():
    items = [_item(i, origin=f"h{i}.example.com") for i in range(40)]
    _title, body, _sev, _url = format_digest(items)
    assert len(body) <= 1024
    assert "weitere" in body


def _alert(i: int) -> Alert:
    return Alert(
        severity="high",
        title=f"Scan {i}",
        body="probe",
        fingerprint=f"exploit_scan:host{i}:/.git",
        kind="exploit_scan",
        event=LogEvent(
            raw="GET /.git 200",
            timestamp=None,
            kind="request",
            router="host-http",
            origin=f"h{i}.example.com",
            client="9.9.9.9",
            user_agent="nuclei",
            method="GET",
            path="/.git",
            status=200,
        ),
    )


def test_alerter_batches_burst():
    sent = []
    cfg = {
        "alerts": {
            "stdout": False,
            "cooldown_seconds": 0,
            "digest_window_seconds": 180,
            "digest_idle_seconds": 15,
            "notify_mode": "severity",
            "min_severity": "info",
            "notify_skip_blocked": False,
            "notify_skip_acked": False,
        }
    }
    alerter = Alerter(cfg, {})

    def capture(title, body, severity, check_url, alert, *, digest_count=0):
        sent.append((title, body, severity, digest_count))

    alerter._dispatch = capture  # type: ignore[method-assign]
    t0 = 1_700_000_000.0
    for i in range(8):
        assert alerter.send(_alert(i), t0)
    assert sent == []
    alerter.flush_due(t0 + 5)
    assert sent == []
    alerter.flush_due(t0 + 15)
    assert len(sent) == 1
    title, body, severity, digest_count = sent[0]
    assert "8 Alarme" in title
    assert digest_count == 8
    assert "gebündelt" in body
    assert severity == "high"


def test_muted_skips_dispatch():
    sent = []
    cfg = {
        "alerts": {
            "stdout": False,
            "cooldown_seconds": 0,
            "digest_window_seconds": 0,
            "notify_mode": "severity",
            "min_severity": "info",
            "notify_skip_blocked": False,
            "notify_skip_acked": False,
            "muted": True,
        }
    }
    alerter = Alerter(cfg, {})

    def capture(title, body, severity, check_url, alert, *, digest_count=0):
        sent.append(title)

    alerter._dispatch = capture  # type: ignore[method-assign]
    assert alerter.send(_alert(1), 1.0) is True
    assert sent == []
    alerter.set_muted(False)
    assert alerter.send(_alert(2), 2.0) is True
    assert len(sent) == 1


if __name__ == "__main__":
    test_single_passthrough()
    test_bundle()
    test_body_limit()
    test_alerter_batches_burst()
    test_muted_skips_dispatch()
    print("digest tests ok")
