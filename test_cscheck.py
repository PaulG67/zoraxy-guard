#!/usr/bin/env python3
from pathlib import Path

from app import cscheck


def _cfg(tmp_path: Path, *, key="test-key", agent="http://crowdsec:8080", collections=True) -> dict:
    csdir = tmp_path / "crowdsec"
    csdir.mkdir()
    (csdir / "config.yaml").write_text("common:\n  log_level: info\n", encoding="utf-8")
    if collections:
        (csdir / "collections").mkdir()
        (csdir / "collections" / "linux.yaml").write_text("name: linux\n", encoding="utf-8")
    bouncer = tmp_path / "plugin" / "config.yaml"
    bouncer.parent.mkdir()
    bouncer.write_text(
        f"api_key: {key}\nagent_url: {agent}\nlog_level: info\n",
        encoding="utf-8",
    )
    return {
        "crowdsec": {
            "config_dir": str(csdir),
            "bouncer_config": str(bouncer),
        }
    }


def test_normalize_and_override():
    assert cscheck.normalize_lapi_url("crowdsec:8080") == "http://crowdsec:8080"
    assert cscheck.normalize_lapi_url("http://10.0.0.5:8080/") == "http://10.0.0.5:8080"
    cfg = {"crowdsec": {"lapi_url": "http://192.168.1.10:8080"}}
    assert cscheck.lapi_url_from_cfg(cfg) == "http://192.168.1.10:8080"
    assert cscheck.lapi_url_from_cfg(cfg, "10.0.0.1:8080") == "http://10.0.0.1:8080"


def test_lapi_ok(tmp_path: Path):
    cfg = _cfg(tmp_path)
    seen = []

    def fake_get(url, headers=None, timeout=4.0):
        seen.append((url, (headers or {}).get("X-Api-Key")))
        if url.endswith("/health"):
            return 200, '{"status":"up"}'
        if "/v1/decisions" in url:
            return 200, "null"
        return 0, "unexpected"

    report = cscheck.run_check(
        cfg,
        plugin_seen=True,
        plugin_lines=12,
        plugin_blocks=3,
        history_blocks=2,
        http_get=fake_get,
    )
    assert report["verdict"] == "ok"
    assert "Bouncer-Key gültig" in report["summary"]
    assert any(k == "test-key" for _, k in seen)
    by_id = {r["id"]: r["status"] for r in report["rows"]}
    assert by_id["lapi_health"] == "ok"
    assert by_id["lapi_bouncer"] == "ok"
    assert "test-key" not in str(report)


def test_connection_error(tmp_path: Path):
    cfg = _cfg(tmp_path)

    def fake_get(url, headers=None, timeout=4.0):
        return 0, "Name or service not known"

    report = cscheck.run_check(cfg, http_get=fake_get)
    assert report["verdict"] == "fail"
    by_id = {r["id"]: r["status"] for r in report["rows"]}
    assert by_id["lapi_health"] == "fail"
    assert by_id["lapi_bouncer"] == "fail"


def test_bad_api_key(tmp_path: Path):
    cfg = _cfg(tmp_path)

    def fake_get(url, headers=None, timeout=4.0):
        if url.endswith("/health"):
            return 200, '{"status":"up"}'
        return 401, "unauthorized"

    report = cscheck.run_check(cfg, plugin_seen=True, http_get=fake_get)
    assert report["verdict"] == "fail"
    by_id = {r["id"]: r["status"] for r in report["rows"]}
    assert by_id["lapi_health"] == "ok"
    assert by_id["lapi_bouncer"] == "fail"


def test_health_missing_but_bouncer_ok(tmp_path: Path):
    cfg = _cfg(tmp_path)

    def fake_get(url, headers=None, timeout=4.0):
        if url.endswith("/health"):
            return 404, "not found"
        return 200, "[]"

    report = cscheck.run_check(cfg, plugin_seen=True, http_get=fake_get)
    assert report["verdict"] == "ok"
    by_id = {r["id"]: r["status"] for r in report["rows"]}
    assert by_id["lapi_health"] == "warn"
    assert by_id["lapi_bouncer"] == "ok"


def test_scan_plugin_lines(tmp_path: Path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "zr_app.log").write_text(
        "[2026-08-18 12:00:00.000000] [plugin-manager] [system:info] "
        "[Crowdsec Bouncer Plugin for Zoraxy:7811] Request blocked: /.env\n",
        encoding="utf-8",
    )
    cfg = _cfg(tmp_path)
    cfg["log"] = {"directory": str(logs), "pattern": "zr_*.log"}
    disk = cscheck.scan_zoraxy_plugin_logs(cfg)
    assert disk["file_count"] == 1
    assert disk["plugin_lines"] == 1
    assert disk["blocked_lines"] == 1

    def fake_get(url, headers=None, timeout=4.0):
        if url.endswith("/health"):
            return 200, '{"status":"up"}'
        return 200, "null"

    report = cscheck.run_check(cfg, http_get=fake_get)
    assert report["verdict"] == "ok"
    by_id = {r["id"]: r["status"] for r in report["rows"]}
    assert by_id["plugin_logs"] == "ok"
    assert "fehlen noch" not in report["summary"]


def test_scan_no_plugin_lines(tmp_path: Path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "zr_app.log").write_text(
        "[2026-08-18 12:00:00.000000] [router:http] [origin:x] [client: 1.2.3.4] GET / 200\n",
        encoding="utf-8",
    )
    cfg = _cfg(tmp_path)
    cfg["log"] = {"directory": str(logs), "pattern": "zr_*.log"}

    def fake_get(url, headers=None, timeout=4.0):
        if url.endswith("/health"):
            return 200, '{"status":"up"}'
        return 200, "null"

    report = cscheck.run_check(cfg, http_get=fake_get)
    by_id = {r["id"]: r["status"] for r in report["rows"]}
    assert by_id["plugin_logs"] == "warn"
    assert "fehlen noch" not in report["summary"]
    assert by_id["lapi_bouncer"] == "ok"
