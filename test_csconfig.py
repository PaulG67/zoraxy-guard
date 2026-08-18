#!/usr/bin/env python3
"""Tests for CrowdSec YAML registry / merge / path safety."""
from __future__ import annotations

from pathlib import Path

from app import csconfig


def test_nested_set_keeps_unknown():
    data = {"common": {"log_level": "info", "log_dir": "/var/log"}, "keep": 1}
    csconfig._nested_set(data, "common.log_level", "debug")
    csconfig._nested_set(data, "api.server.listen_uri", "0.0.0.0:8080")
    assert data["common"]["log_dir"] == "/var/log"
    assert data["common"]["log_level"] == "debug"
    assert data["api"]["server"]["listen_uri"] == "0.0.0.0:8080"
    assert data["keep"] == 1


def test_apply_fields_password_keep():
    doc = csconfig.get_doc("bouncer")
    data = {"api_key": "secret-old", "log_level": "warning", "extra": True}
    csconfig.apply_fields(
        doc,
        data,
        {
            "api_key": "",
            "agent_url": "http://crowdsec:8080",
            "log_level": "info",
            "cloudflare": "on",
        },
    )
    assert data["api_key"] == "secret-old"
    assert data["log_level"] == "info"
    assert data["is_proxied_behind_cloudflare"] is True
    assert data["extra"] is True


def test_ip_cidr_split():
    data: dict = {}
    csconfig._apply_ip_cidr(data, ["192.168.1.10", "10.0.0.0/8", "2001:db8::1"])
    assert data["whitelist"]["ip"] == ["192.168.1.10", "2001:db8::1"]
    assert data["whitelist"]["cidr"] == ["10.0.0.0/8"]
    roundtrip = csconfig._ip_cidr_from_whitelist(data)
    assert "10.0.0.0/8" in roundtrip
    assert "192.168.1.10" in roundtrip


def test_path_safety(tmp_path: Path | None = None):
    root = Path(tmp_path) if tmp_path else Path(".").resolve()
    cfg = {"crowdsec": {"config_dir": str(root / "cs"), "bouncer_config": str(root / "b.yaml")}}
    (root / "cs").mkdir(parents=True, exist_ok=True)
    ok = root / "cs" / "config.yaml"
    ok.write_text("common:\n  log_level: info\n", encoding="utf-8")
    assert csconfig.allowed_write_path(cfg, ok)
    assert not csconfig.allowed_write_path(cfg, root / "cs" / "local_api_credentials.yaml")
    assert not csconfig.allowed_write_path(cfg, root / "other.yaml")
    assert csconfig.allowed_write_path(cfg, Path(cfg["crowdsec"]["bouncer_config"]))
    assert csconfig._normalize_rel("../etc/passwd") == ""
    assert csconfig._normalize_rel("acquis.d/foo.yaml") == "acquis.d/foo.yaml"
    assert csconfig._normalize_rel("collections/linux.yaml") == "collections/linux.yaml"


def test_save_form_and_raw(tmp_path: Path):
    bouncer = tmp_path / "plugin" / "config.yaml"
    csdir = tmp_path / "crowdsec"
    csdir.mkdir()
    bouncer.parent.mkdir()
    cfg = {
        "crowdsec": {
            "config_dir": str(csdir),
            "bouncer_config": str(bouncer),
        }
    }
    ok, msg = csconfig.save_document_form(
        cfg,
        "bouncer",
        {
            "api_key": "k1",
            "agent_url": "http://crowdsec:8080",
            "log_level": "info",
        },
    )
    assert ok, msg
    loaded = csconfig.load_yaml(bouncer)
    assert loaded["log_level"] == "info"
    assert loaded["api_key"] == "k1"

    engine = csdir / "config.yaml"
    engine.write_text(
        "common:\n  log_level: info\n  log_dir: /var/log\napi:\n  server:\n    listen_uri: 127.0.0.1:8080\n",
        encoding="utf-8",
    )
    ok, msg = csconfig.save_document_form(
        cfg,
        "engine",
        {"log_level": "debug", "listen_uri": "0.0.0.0:8080", "trusted_ips": "127.0.0.1\n::1"},
    )
    assert ok, msg
    loaded = csconfig.load_yaml(engine)
    assert loaded["common"]["log_dir"] == "/var/log"
    assert loaded["common"]["log_level"] == "debug"
    assert loaded["api"]["server"]["listen_uri"] == "0.0.0.0:8080"
    bak = engine.with_name("config.yaml.bak")
    assert bak.is_file()

    ok, msg = csconfig.save_document_form(
        cfg,
        "whitelist",
        {"entries": "192.168.0.0/16\n1.2.3.4"},
    )
    assert ok, msg
    wl = csconfig.load_yaml(csdir / "parsers/s02-enrich/zoraxy-guard-whitelist.yaml")
    assert "1.2.3.4" in wl["whitelist"]["ip"]
    assert "192.168.0.0/16" in wl["whitelist"]["cidr"]
    po = csdir / "postoverflows/s01-whitelist/zoraxy-guard-whitelist.yaml"
    assert po.is_file()

    extra = csdir / "acquis.d" / "custom.yaml"
    extra.parent.mkdir(exist_ok=True)
    extra.write_text("filenames:\n  - /tmp/a.log\n", encoding="utf-8")
    ok, msg = csconfig.save_extra_raw(cfg, "acquis.d/custom.yaml", "filenames:\n  - /tmp/b.log\n")
    assert ok, msg
    assert "/tmp/b.log" in extra.read_text(encoding="utf-8")

    ok, msg = csconfig.save_extra_raw(cfg, "../escape.yaml", "a: 1\n")
    assert not ok

    ctx = csconfig.setup_context(cfg)
    ids = [d["id"] for d in ctx["documents"]]
    assert ids == [d.id for d in csconfig.DOCUMENTS]
    bview = next(d for d in ctx["documents"] if d["id"] == "bouncer")
    assert bview["exists"]
    assert bview["writable"]


def test_missing_mount_not_fatal(tmp_path: Path):
    cfg = {
        "crowdsec": {
            "config_dir": str(tmp_path / "nope"),
            "bouncer_config": str(tmp_path / "missing" / "config.yaml"),
        }
    }
    ctx = csconfig.setup_context(cfg)
    assert ctx["config_dir_status"]["missing"]
    bouncer = next(d for d in ctx["documents"] if d["id"] == "bouncer")
    assert bouncer["missing"]
    ok, _ = csconfig.save_document_form(cfg, "bouncer", {"log_level": "info"})
    assert not ok


def test_engine_capi_fields_and_help():
    doc = csconfig.get_doc("engine")
    names = {f.name for f in doc.fields}
    assert "capi_community" in names
    assert "capi_blocklists" in names
    assert any(f.help for f in doc.fields)
    data = {"common": {"log_level": "info"}, "keep": True}
    csconfig.apply_fields(
        doc,
        data,
        {
            "log_level": "debug",
            "capi_community": "on",
            "capi_blocklists": "",
            "capi_sharing": "on",
            "listen_uri": "0.0.0.0:8080",
            "db_max_items": "8000",
            "db_max_age": "14d",
        },
    )
    assert data["keep"] is True
    assert data["api"]["server"]["online_client"]["pull"]["community"] is True
    assert data["api"]["server"]["online_client"]["pull"]["blocklists"] is False
    assert data["db_config"]["flush"]["max_items"] == 8000


def test_capi_whitelist_and_profiles(tmp_path: Path):
    csdir = tmp_path / "crowdsec"
    csdir.mkdir()
    cfg = {"crowdsec": {"config_dir": str(csdir), "bouncer_config": str(tmp_path / "b.yaml")}}
    ok, msg = csconfig.save_document_form(cfg, "capi_wl", {"entries": "9.9.9.9\n8.8.8.0/24"})
    assert ok, msg
    loaded = csconfig.load_yaml(csdir / "capi_whitelists.yaml")
    assert loaded["ips"] == ["9.9.9.9"]
    assert loaded["cidrs"] == ["8.8.8.0/24"]

    (csdir / "profiles.yaml").write_text(
        "name: default_ip_remediation\n"
        "decisions:\n  - type: ban\n    duration: 4h\non_success: break\n",
        encoding="utf-8",
    )
    ok, msg = csconfig.save_document_form(cfg, "profiles", {"duration": "24h"})
    assert ok, msg
    docs = csconfig._load_yaml_docs(csdir / "profiles.yaml")
    assert csconfig._profiles_duration(docs) == "24h"


def test_hub_collections_and_simulation(tmp_path: Path):
    from app import cshub

    csdir = tmp_path / "crowdsec"
    (csdir / "collections").mkdir(parents=True)
    (csdir / "scenarios").mkdir()
    (csdir / "hub" / "collections").mkdir(parents=True)
    cfg = {"crowdsec": {"config_dir": str(csdir), "bouncer_config": str(tmp_path / "b.yaml")}}
    (csdir / "collections" / "linux.yaml").write_text("name: crowdsecurity/linux\n", encoding="utf-8")
    (csdir / "scenarios" / "http-probing.yaml").write_text(
        "name: crowdsecurity/http-probing\ndescription: probe\n",
        encoding="utf-8",
    )
    (csdir / "hub" / ".index.json").write_text(
        '{"collections": {"crowdsecurity/http-cve": {"path": "collections/http-cve.yaml", "description": "cves"}}}',
        encoding="utf-8",
    )
    (csdir / "hub" / "collections" / "http-cve.yaml").write_text(
        "name: crowdsecurity/http-cve\nparsers: []\nscenarios: []\n",
        encoding="utf-8",
    )
    view = cshub.collections_view(cfg)
    ids = [r["id"] for r in view["rows"]]
    assert "crowdsecurity/linux" in ids
    linux = next(r for r in view["rows"] if r["id"] == "crowdsecurity/linux")
    assert linux["installed"]
    assert linux["locked"]
    (csdir / "hub" / "scenarios").mkdir(parents=True, exist_ok=True)
    (csdir / "hub" / "collections" / "http-cve.yaml").write_text(
        "name: crowdsecurity/http-cve\n"
        "parsers: []\n"
        "scenarios:\n  - crowdsecurity/http-cve-probe\n",
        encoding="utf-8",
    )
    (csdir / "hub" / "scenarios" / "http-cve-probe.yaml").write_text(
        "name: crowdsecurity/http-cve-probe\ndescription: probe cve\n",
        encoding="utf-8",
    )
    ok, msg = cshub.install_collections(cfg, ["crowdsecurity/linux", "crowdsecurity/http-cve"])
    assert ok, msg
    assert (csdir / "collections" / "http-cve.yaml").is_file()
    assert (csdir / "scenarios" / "http-cve-probe.yaml").is_file()
    ok, msg = cshub.sync_collections(cfg, [])  # linux stays locked
    assert ok, msg
    assert (csdir / "collections" / "linux.yaml").is_file()
    assert not (csdir / "collections" / "http-cve.yaml").is_file()
    assert not (csdir / "scenarios" / "http-cve-probe.yaml").is_file()
    ok, msg = cshub.save_simulation(cfg, global_simulation=False, ban_enabled=[])
    assert ok, msg
    sim = cshub.load_simulation(cfg)
    assert "crowdsecurity/http-probing" in sim["exclusions"]


if __name__ == "__main__":
    from tempfile import TemporaryDirectory

    test_nested_set_keeps_unknown()
    test_apply_fields_password_keep()
    test_ip_cidr_split()
    with TemporaryDirectory() as td:
        root = Path(td)
        test_path_safety(root / "safe")
        test_save_form_and_raw(root / "work")
        test_missing_mount_not_fatal(root / "miss")
        test_capi_whitelist_and_profiles(root / "wl")
        test_hub_collections_and_simulation(root / "hub")
    test_engine_capi_fields_and_help()
    print("csconfig tests ok")
