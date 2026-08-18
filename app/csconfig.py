"""CrowdSec YAML documents editable from the Guard web UI.

Designed as a registry: add YamlDoc entries to expose more files/fields later.
Guard never talks to cscli; it only reads/writes mounted YAML.
"""
from __future__ import annotations

import copy
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from .fileio import write_text

DEFAULT_CONFIG_DIR = "/crowdsec-config"
DEFAULT_BOUNCER_CONFIG = "/crowdsec-bouncer/config.yaml"

CREDENTIAL_NAMES = frozenset(
    {
        "local_api_credentials.yaml",
        "online_api_credentials.yaml",
        "local_api_credentials.yml",
        "online_api_credentials.yml",
    }
)

YAML_SUFFIXES = {".yaml", ".yml"}

LOG_LEVELS = ("trace", "debug", "info", "warning", "error")


@dataclass(frozen=True)
class Field:
    """One form control mapped onto a YAML path (dotted)."""

    name: str
    yaml_path: str
    kind: str  # text | password | bool | select | list | ip_cidr_list
    label: str
    hint: str = ""
    options: Tuple[str, ...] = ()
    keep_if_empty: bool = False
    default: Any = None


@dataclass(frozen=True)
class YamlDoc:
    """A CrowdSec (or bouncer) YAML file the UI can edit."""

    id: str
    title: str
    hint: str
    restart: str
    relpath: str = ""  # under config_dir; unused for bouncer
    bouncer: bool = False
    create_if_missing: bool = False
    raw_only: bool = False
    fields: Tuple[Field, ...] = ()
    defaults: Dict[str, Any] = field(default_factory=dict)
    # Extra copies written with the same mapping (e.g. parser + postoverflow whitelist)
    also_relpaths: Tuple[str, ...] = ()


# --- registry (append here to expose more YAML later) -----------------------

DOCUMENTS: Tuple[YamlDoc, ...] = (
    YamlDoc(
        id="bouncer",
        title="Zoraxy-Bouncer",
        hint=(
            "Plugin-config.yaml des Zoraxy CrowdSec-Bouncers. "
            "log_level info ist nötig, damit «Request blocked» in den Zoraxy-Logs steht. "
            "Unraid-Images, die die Datei beim Start aus Env bauen, brauchen CROWDSEC_LOG_LEVEL=info."
        ),
        restart="Danach Zoraxy- bzw. Plugin-Container neu starten.",
        bouncer=True,
        create_if_missing=True,
        defaults={
            "api_key": "",
            "agent_url": "http://crowdsec:8080",
            "log_level": "info",
            "is_proxied_behind_cloudflare": False,
        },
        fields=(
            Field(
                "api_key",
                "api_key",
                "password",
                "API-Key",
                "cscli bouncers add zoraxy-bouncer — leer lassen, um den vorhandenen Key zu behalten.",
                keep_if_empty=True,
                default="",
            ),
            Field(
                "agent_url",
                "agent_url",
                "text",
                "CrowdSec LAPI (agent_url)",
                "Aus dem Guard-/Zoraxy-Container erreichbar, z. B. http://crowdsec:8080",
                default="http://crowdsec:8080",
            ),
            Field(
                "log_level",
                "log_level",
                "select",
                "Log-Level",
                "info oder debug, sonst fehlen die Block-Zeilen im Reiter Auswertung.",
                options=LOG_LEVELS,
                default="info",
            ),
            Field(
                "cloudflare",
                "is_proxied_behind_cloudflare",
                "bool",
                "Hinter Cloudflare (echte Client-IP)",
                "Setzen, wenn Zoraxy hinter Cloudflare sitzt.",
                default=False,
            ),
        ),
    ),
    YamlDoc(
        id="engine",
        title="CrowdSec Engine (config.yaml)",
        hint=(
            "Nur ausgewählte Schlüssel — unbekannte Abschnitte bleiben erhalten. "
            "Formular-Speichern entfernt YAML-Kommentare (Backup .bak)."
        ),
        restart="Danach CrowdSec-Container neu starten.",
        relpath="config.yaml",
        create_if_missing=False,
        fields=(
            Field(
                "log_level",
                "common.log_level",
                "select",
                "Log-Level",
                "",
                options=LOG_LEVELS,
                default="info",
            ),
            Field(
                "listen_uri",
                "api.server.listen_uri",
                "text",
                "LAPI listen_uri",
                "Im Docker oft 0.0.0.0:8080, damit der Bouncer verbinden kann.",
                default="0.0.0.0:8080",
            ),
            Field(
                "forwarded_for",
                "api.server.use_forwarded_for_headers",
                "bool",
                "X-Forwarded-For auswerten",
                "Nur mit vertrauenswürdigem Proxy und trusted_ips.",
                default=False,
            ),
            Field(
                "trusted_ips",
                "api.server.trusted_ips",
                "list",
                "Trusted IPs / CIDRs",
                "Eine pro Zeile. IPs, denen Forwarded-For bzw. Admin-API erlaubt ist.",
                default=["127.0.0.1", "::1"],
            ),
        ),
    ),
    YamlDoc(
        id="acquis",
        title="Log-Erfassung (acquis.d)",
        hint=(
            "Eigene Overlay-Datei acquis.d/zoraxy-guard.yaml. "
            "Pfade gelten im CrowdSec-Container, nicht in Guard."
        ),
        restart="Danach CrowdSec-Container neu starten.",
        relpath="acquis.d/zoraxy-guard.yaml",
        create_if_missing=True,
        defaults={
            "source": "file",
            "filenames": ["/var/log/zoraxy/*.log"],
            "labels": {"type": "syslog"},
        },
        fields=(
            Field(
                "filenames",
                "filenames",
                "list",
                "Log-Dateien / Globs",
                "Eine pro Zeile. Muss im CrowdSec-Container existieren.",
                default=["/var/log/zoraxy/*.log"],
            ),
            Field(
                "log_type",
                "labels.type",
                "text",
                "Parser-Typ (labels.type)",
                "z. B. syslog, nginx — nur wenn die passende Collection installiert ist.",
                default="syslog",
            ),
        ),
    ),
    YamlDoc(
        id="whitelist",
        title="Whitelist (IPs / CIDRs)",
        hint=(
            "Lokale Overlay-Parser, die diese IPs nicht bannen. "
            "Wird nach parsers/s02-enrich und postoverflows/s01-whitelist geschrieben."
        ),
        restart="Danach CrowdSec-Container neu starten.",
        relpath="parsers/s02-enrich/zoraxy-guard-whitelist.yaml",
        also_relpaths=("postoverflows/s01-whitelist/zoraxy-guard-whitelist.yaml",),
        create_if_missing=True,
        defaults={
            "name": "zoraxy-guard/whitelist",
            "description": "IPs/CIDRs never banned (Zoraxy Guard)",
            "filter": "true",
            "whitelist": {
                "reason": "trusted (Zoraxy Guard)",
                "ip": [],
                "cidr": [],
            },
        },
        fields=(
            Field(
                "entries",
                "whitelist",
                "ip_cidr_list",
                "IPs und CIDRs",
                "Eine pro Zeile. Mit / wird als CIDR gespeichert, sonst als IP.",
                default=[],
            ),
        ),
    ),
    YamlDoc(
        id="console",
        title="Console / Sharing",
        hint="Welche Entscheidungen mit der CrowdSec Console geteilt werden.",
        restart="Danach CrowdSec-Container neu starten.",
        relpath="console.yaml",
        create_if_missing=False,
        fields=(
            Field(
                "share_manual",
                "share_manual_decisions",
                "bool",
                "Manuelle Entscheidungen teilen",
                default=False,
            ),
            Field(
                "share_tainted",
                "share_tainted",
                "bool",
                "Tainted Scenarios teilen",
                default=False,
            ),
            Field(
                "share_custom",
                "share_custom",
                "bool",
                "Eigene Scenarios teilen",
                default=False,
            ),
        ),
    ),
    YamlDoc(
        id="profiles",
        title="Profile (Ban-Dauer)",
        hint="Komplexe YAML — vorerst nur Raw-Editor. Später Felder für default_duration.",
        restart="Danach CrowdSec-Container neu starten.",
        relpath="profiles.yaml",
        create_if_missing=False,
        raw_only=True,
    ),
)

DOCS_BY_ID: Dict[str, YamlDoc] = {d.id: d for d in DOCUMENTS}


def crowdsec_section(cfg: Optional[dict]) -> dict:
    raw = (cfg or {}).get("crowdsec")
    return raw if isinstance(raw, dict) else {}


def config_dir(cfg: Optional[dict]) -> str:
    cs = crowdsec_section(cfg)
    val = (
        str(cs.get("config_dir") or "").strip()
        or (os.environ.get("CROWDSEC_CONFIG_DIR") or "").strip()
        or DEFAULT_CONFIG_DIR
    )
    return val.rstrip("/\\")


def bouncer_config(cfg: Optional[dict]) -> str:
    cs = crowdsec_section(cfg)
    return (
        str(cs.get("bouncer_config") or "").strip()
        or (os.environ.get("CROWDSEC_BOUNCER_CONFIG") or "").strip()
        or DEFAULT_BOUNCER_CONFIG
    )


def get_doc(doc_id: str) -> Optional[YamlDoc]:
    return DOCS_BY_ID.get((doc_id or "").strip())


def document_path(cfg: Optional[dict], doc: YamlDoc) -> Path:
    if doc.bouncer:
        return Path(bouncer_config(cfg))
    return Path(config_dir(cfg)) / doc.relpath


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def _is_under(child: Path, root: Path) -> bool:
    try:
        child_r = _resolve(child)
        root_r = _resolve(root)
        return child_r == root_r or root_r in child_r.parents
    except (OSError, ValueError):
        return False


def allowed_write_path(cfg: Optional[dict], target: Path) -> bool:
    """Only bouncer file or anything under config_dir, never credential files."""
    name = target.name.lower()
    if name in CREDENTIAL_NAMES:
        return False
    if target.suffix.lower() not in YAML_SUFFIXES:
        return False
    resolved = _resolve(target)
    bpath = _resolve(Path(bouncer_config(cfg)))
    if resolved == bpath:
        return True
    root = Path(config_dir(cfg))
    if not str(root):
        return False
    return _is_under(resolved, root)


def _nested_get(data: Any, dotted: str) -> Any:
    cur = data
    if not dotted:
        return cur
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _nested_set(data: dict, dotted: str, value: Any) -> None:
    parts = [p for p in dotted.split(".") if p]
    if not parts:
        return
    cur: dict = data
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def parse_list(text: str) -> List[str]:
    items: List[str] = []
    for part in (text or "").replace(",", "\n").splitlines():
        part = part.strip()
        if part:
            items.append(part)
    return items


def list_as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(str(x) for x in value)
    return str(value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _ip_cidr_from_whitelist(data: dict) -> List[str]:
    wl = data.get("whitelist") if isinstance(data.get("whitelist"), dict) else {}
    ips = list(wl.get("ip") or []) if isinstance(wl, dict) else []
    cidrs = list(wl.get("cidr") or []) if isinstance(wl, dict) else []
    return [str(x) for x in ips] + [str(x) for x in cidrs]


def _apply_ip_cidr(data: dict, entries: Sequence[str]) -> None:
    ips: List[str] = []
    cidrs: List[str] = []
    for item in entries:
        (cidrs if "/" in item else ips).append(item)
    wl = data.get("whitelist")
    if not isinstance(wl, dict):
        wl = {}
        data["whitelist"] = wl
    wl["ip"] = ips
    wl["cidr"] = cidrs
    wl.setdefault("reason", "trusted (Zoraxy Guard)")
    data.setdefault("name", "zoraxy-guard/whitelist")
    data.setdefault("description", "IPs/CIDRs never banned (Zoraxy Guard)")
    data.setdefault("filter", "true")


def apply_fields(doc: YamlDoc, data: dict, form: dict) -> dict:
    """Patch known fields onto an existing mapping; unknown keys stay."""
    if not isinstance(data, dict):
        data = {}
    for fld in doc.fields:
        raw = form.get(fld.name)
        if fld.kind == "bool":
            # checkbox: missing means false
            _nested_set(data, fld.yaml_path, raw in ("on", "true", "1", "yes", True))
            continue
        if fld.kind == "password" and fld.keep_if_empty and not str(raw or "").strip():
            continue
        if fld.kind == "list":
            _nested_set(data, fld.yaml_path, parse_list(str(raw or "")))
            continue
        if fld.kind == "ip_cidr_list":
            _apply_ip_cidr(data, parse_list(str(raw or "")))
            continue
        if fld.kind == "select":
            val = str(raw or "").strip() or str(fld.default or "")
            if fld.options and val not in fld.options:
                val = str(fld.default or (fld.options[0] if fld.options else val))
            _nested_set(data, fld.yaml_path, val)
            continue
        text = "" if raw is None else str(raw).strip()
        _nested_set(data, fld.yaml_path, text)
    return data


def dump_yaml(data: Any) -> str:
    return yaml.safe_dump(
        data, sort_keys=False, allow_unicode=True, default_flow_style=False
    )


def load_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    loaded = yaml.safe_load(text)
    return {} if loaded is None else loaded


def _backup(path: Path) -> None:
    if not path.is_file():
        return
    bak = path.with_name(path.name + ".bak")
    try:
        bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    except OSError:
        pass


def _parent_writable(path: Path) -> bool:
    parent = path.parent
    return parent.is_dir() and os.access(parent, os.W_OK)


def can_create(path: Path, root: Optional[Path] = None) -> bool:
    if path.exists():
        return path.is_file() and os.access(path, os.W_OK)
    if _parent_writable(path):
        return True
    if root and root.is_dir() and os.access(root, os.W_OK) and _is_under(path, root):
        return True
    return False


def path_status(path: Path, *, root: Optional[Path] = None, create: bool = False) -> dict:
    exists = path.exists()
    is_file = path.is_file()
    writable = False
    if is_file:
        writable = os.access(path, os.W_OK)
    elif create:
        writable = can_create(path, root)
    mtime = ""
    if is_file:
        try:
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(path.stat().st_mtime))
        except OSError:
            mtime = ""
    return {
        "path": str(path),
        "exists": exists,
        "is_file": is_file,
        "writable": writable,
        "mtime": mtime,
        "missing": not exists,
    }


def _write_mapping(path: Path, data: dict, *, root: Optional[Path] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _backup(path)
    write_text(str(path), dump_yaml(data))


def save_document_form(cfg: Optional[dict], doc_id: str, form: dict) -> Tuple[bool, str]:
    doc = get_doc(doc_id)
    if not doc:
        return False, "Unbekanntes YAML-Dokument."
    if doc.raw_only:
        return False, "Diese Datei nur als Raw YAML speichern."
    path = document_path(cfg, doc)
    if not allowed_write_path(cfg, path):
        return False, f"Pfad nicht erlaubt: {path}"
    root = Path(config_dir(cfg)) if not doc.bouncer else None
    data: dict = {}
    if path.is_file():
        loaded = load_yaml(path)
        if not isinstance(loaded, dict):
            return False, "Datei ist keine YAML-Map — Raw YAML verwenden."
        data = loaded
    elif doc.create_if_missing and can_create(path, root):
        data = copy.deepcopy(doc.defaults) if doc.defaults else {}
    elif not path.exists():
        return False, (
            f"Datei nicht gefunden: {path}. "
            "CrowdSec- bzw. Bouncer-Pfad in Unraid mounten."
        )
    else:
        return False, f"Nicht schreibbar: {path}"

    apply_fields(doc, data, form)
    try:
        _write_mapping(path, data, root=root)
        for rel in doc.also_relpaths:
            extra = Path(config_dir(cfg)) / rel
            if not allowed_write_path(cfg, extra):
                continue
            _write_mapping(extra, data, root=root)
    except OSError as exc:
        return False, f"Speichern fehlgeschlagen: {exc}"
    return True, f"{doc.title} gespeichert. {doc.restart}"


def save_document_raw(cfg: Optional[dict], doc_id: str, text: str) -> Tuple[bool, str]:
    doc = get_doc(doc_id)
    if not doc:
        return False, "Unbekanntes YAML-Dokument."
    path = document_path(cfg, doc)
    return save_raw_path(cfg, path, text, create=doc.create_if_missing, title=doc.title, restart=doc.restart)


def save_raw_path(
    cfg: Optional[dict],
    path: Path,
    text: str,
    *,
    create: bool = False,
    title: str = "YAML",
    restart: str = "",
) -> Tuple[bool, str]:
    if not allowed_write_path(cfg, path):
        return False, f"Pfad nicht erlaubt: {path}"
    try:
        loaded = yaml.safe_load(text or "")
    except yaml.YAMLError as exc:
        return False, f"Ungültiges YAML: {exc}"
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, (dict, list)):
        return False, "YAML-Wurzel muss ein Mapping oder eine Liste sein."
    root = Path(config_dir(cfg))
    if not path.exists() and not (create and can_create(path, root)):
        return False, f"Datei nicht gefunden: {path}"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _backup(path)
        body = text if text.endswith("\n") else (text + "\n")
        write_text(str(path), body)
    except OSError as exc:
        return False, f"Speichern fehlgeschlagen: {exc}"
    extra = f" {restart}" if restart else ""
    return True, f"{title} gespeichert.{extra}"


def save_extra_raw(cfg: Optional[dict], rel: str, text: str) -> Tuple[bool, str]:
    rel_n = _normalize_rel(rel)
    if not rel_n:
        return False, "Ungültiger Dateipfad."
    path = Path(config_dir(cfg)) / rel_n
    return save_raw_path(cfg, path, text, create=False, title=rel_n)


def _normalize_rel(rel: str) -> str:
    rel = (rel or "").replace("\\", "/").strip().lstrip("/")
    if not rel or ".." in Path(rel).parts:
        return ""
    p = Path(rel)
    if p.suffix.lower() not in YAML_SUFFIXES:
        return ""
    if p.name.lower() in CREDENTIAL_NAMES:
        return ""
    return str(p).replace("\\", "/")


def field_value(doc: YamlDoc, fld: Field, data: Any) -> Any:
    if not isinstance(data, dict):
        data = {}
    if fld.kind == "ip_cidr_list":
        return _ip_cidr_from_whitelist(data)
    val = _nested_get(data, fld.yaml_path)
    if val is None:
        return fld.default
    return val


def document_view(cfg: Optional[dict], doc: YamlDoc) -> dict:
    path = document_path(cfg, doc)
    root = None if doc.bouncer else Path(config_dir(cfg))
    st = path_status(path, root=root, create=doc.create_if_missing)
    data: Any = None
    yaml_text = ""
    load_error = ""
    mapping = False
    if path.is_file():
        try:
            data = load_yaml(path)
            yaml_text = path.read_text(encoding="utf-8")
            mapping = isinstance(data, dict)
        except Exception as exc:
            load_error = str(exc)
            data = None
    elif doc.create_if_missing and doc.defaults:
        data = copy.deepcopy(doc.defaults)
        mapping = True
        yaml_text = dump_yaml(data)

    fields_out = []
    for fld in doc.fields:
        val = field_value(doc, fld, data if isinstance(data, dict) else {})
        if fld.kind in ("list", "ip_cidr_list"):
            shown = list_as_text(val)
        elif fld.kind == "bool":
            shown = _as_bool(val)
        elif fld.kind == "password":
            shown = "" if fld.keep_if_empty else ("" if val is None else str(val))
        else:
            shown = "" if val is None else str(val)
        options = list(fld.options)
        if fld.kind == "select" and shown and shown not in options:
            options = [shown] + options
        secret_set = False
        if fld.kind == "password":
            existing = _nested_get(data, fld.yaml_path) if isinstance(data, dict) else None
            secret_set = bool(str(existing or "").strip())
        fields_out.append(
            {
                "name": fld.name,
                "kind": fld.kind,
                "label": fld.label,
                "hint": fld.hint,
                "value": shown,
                "options": options,
                "secret_set": secret_set,
            }
        )

    return {
        "id": doc.id,
        "title": doc.title,
        "hint": doc.hint,
        "restart": doc.restart,
        "raw_only": doc.raw_only or (data is not None and not mapping and not load_error),
        "create_if_missing": doc.create_if_missing,
        "load_error": load_error,
        "yaml_text": yaml_text,
        "fields": fields_out,
        **st,
    }


def list_collections(cfg: Optional[dict]) -> List[dict]:
    root = Path(config_dir(cfg)) / "collections"
    if not root.is_dir():
        return []
    items: List[dict] = []
    files = sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml"))
    for p in files:
        name = p.stem
        try:
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict) and loaded.get("name"):
                name = str(loaded["name"])
        except Exception:
            pass
        items.append(
            {
                "file": p.name,
                "name": name,
                "rel": f"collections/{p.name}",
            }
        )
    return items


def _iter_yaml_under(root: Path, *, max_files: int = 80) -> Iterable[Path]:
    if not root.is_dir():
        return
    skip_dirs = {".git", "hub", "data", "__pycache__"}
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        # keep walk shallow-ish: parsers/s02-enrich is depth 2
        rel_dir = os.path.relpath(dirpath, root)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        if depth > 3:
            dirnames[:] = []
            continue
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.suffix.lower() not in YAML_SUFFIXES:
                continue
            if name.lower() in CREDENTIAL_NAMES:
                continue
            yield p
            n += 1
            if n >= max_files:
                return


def list_extra_files(cfg: Optional[dict]) -> List[dict]:
    root = Path(config_dir(cfg))
    if not root.is_dir():
        return []
    managed = set()
    for doc in DOCUMENTS:
        if doc.bouncer:
            continue
        managed.add(_resolve(document_path(cfg, doc)))
        for rel in doc.also_relpaths:
            managed.add(_resolve(root / rel))
    out: List[dict] = []
    for p in _iter_yaml_under(root):
        if _resolve(p) in managed:
            continue
        rel = p.relative_to(root).as_posix()
        if rel.startswith("collections/"):
            continue
        out.append({"rel": rel, "name": p.name})
    out.sort(key=lambda x: x["rel"])
    return out


def extra_file_view(cfg: Optional[dict], rel: str) -> Optional[dict]:
    rel_n = _normalize_rel(rel)
    if not rel_n:
        return None
    path = Path(config_dir(cfg)) / rel_n
    if not _is_under(path, Path(config_dir(cfg))):
        return None
    st = path_status(path, root=Path(config_dir(cfg)), create=False)
    yaml_text = ""
    load_error = ""
    if path.is_file():
        try:
            yaml_text = path.read_text(encoding="utf-8")
        except OSError as exc:
            load_error = str(exc)
    return {"rel": rel_n, "yaml_text": yaml_text, "load_error": load_error, **st}


def setup_context(cfg: Optional[dict], extra_rel: str = "") -> dict:
    docs = [document_view(cfg, d) for d in DOCUMENTS]
    extra_files = list_extra_files(cfg)
    chosen = extra_rel or (extra_files[0]["rel"] if extra_files else "")
    extra = extra_file_view(cfg, chosen) if chosen else None
    cdir = Path(config_dir(cfg))
    bpath = Path(bouncer_config(cfg))
    return {
        "config_dir": str(cdir),
        "bouncer_config": str(bpath),
        "config_dir_status": path_status(cdir),
        "bouncer_status": path_status(bpath, create=True),
        "documents": docs,
        "collections": list_collections(cfg),
        "extra_files": extra_files,
        "extra": extra,
    }
