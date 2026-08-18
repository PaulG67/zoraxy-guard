"""CrowdSec Hub collections and scenarios visible from the mounted config dir."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import yaml

from . import csconfig
from .fileio import write_text

# Collections CrowdSec accepts; Zoraxy sits in front of HTTP apps.
CATALOG: Tuple[Dict[str, str], ...] = (
    {
        "id": "crowdsecurity/linux",
        "title": "Linux-Basis",
        "description": "Syslog, GeoIP, Datum — Grundlage, nicht entfernen.",
    },
    {
        "id": "crowdsecurity/base-http-scenarios",
        "title": "HTTP-Angriffe (allgemein)",
        "description": "Scanner, Path-Traversal, Bad Bots, HTTP-Brute-Force.",
    },
    {
        "id": "crowdsecurity/http-cve",
        "title": "HTTP-CVEs",
        "description": "Bekannte Exploit-Pfade (Log4j, ThinkPHP, Fortinet, …).",
    },
    {
        "id": "crowdsecurity/http-dos",
        "title": "HTTP-DoS",
        "description": "Auffällige Request-Fluten gegen Web-Apps.",
    },
    {
        "id": "crowdsecurity/whitelist-good-actors",
        "title": "Gute Akteure",
        "description": "Suchmaschinen/Crawler nicht bannen (weniger False Positives).",
    },
    {
        "id": "crowdsecurity/sshd",
        "title": "SSH",
        "description": "SSH-Brute-Force — nur wenn CrowdSec SSH-Logs sieht.",
    },
    {
        "id": "crowdsecurity/nginx",
        "title": "Nginx-Parser",
        "description": "Nur wenn Access-Logs im Nginx-Format ankommen (Zoraxy oft nicht).",
    },
    {
        "id": "crowdsecurity/apache2",
        "title": "Apache-Parser",
        "description": "Nur bei Apache-Combined-Logs hinter Zoraxy.",
    },
    {
        "id": "crowdsecurity/appsec-virtual-patching",
        "title": "AppSec Virtual Patching",
        "description": "WAF-Regeln — braucht einen AppSec-Bouncer, nicht den Zoraxy-Bouncer.",
    },
)

_CATALOG_IDS = {c["id"] for c in CATALOG}


def _hub_dir(cfg: Optional[dict]) -> Path:
    return Path(csconfig.config_dir(cfg)) / "hub"


def load_hub_index(cfg: Optional[dict]) -> dict:
    hub = _hub_dir(cfg)
    for name in (".index.json", "index.json"):
        path = hub / name
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
            except (OSError, json.JSONDecodeError):
                return {}
    return {}


def installed_collection_ids(cfg: Optional[dict]) -> Set[str]:
    ids: Set[str] = set()
    for item in csconfig.list_collections(cfg):
        name = str(item.get("name") or "").strip()
        if name:
            ids.add(name)
        stem = Path(str(item.get("file") or "")).stem
        if stem:
            ids.add(f"crowdsecurity/{stem}")
            ids.add(stem)
    return ids


def _collection_installed(installed: Set[str], col_id: str) -> bool:
    if col_id in installed:
        return True
    short = col_id.split("/", 1)[-1]
    return short in installed or f"crowdsecurity/{short}" in installed


def _index_description(index: dict, col_id: str) -> str:
    meta = (index.get("collections") or {}).get(col_id) or {}
    if not isinstance(meta, dict):
        return ""
    return str(meta.get("description") or meta.get("long_description") or "").strip()


def collections_view(cfg: Optional[dict]) -> dict:
    index = load_hub_index(cfg)
    installed = installed_collection_ids(cfg)
    index_cols = index.get("collections") if isinstance(index.get("collections"), dict) else {}
    seen: Set[str] = set()
    rows: List[dict] = []

    def add_row(col_id: str, title: str, description: str, *, recommended: bool) -> None:
        if col_id in seen:
            return
        seen.add(col_id)
        desc = description or _index_description(index, col_id)
        installable = bool(_hub_source_file(cfg, index, "collections", col_id))
        rows.append(
            {
                "id": col_id,
                "title": title or col_id,
                "description": desc,
                "installed": _collection_installed(installed, col_id),
                "recommended": recommended,
                "installable": installable,
            }
        )

    for item in CATALOG:
        add_row(item["id"], item["title"], item["description"], recommended=True)

    for col_id in sorted(index_cols):
        if col_id in seen:
            continue
        meta = index_cols.get(col_id) or {}
        desc = ""
        title = col_id
        if isinstance(meta, dict):
            desc = str(meta.get("description") or "").strip()
            title = str(meta.get("label") or col_id)
        add_row(col_id, title, desc, recommended=False)

    for name in sorted(installed):
        if name in seen or f"crowdsecurity/{name}" in seen:
            continue
        if "/" not in name and f"crowdsecurity/{name}" in seen:
            continue
        add_row(name, name, "Lokal installiert.", recommended=False)

    return {
        "index_present": bool(index),
        "hub_dir": str(_hub_dir(cfg)),
        "rows": rows,
    }


def list_scenarios(cfg: Optional[dict]) -> List[dict]:
    root = Path(csconfig.config_dir(cfg)) / "scenarios"
    if not root.is_dir():
        return []
    out: List[dict] = []
    for p in sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml")):
        name = p.stem
        desc = ""
        try:
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                name = str(loaded.get("name") or name)
                desc = str(loaded.get("description") or loaded.get("label") or "").strip()
        except Exception:
            pass
        out.append({"name": name, "file": p.name, "description": desc})
    return out


def load_simulation(cfg: Optional[dict]) -> dict:
    path = Path(csconfig.config_dir(cfg)) / "simulation.yaml"
    data: dict = {"simulation": False, "exclusions": []}
    if path.is_file():
        try:
            loaded = csconfig.load_yaml(path)
            if isinstance(loaded, dict):
                data["simulation"] = csconfig._as_bool(loaded.get("simulation"))
                excl = loaded.get("exclusions") or []
                if isinstance(excl, list):
                    data["exclusions"] = [str(x) for x in excl if str(x).strip()]
        except Exception:
            pass
    return data


def scenarios_view(cfg: Optional[dict]) -> dict:
    sim = load_simulation(cfg)
    excl = set(sim.get("exclusions") or [])
    items = []
    for sc in list_scenarios(cfg):
        items.append(
            {
                **sc,
                "ban": sc["name"] not in excl,
            }
        )
    return {
        "global_simulation": bool(sim.get("simulation")),
        "rows": items,
    }


def _hub_source_file(cfg: Optional[dict], index: dict, kind: str, item_id: str) -> Optional[Path]:
    hub = _hub_dir(cfg)
    bucket = index.get(kind) if isinstance(index.get(kind), dict) else {}
    meta = bucket.get(item_id) if isinstance(bucket, dict) else None
    rels: List[str] = []
    if isinstance(meta, dict) and meta.get("path"):
        rels.append(str(meta["path"]).lstrip("/"))
    short = item_id.split("/", 1)[-1]
    rels.extend(
        [
            f"{kind}/{short}.yaml",
            f"{kind}/{item_id}.yaml",
            f"{short}.yaml",
        ]
    )
    for rel in rels:
        for cand in (hub / rel, hub / "crowdsecurity" / rel):
            if cand.is_file():
                return cand
    return None


def _dest_for_item(cfg: Optional[dict], index: dict, kind: str, item_id: str, src: Path) -> Path:
    root = Path(csconfig.config_dir(cfg))
    bucket = index.get(kind) if isinstance(index.get(kind), dict) else {}
    meta = bucket.get(item_id) if isinstance(bucket, dict) else None
    if isinstance(meta, dict):
        rel = str(meta.get("path") or "").lstrip("/")
        stage = str(meta.get("stage") or "").strip()
        if kind == "parsers" and stage and not rel:
            rel = f"parsers/{stage}/{src.name}"
        if rel:
            return root / rel
    if kind == "parsers":
        # keep hub-relative stage folders when present
        parts = src.as_posix().split("/parsers/")
        if len(parts) == 2:
            return root / "parsers" / parts[1]
        return root / "parsers" / "s01-parse" / src.name
    if kind == "scenarios":
        return root / "scenarios" / src.name
    if kind == "postoverflows":
        parts = src.as_posix().split("/postoverflows/")
        if len(parts) == 2:
            return root / "postoverflows" / parts[1]
        return root / "postoverflows" / src.name
    return root / "collections" / src.name


def _install_named(cfg: Optional[dict], index: dict, kind: str, item_id: str, seen: Set[str]) -> List[str]:
    key = f"{kind}:{item_id}"
    if key in seen:
        return []
    seen.add(key)
    copied: List[str] = []
    src = _hub_source_file(cfg, index, kind, item_id)
    if src is None:
        return copied
    dest = _dest_for_item(cfg, index, kind, item_id, src)
    if not csconfig.allowed_write_path(cfg, dest):
        return copied
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        write_text(str(dest), src.read_text(encoding="utf-8"))
        copied.append(str(dest.relative_to(Path(csconfig.config_dir(cfg)))))
    if kind != "collections":
        return copied
    try:
        spec = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return copied
    if not isinstance(spec, dict):
        return copied
    for dep_kind, dep_key in (
        ("collections", "collections"),
        ("parsers", "parsers"),
        ("scenarios", "scenarios"),
        ("postoverflows", "postoverflows"),
    ):
        deps = spec.get(dep_key) or []
        if not isinstance(deps, list):
            continue
        for dep in deps:
            dep_id = str(dep).strip()
            if dep_id:
                copied.extend(_install_named(cfg, index, dep_kind, dep_id, seen))
    return copied


def install_collections(cfg: Optional[dict], wanted: Sequence[str]) -> Tuple[bool, str]:
    root = Path(csconfig.config_dir(cfg))
    if not root.is_dir():
        return False, "CrowdSec-Config-Ordner nicht gemountet."
    index = load_hub_index(cfg)
    installed = installed_collection_ids(cfg)
    copied: List[str] = []
    missing: List[str] = []
    seen: Set[str] = set()
    for name in wanted:
        name = str(name).strip()
        if not name:
            continue
        if _collection_installed(installed, name):
            continue
        before = len(copied)
        copied.extend(_install_named(cfg, index, "collections", name, seen))
        if len(copied) == before:
            missing.append(name)
    if copied and not missing:
        return True, (
            f"{len(copied)} Hub-Dateien nach {root} kopiert. "
            "CrowdSec-Container neu starten."
        )
    if copied:
        return True, (
            f"{len(copied)} Dateien kopiert; nicht im lokalen Hub: {', '.join(missing)}. "
            "Fehlende per cscli collections install … im CrowdSec-Container nachziehen, dann neu starten."
        )
    if missing:
        return False, (
            "Kein lokaler Hub zum Kopieren (hub/.index.json bzw. Hub-YAML). "
            "Im CrowdSec-Container: cscli hub update && cscli collections install "
            + ", ".join(missing)
        )
    return True, "Keine neuen Collections — alles Gewählte ist schon installiert."


def save_simulation(
    cfg: Optional[dict],
    *,
    global_simulation: bool,
    ban_enabled: Sequence[str],
) -> Tuple[bool, str]:
    root = Path(csconfig.config_dir(cfg))
    path = root / "simulation.yaml"
    if not (path.is_file() or csconfig.can_create(path, root)):
        return False, f"simulation.yaml nicht schreibbar: {path}"
    all_names = [s["name"] for s in list_scenarios(cfg)]
    enabled = {str(x) for x in ban_enabled}
    exclusions = [n for n in all_names if n not in enabled]
    data: Dict[str, Any] = {"simulation": bool(global_simulation)}
    if exclusions:
        data["exclusions"] = exclusions
    try:
        csconfig._write_mapping(path, data, root=root)
    except OSError as exc:
        return False, f"Speichern fehlgeschlagen: {exc}"
    return True, "Simulation/Scenarios gespeichert. CrowdSec-Container neu starten."


def hub_view(cfg: Optional[dict]) -> dict:
    return {
        "collections": collections_view(cfg),
        "scenarios": scenarios_view(cfg),
    }
