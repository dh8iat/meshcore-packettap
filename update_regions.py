#!/usr/bin/env python3
"""
MeshCore PacketTap - Region Updater

Version: 0.1

Aktualisiert regions.json aus dem kanonischen MeshCore-Regionskatalog:
    https://github.com/marcelverdult/meshcore-regions

Sicherheitskonzept
------------------
* Standard ist DRY-RUN. Ohne --apply wird nichts geschrieben.
* Quelle für reguläre Regionen ist ausschließlich index.json / flat.
* Bestehende lokale Regionen bleiben erhalten.
* Unsortierte Einträge werden NICHT pauschal übernommen.
* Vorläufige, ausdrücklich freigegebene Overrides können aus unsorted/todo.json
  übernommen werden. Aktuell: rhein-neckar.
* Vor dem Schreiben wird regions.json.bak angelegt.

Hintergrund
-----------
Der Decoder bildet den Transport-Key aus "#" + Region-Code. Daher werden die
Upstream-Codes als "#<code>" in regions.json gespeichert.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import urllib.request
from pathlib import Path
from typing import Any

APP_VERSION = "0.1"

INDEX_URL = (
    "https://raw.githubusercontent.com/"
    "marcelverdult/meshcore-regions/main/index.json"
)
UNSORTED_URL = (
    "https://raw.githubusercontent.com/"
    "marcelverdult/meshcore-regions/main/unsorted/todo.json"
)

# Diese Einträge werden nur übernommen, wenn sie in der aktuellen
# unsorted/todo.json der Upstream-Quelle tatsächlich vorkommen.
PENDING_OVERRIDES = {
    "rhein-neckar",
}

REGION_CODE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def fetch_json(url: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": f"meshcore-packettap-region-updater/{APP_VERSION}",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def load_local(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()

    if not isinstance(data, list):
        return set()

    result: set[str] = set()
    for item in data:
        value = str(item or "").strip().lower()
        if value and not value.startswith("#"):
            value = "#" + value
        if value and REGION_CODE_RE.fullmatch(value[1:]):
            result.add(value)
    return result


def load_canonical(data: Any) -> set[str]:
    if not isinstance(data, dict):
        raise RuntimeError("index.json ist kein JSON-Objekt.")

    flat = data.get("flat")
    if not isinstance(flat, list):
        raise RuntimeError("index.json enthält kein gültiges 'flat'-Array.")

    result: set[str] = set()
    for entry in flat:
        if not isinstance(entry, dict):
            continue
        code = str(entry.get("path") or entry.get("code") or "").strip().lower()
        if REGION_CODE_RE.fullmatch(code):
            result.add("#" + code)

    if not result:
        raise RuntimeError("Keine gültigen Regionen in index.json gefunden.")
    return result


def load_unsorted_raw(data: Any) -> set[str]:
    if not isinstance(data, dict):
        return set()

    buckets = data.get("buckets")
    if not isinstance(buckets, dict):
        return set()

    result: set[str] = set()
    for entries in buckets.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            raw = str(entry.get("raw") or "").strip().lower()
            if REGION_CODE_RE.fullmatch(raw):
                result.add(raw)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="regions.json aus marcelverdult/meshcore-regions aktualisieren."
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="MeshCore-PacketTap Projektverzeichnis.",
    )
    parser.add_argument("--index-url", default=INDEX_URL)
    parser.add_argument("--unsorted-url", default=UNSORTED_URL)
    parser.add_argument(
        "--prune-local",
        action="store_true",
        help="Lokale Einträge entfernen, wenn sie nicht mehr aus der Quelle kommen.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="regions.json tatsächlich schreiben.",
    )
    args = parser.parse_args()

    project = args.project_dir.resolve()
    regions_path = project / "regions.json"
    backup_path = project / "regions.json.bak"

    local = load_local(regions_path)

    print("MeshCore Region Updater")
    print("=" * 72)
    print(f"Version             : {APP_VERSION}")
    print(f"Projekt             : {project}")
    print(f"Quelle              : {args.index_url}")
    print(f"Modus               : {'APPLY' if args.apply else 'DRY-RUN'}")
    print()

    index_data = fetch_json(args.index_url)
    canonical = load_canonical(index_data)

    pending_added: set[str] = set()
    pending_missing: set[str] = set()

    if PENDING_OVERRIDES:
        unsorted_data = fetch_json(args.unsorted_url)
        unsorted_raw = load_unsorted_raw(unsorted_data)
        for code in sorted(PENDING_OVERRIDES):
            if code in unsorted_raw:
                pending_added.add("#" + code)
            else:
                pending_missing.add("#" + code)

    source_regions = canonical | pending_added
    selected = set(source_regions)
    if not args.prune_local:
        selected |= local

    added = sorted(selected - local)
    removed = sorted(local - selected)

    print("Bestand")
    print("-" * 72)
    print(f"Lokal vorher        : {len(local)}")
    print(f"Kanonischer Katalog : {len(canonical)}")
    print(f"Pending Overrides   : {len(pending_added)}")
    print(f"Ergebnis            : {len(selected)}")
    print(f"Neu                 : {len(added)}")
    print(f"Entfernt            : {len(removed)}")
    print()

    if pending_added:
        print("Bestätigte Pending-Overrides")
        print("-" * 72)
        for item in sorted(pending_added):
            print(item)
        print()

    if pending_missing:
        print("Nicht mehr in unsorted/todo.json")
        print("-" * 72)
        for item in sorted(pending_missing):
            print(item)
        print()

    if added:
        print("Neue Regionen")
        print("-" * 72)
        for item in added[:100]:
            print(item)
        if len(added) > 100:
            print(f"... und {len(added) - 100} weitere")
        print()

    if removed:
        print("Zu entfernende Regionen")
        print("-" * 72)
        for item in removed[:100]:
            print(item)
        if len(removed) > 100:
            print(f"... und {len(removed) - 100} weitere")
        print()

    if not args.apply:
        print("DRY-RUN beendet. regions.json wurde nicht verändert.")
        return 0

    if regions_path.exists():
        shutil.copy2(regions_path, backup_path)

    regions_path.write_text(
        json.dumps(sorted(selected), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print("Fertig")
    print("-" * 72)
    print(f"Geschrieben          : {regions_path}")
    if backup_path.exists():
        print(f"Sicherung            : {backup_path}")
    print(f"Regionen             : {len(selected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
