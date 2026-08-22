#!/usr/bin/env python3
"""
test_meshcore_map_directory.py

Reines Diagnose-Skript fuer die offizielle MeshCore Map API.
Es schreibt NICHT nach QuestDB oder SQLite.

Getestete Quelle:
    https://map.meshcore.dev/api/v1/nodes

Die offizielle Map verwendet laut Frontend:
    https://map.meshcore.dev/api/v1/nodes?binary=1&short=1

Dieses Skript versucht zunaechst eine JSON-Variante. Falls der Server nur
MessagePack liefert, wird optional das Python-Paket "msgpack" verwendet.

Beispiele:
    python test_meshcore_map_directory.py
    python test_meshcore_map_directory.py 1dea 827c bbca 1dea8f 6dc4 89e5 01e4
    python test_meshcore_map_directory.py --verbose
    python test_meshcore_map_directory.py --api-url https://map.meshcore.dev/api/v1/nodes
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_API_URL = "https://map.meshcore.dev/api/v1/nodes"
DEFAULT_IDS = ["1dea", "827c", "bbca", "1dea8f", "6dc4", "89e5", "01e4"]
USER_AGENT = "MeshCore-PacketTap-MapDirectory-Test/0.1"

TYPE_NAMES = {
    "1": "companion",
    "2": "repeater",
    "3": "room_server",
    "4": "sensor",
    1: "companion",
    2: "repeater",
    3: "room_server",
    4: "sensor",
}


def norm_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return "".join(
        ch for ch in str(value or "").strip().lower()
        if ch in "0123456789abcdef"
    )


def valid_path_id(value: str) -> bool:
    return len(norm_hex(value)) in (2, 4, 6)


def to_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def first_value(node: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in node and node[key] not in (None, ""):
            return node[key]
    return None


def public_key_of(node: dict[str, Any]) -> str | None:
    value = first_value(
        node,
        "public_key",
        "pubkey",
        "publicKey",
        "pk",
        "key",
        "node_id",
        "nodeId",
    )
    if value is None:
        return None
    key = norm_hex(value)
    return key if len(key) == 64 else None


def role_of(node: dict[str, Any]) -> str | None:
    value = first_value(
        node,
        "node_role",
        "role",
        "type",
        "t",
    )
    if value is None:
        return None
    return TYPE_NAMES.get(value, TYPE_NAMES.get(str(value), str(value)))


def name_of(node: dict[str, Any]) -> str | None:
    value = first_value(
        node,
        "adv_name",
        "name",
        "node_name",
        "nodeName",
        "n",
    )
    return str(value) if value not in (None, "") else None


def coordinate_pair(node: dict[str, Any]) -> tuple[float | None, float | None]:
    lat = first_value(node, "lat", "latitude", "adv_lat", "la_lat")
    lon = first_value(node, "lon", "lng", "longitude", "adv_lon", "lo")

    if lat is not None or lon is not None:
        return to_float(lat), to_float(lon)

    coords = first_value(node, "coords", "coordinates", "c")
    if isinstance(coords, dict):
        lat = first_value(coords, "lat", "latitude", "y")
        lon = first_value(coords, "lon", "lng", "longitude", "x")
        return to_float(lat), to_float(lon)

    if isinstance(coords, (list, tuple)) and len(coords) >= 2:
        a = to_float(coords[0])
        b = to_float(coords[1])
        if a is not None and b is not None:
            # Most APIs use [lat, lon]. If first looks impossible for latitude,
            # assume [lon, lat].
            if abs(a) <= 90 and abs(b) <= 180:
                return a, b
            if abs(b) <= 90 and abs(a) <= 180:
                return b, a

    return None, None


def last_seen_of(node: dict[str, Any]) -> str | None:
    value = first_value(
        node,
        "last_seen",
        "last_advert",
        "updated_date",
        "updated_at",
        "ud",
        "la",
    )
    return str(value) if value not in (None, "") else None


def extract_nodes(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    for key in ("nodes", "items", "results", "data", "entries"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            for subkey in ("nodes", "items", "results", "data"):
                sub = value.get(subkey)
                if isinstance(sub, list):
                    return [item for item in sub if isinstance(item, dict)]

    if public_key_of(payload):
        return [payload]

    return []


def request_bytes(url: str, timeout: float) -> tuple[bytes, str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, application/msgpack, application/octet-stream;q=0.9, */*;q=0.1",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        content_type = response.headers.get("Content-Type", "")
        return response.read(), content_type


def decode_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def decode_msgpack(raw: bytes) -> Any:
    try:
        import msgpack  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "MessagePack-Antwort erkannt, aber Python-Paket 'msgpack' fehlt. "
            "Installieren mit: pip install msgpack"
        ) from exc

    return msgpack.unpackb(raw, raw=False, strict_map_key=False)


def load_directory(
    api_url: str,
    timeout: float,
    verbose: bool = False,
) -> tuple[list[dict[str, Any]], str]:
    attempts = [
        ("JSON short", api_url + "?" + urllib.parse.urlencode({"short": "1"}), "json"),
        ("JSON full", api_url, "json"),
        (
            "MessagePack short",
            api_url + "?" + urllib.parse.urlencode({"binary": "1", "short": "1"}),
            "msgpack",
        ),
    ]

    errors: list[str] = []

    for label, url, decoder in attempts:
        if verbose:
            print(f"Versuch: {label}")
            print(f"  URL: {url}")

        try:
            raw, content_type = request_bytes(url, timeout)
        except Exception as exc:
            errors.append(f"{label}: {exc}")
            if verbose:
                print(f"  FEHLER: {exc}")
            continue

        if verbose:
            print(f"  Content-Type: {content_type or '–'}")
            print(f"  Bytes       : {len(raw)}")

        try:
            payload = decode_json(raw) if decoder == "json" else decode_msgpack(raw)
        except Exception as exc:
            errors.append(f"{label}: Decode-Fehler: {exc}")
            if verbose:
                print(f"  Decode-Fehler: {exc}")
            continue

        nodes = extract_nodes(payload)
        if nodes:
            return nodes, label

        errors.append(f"{label}: keine Node-Liste im Payload erkannt")
        if verbose:
            if isinstance(payload, dict):
                print(f"  Top-Level-Keys: {list(payload.keys())[:30]}")
            else:
                print(f"  Payload-Typ: {type(payload).__name__}")

    raise RuntimeError(
        "MeshCore-Map-Verzeichnis konnte nicht geladen werden.\n  "
        + "\n  ".join(errors)
    )


def normalized_record(node: dict[str, Any]) -> dict[str, Any] | None:
    public_key = public_key_of(node)
    if not public_key:
        return None

    lat, lon = coordinate_pair(node)

    return {
        "public_key": public_key,
        "name": name_of(node),
        "role": role_of(node),
        "lat": lat,
        "lon": lon,
        "last_seen": last_seen_of(node),
        "raw": node,
    }


def print_candidate(index: int, item: dict[str, Any], verbose: bool) -> None:
    pos = "–"
    if item["lat"] is not None and item["lon"] is not None:
        pos = f"{item['lat']:.6f}, {item['lon']:.6f}"

    print(f"    [{index}] {item['name'] or '–'}")
    print(f"        public_key : {item['public_key']}")
    print(f"        role       : {item['role'] or '–'}")
    print(f"        position   : {pos}")
    print(f"        last_seen  : {item['last_seen'] or '–'}")
    print("        source     : meshcore_map")

    if verbose:
        print(f"        raw_keys   : {', '.join(sorted(map(str, item['raw'].keys())))}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test der offiziellen MeshCore Map als Path-ID-Verzeichnis."
    )
    parser.add_argument(
        "path_ids",
        nargs="*",
        default=DEFAULT_IDS,
        help="Path-IDs, z. B. 1dea 827c 1dea8f",
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"API-Endpunkt (Standard: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP-Timeout in Sekunden (Standard: 30)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="API-/Payload-Diagnose ausgeben",
    )
    args = parser.parse_args()

    path_ids = [norm_hex(value) for value in args.path_ids]
    invalid = [value for value in path_ids if not valid_path_id(value)]
    if invalid:
        print(
            "Ungültige Path-ID(s): " + ", ".join(invalid),
            file=sys.stderr,
        )
        return 2

    print("MeshCore Map Directory Test")
    print("=" * 72)
    print(f"API      : {args.api_url}")
    print(f"Path-IDs : {', '.join(path_ids)}")
    print()

    try:
        nodes, transport = load_directory(
            args.api_url,
            args.timeout,
            verbose=args.verbose,
        )
    except Exception as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1

    records: list[dict[str, Any]] = []
    invalid_nodes = 0
    for raw in nodes:
        record = normalized_record(raw)
        if record is None:
            invalid_nodes += 1
            continue
        records.append(record)

    print(f"Verzeichnis geladen über: {transport}")
    print(f"Nodes gesamt           : {len(nodes)}")
    print(f"Nodes mit Public Key   : {len(records)}")
    if invalid_nodes:
        print(f"Nodes ohne Public Key  : {invalid_nodes}")
    print()

    if args.verbose and nodes:
        print("Beispiel Rohdaten-Schlüssel")
        print("-" * 72)
        print(", ".join(sorted(map(str, nodes[0].keys()))))
        print()

    summary: list[tuple[str, int, int, str]] = []

    for path_id in path_ids:
        matches = [
            item
            for item in records
            if item["public_key"].startswith(path_id)
        ]
        matches.sort(
            key=lambda item: (
                0 if item["role"] == "repeater" else 1,
                (item["name"] or "").lower(),
                item["public_key"],
            )
        )

        print(f"{path_id}:")
        if not matches:
            print("  Kein Prefix-Treffer in MeshCore Map.")
            status = "unaufgelöst"
        elif len(matches) == 1:
            print("  EINDEUTIG")
            print_candidate(1, matches[0], args.verbose)
            status = f"eindeutig -> {matches[0]['name'] or matches[0]['public_key'][:12]}"
        else:
            print(f"  KOLLISION / {len(matches)} KANDIDATEN")
            for index, item in enumerate(matches, 1):
                print_candidate(index, item, args.verbose)
            status = "mehrdeutig / Hash-Kollision"

        summary.append(
            (
                path_id,
                len(path_id) // 2,
                len(matches),
                status,
            )
        )
        print()

    print("Zusammenfassung")
    print("=" * 72)
    print(f"{'Path-ID':<10} {'Bytes':<7} {'Treffer':<9} Status")
    print("-" * 72)
    for path_id, byte_count, match_count, status in summary:
        print(
            f"{path_id:<10} "
            f"{byte_count:<7} "
            f"{match_count:<9} "
            f"{status}"
        )

    print()
    print("Hinweis:")
    print(
        "Dieses Skript schreibt nichts nach QuestDB oder SQLite. "
        "Es dient ausschließlich dazu, die offizielle MeshCore Map "
        "als zusätzliche Directory-Quelle zu prüfen."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
