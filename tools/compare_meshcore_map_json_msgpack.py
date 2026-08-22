#!/usr/bin/env python3
"""
compare_meshcore_map_json_msgpack.py

Vergleicht die Node-Mengen der offiziellen MeshCore Map API:

  JSON:
    https://map.meshcore.dev/api/v1/nodes?short=1

  MessagePack:
    https://map.meshcore.dev/api/v1/nodes?binary=1&short=1

Ziel:
  - Public Keys identifizieren, die nur in JSON bzw. nur in MessagePack vorkommen
  - Rollen, Alter des letzten Adverts und Positionsverfügbarkeit zusammenfassen
  - Beispiele der Abweichungen ausgeben
  - optional CSV-Dateien schreiben

Das Skript schreibt NICHT nach QuestDB oder SQLite.

Voraussetzung:
    pip install msgpack

Beispiele:
    python compare_meshcore_map_json_msgpack.py
    python compare_meshcore_map_json_msgpack.py --examples 50
    python compare_meshcore_map_json_msgpack.py --csv-prefix meshcore_map_diff
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_API_URL = "https://map.meshcore.dev/api/v1/nodes"
USER_AGENT = "MeshCore-PacketTap-MapDiff/0.1"

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


@dataclass
class Node:
    public_key: str
    name: str | None
    role: str | None
    lat: float | None
    lon: float | None
    last_advert: str | None
    inserted_date: str | None
    updated_date: str | None
    source: str | None


def norm_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()

    return "".join(
        ch
        for ch in str(value or "").strip().lower()
        if ch in "0123456789abcdef"
    )


def to_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        result = float(value)
        return result if math.isfinite(result) else None
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

    public_key = norm_hex(value)
    return public_key if len(public_key) == 64 else None


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
    return TYPE_NAMES.get(
        value,
        TYPE_NAMES.get(str(value), str(value)),
    )


def coords_of(node: dict[str, Any]) -> tuple[float | None, float | None]:
    lat = first_value(
        node,
        "adv_lat",
        "lat",
        "latitude",
    )
    lon = first_value(
        node,
        "adv_lon",
        "lon",
        "lng",
        "longitude",
    )

    if lat is not None or lon is not None:
        return to_float(lat), to_float(lon)

    coords = first_value(
        node,
        "coords",
        "coordinates",
        "c",
    )

    if isinstance(coords, dict):
        lat = first_value(coords, "lat", "latitude", "y")
        lon = first_value(coords, "lon", "lng", "longitude", "x")
        return to_float(lat), to_float(lon)

    if isinstance(coords, (list, tuple)) and len(coords) >= 2:
        a = to_float(coords[0])
        b = to_float(coords[1])

        if a is not None and b is not None:
            if abs(a) <= 90 and abs(b) <= 180:
                return a, b
            if abs(b) <= 90 and abs(a) <= 180:
                return b, a

    return None, None


def date_value(node: dict[str, Any], *keys: str) -> str | None:
    value = first_value(node, *keys)
    return str(value) if value not in (None, "") else None


def extract_nodes(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [
            item
            for item in payload
            if isinstance(item, dict)
        ]

    if not isinstance(payload, dict):
        return []

    for key in (
        "nodes",
        "items",
        "results",
        "data",
        "entries",
    ):
        value = payload.get(key)

        if isinstance(value, list):
            return [
                item
                for item in value
                if isinstance(item, dict)
            ]

        if isinstance(value, dict):
            for subkey in (
                "nodes",
                "items",
                "results",
                "data",
            ):
                sub = value.get(subkey)
                if isinstance(sub, list):
                    return [
                        item
                        for item in sub
                        if isinstance(item, dict)
                    ]

    return []


def normalize_node(raw: dict[str, Any]) -> Node | None:
    public_key = public_key_of(raw)
    if not public_key:
        return None

    lat, lon = coords_of(raw)

    return Node(
        public_key=public_key,
        name=name_of(raw),
        role=role_of(raw),
        lat=lat,
        lon=lon,
        last_advert=date_value(
            raw,
            "last_advert",
            "last_seen",
            "la",
        ),
        inserted_date=date_value(
            raw,
            "inserted_date",
            "inserted_at",
            "id",
        ),
        updated_date=date_value(
            raw,
            "updated_date",
            "updated_at",
            "ud",
        ),
        source=(
            str(first_value(raw, "source", "s"))
            if first_value(raw, "source", "s") not in (None, "")
            else None
        ),
    )


def request_bytes(
    url: str,
    timeout: float,
) -> tuple[bytes, str, float]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/json, application/msgpack, "
                "application/octet-stream;q=0.9, */*;q=0.1"
            ),
        },
    )

    start = time.perf_counter()
    with urllib.request.urlopen(
        request,
        timeout=timeout,
    ) as response:
        raw = response.read()
        content_type = response.headers.get(
            "Content-Type",
            "",
        )

    return (
        raw,
        content_type,
        time.perf_counter() - start,
    )


def load_json(
    api_url: str,
    timeout: float,
) -> tuple[dict[str, Node], int, int, float, float]:
    url = api_url + "?" + urllib.parse.urlencode(
        {"short": "1"}
    )

    raw, _, download_s = request_bytes(
        url,
        timeout,
    )

    start = time.perf_counter()
    payload = json.loads(raw.decode("utf-8"))
    decode_s = time.perf_counter() - start

    nodes_raw = extract_nodes(payload)
    nodes: dict[str, Node] = {}

    for item in nodes_raw:
        node = normalize_node(item)
        if node is not None:
            nodes[node.public_key] = node

    return (
        nodes,
        len(raw),
        len(nodes_raw),
        download_s,
        decode_s,
    )


def load_msgpack(
    api_url: str,
    timeout: float,
) -> tuple[dict[str, Node], int, int, float, float]:
    try:
        import msgpack  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Python-Paket 'msgpack' fehlt. "
            "Installieren mit: pip install msgpack"
        ) from exc

    url = api_url + "?" + urllib.parse.urlencode(
        {
            "binary": "1",
            "short": "1",
        }
    )

    raw, _, download_s = request_bytes(
        url,
        timeout,
    )

    start = time.perf_counter()
    payload = msgpack.unpackb(
        raw,
        raw=False,
        strict_map_key=False,
    )
    decode_s = time.perf_counter() - start

    nodes_raw = extract_nodes(payload)
    nodes: dict[str, Node] = {}

    for item in nodes_raw:
        node = normalize_node(item)
        if node is not None:
            nodes[node.public_key] = node

    return (
        nodes,
        len(raw),
        len(nodes_raw),
        download_s,
        decode_s,
    )


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None

    raw = value.strip()

    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"

        dt = datetime.fromisoformat(raw)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def age_bucket(
    value: str | None,
    now: datetime,
) -> str:
    dt = parse_timestamp(value)

    if dt is None:
        return "unknown"

    age_days = (now - dt).total_seconds() / 86400.0

    if age_days < 0:
        return "future"
    if age_days <= 1:
        return "<=1d"
    if age_days <= 7:
        return "<=7d"
    if age_days <= 30:
        return "<=30d"
    if age_days <= 180:
        return "<=180d"
    if age_days <= 365:
        return "<=1y"
    return ">1y"


def print_summary(
    label: str,
    nodes: list[Node],
) -> None:
    print()
    print(label)
    print("-" * 76)
    print(f"Nodes: {len(nodes):,}")

    roles = Counter(
        node.role or "unknown"
        for node in nodes
    )

    print("Rollen:")
    for role, count in sorted(
        roles.items(),
        key=lambda item: (-item[1], item[0]),
    ):
        print(
            f"  {role:<14} {count:>6}"
        )

    now = datetime.now(timezone.utc)

    freshness = Counter(
        age_bucket(node.last_advert, now)
        for node in nodes
    )

    order = [
        "<=1d",
        "<=7d",
        "<=30d",
        "<=180d",
        "<=1y",
        ">1y",
        "future",
        "unknown",
    ]

    print("Last-Advert-Alter:")
    for bucket in order:
        if freshness.get(bucket):
            print(
                f"  {bucket:<14} "
                f"{freshness[bucket]:>6}"
            )

    with_position = sum(
        1
        for node in nodes
        if node.lat is not None
        and node.lon is not None
    )

    print(
        f"Mit Position: {with_position:,} "
        f"({100.0 * with_position / len(nodes):.1f} %)"
        if nodes
        else "Mit Position: 0"
    )


def format_node(
    node: Node,
) -> str:
    position = "–"

    if (
        node.lat is not None
        and node.lon is not None
    ):
        position = (
            f"{node.lat:.6f}, "
            f"{node.lon:.6f}"
        )

    return (
        f"{node.public_key} | "
        f"{node.role or '–':<11} | "
        f"{node.name or '–'} | "
        f"last_advert={node.last_advert or '–'} | "
        f"position={position}"
    )


def write_csv(
    path: Path,
    nodes: list[Node],
) -> None:
    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        writer = csv.writer(
            handle,
            delimiter=";",
        )

        writer.writerow(
            [
                "public_key",
                "role",
                "name",
                "lat",
                "lon",
                "last_advert",
                "inserted_date",
                "updated_date",
                "source",
            ]
        )

        for node in nodes:
            writer.writerow(
                [
                    node.public_key,
                    node.role or "",
                    node.name or "",
                    (
                        ""
                        if node.lat is None
                        else node.lat
                    ),
                    (
                        ""
                        if node.lon is None
                        else node.lon
                    ),
                    node.last_advert or "",
                    node.inserted_date or "",
                    node.updated_date or "",
                    node.source or "",
                ]
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Vergleicht JSON- und MessagePack-Node-Mengen "
            "der offiziellen MeshCore Map API."
        )
    )

    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=(
            f"Basis-API "
            f"(Standard: {DEFAULT_API_URL})"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="HTTP-Timeout in Sekunden (Standard: 90)",
    )

    parser.add_argument(
        "--examples",
        type=int,
        default=30,
        help=(
            "Maximale Zahl Beispiel-Nodes je Richtung "
            "(Standard: 30)"
        ),
    )

    parser.add_argument(
        "--csv-prefix",
        default="",
        help=(
            "Optionaler Dateiprefix fuer CSV-Ausgabe, "
            "z.B. meshcore_map_diff"
        ),
    )

    args = parser.parse_args()

    print(
        "MeshCore Map JSON-vs-MessagePack Differenztest"
    )
    print("=" * 76)
    print(f"API: {args.api_url}")

    try:
        print()
        print("Lade JSON ...")
        (
            json_nodes,
            json_bytes,
            json_raw_count,
            json_download,
            json_decode,
        ) = load_json(
            args.api_url,
            args.timeout,
        )

        print("Lade MessagePack ...")
        (
            msg_nodes,
            msg_bytes,
            msg_raw_count,
            msg_download,
            msg_decode,
        ) = load_msgpack(
            args.api_url,
            args.timeout,
        )

    except Exception as exc:
        print(
            f"FEHLER: {exc}",
            file=sys.stderr,
        )
        return 1

    json_keys = set(json_nodes)
    msg_keys = set(msg_nodes)

    common_keys = json_keys & msg_keys
    only_json_keys = json_keys - msg_keys
    only_msg_keys = msg_keys - json_keys

    only_json = [
        json_nodes[key]
        for key in sorted(only_json_keys)
    ]

    only_msg = [
        msg_nodes[key]
        for key in sorted(only_msg_keys)
    ]

    print()
    print("Grunddaten")
    print("-" * 76)
    print(
        f"JSON        : "
        f"{json_raw_count:,} Roh-Nodes, "
        f"{len(json_nodes):,} Public Keys, "
        f"{json_bytes / (1024 * 1024):.2f} MiB"
    )
    print(
        f"              Download {json_download:.3f} s, "
        f"Decode {json_decode:.3f} s"
    )

    print(
        f"MessagePack : "
        f"{msg_raw_count:,} Roh-Nodes, "
        f"{len(msg_nodes):,} Public Keys, "
        f"{msg_bytes / (1024 * 1024):.2f} MiB"
    )
    print(
        f"              Download {msg_download:.3f} s, "
        f"Decode {msg_decode:.3f} s"
    )

    print()
    print("Mengenvergleich")
    print("-" * 76)
    print(
        f"In beiden vorhanden : "
        f"{len(common_keys):,}"
    )
    print(
        f"Nur JSON            : "
        f"{len(only_json):,}"
    )
    print(
        f"Nur MessagePack     : "
        f"{len(only_msg):,}"
    )

    print_summary(
        "Nur in JSON",
        only_json,
    )

    print_summary(
        "Nur in MessagePack",
        only_msg,
    )

    example_count = max(
        0,
        args.examples,
    )

    if only_json and example_count:
        print()
        print(
            f"Beispiele: nur JSON "
            f"(max. {example_count})"
        )
        print("-" * 76)

        # Prefer recent/repeater examples first.
        only_json_sorted = sorted(
            only_json,
            key=lambda node: (
                0
                if node.role == "repeater"
                else 1,
                -(
                    parse_timestamp(
                        node.last_advert
                    ).timestamp()
                    if parse_timestamp(
                        node.last_advert
                    )
                    else 0
                ),
                node.name or "",
                node.public_key,
            ),
        )

        for node in only_json_sorted[:example_count]:
            print(format_node(node))

    if only_msg and example_count:
        print()
        print(
            f"Beispiele: nur MessagePack "
            f"(max. {example_count})"
        )
        print("-" * 76)

        for node in only_msg[:example_count]:
            print(format_node(node))

    # Check whether common records differ in core fields.
    differing_common: list[
        tuple[Node, Node, list[str]]
    ] = []

    for key in common_keys:
        a = json_nodes[key]
        b = msg_nodes[key]

        differences: list[str] = []

        if (a.name or "") != (b.name or ""):
            differences.append("name")

        if (a.role or "") != (b.role or ""):
            differences.append("role")

        if a.lat != b.lat:
            differences.append("lat")

        if a.lon != b.lon:
            differences.append("lon")

        if (
            a.last_advert or ""
        ) != (
            b.last_advert or ""
        ):
            differences.append(
                "last_advert"
            )

        if differences:
            differing_common.append(
                (a, b, differences)
            )

    print()
    print("Gemeinsame Nodes mit abweichenden Kernfeldern")
    print("-" * 76)
    print(
        f"Anzahl: {len(differing_common):,}"
    )

    if differing_common and example_count:
        print()
        print(
            f"Beispiele abweichender gemeinsamer Nodes "
            f"(max. {example_count})"
        )
        print("-" * 76)

        for a, b, fields in differing_common[:example_count]:
            print(
                f"{a.public_key} | "
                f"Felder: {', '.join(fields)}"
            )
            print(
                f"  JSON       : "
                f"{format_node(a)}"
            )
            print(
                f"  MessagePack: "
                f"{format_node(b)}"
            )

    if args.csv_prefix:
        prefix = Path(args.csv_prefix)

        json_path = Path(
            str(prefix) + "_only_json.csv"
        )

        msg_path = Path(
            str(prefix) + "_only_msgpack.csv"
        )

        write_csv(
            json_path,
            only_json,
        )

        write_csv(
            msg_path,
            only_msg,
        )

        print()
        print("CSV-Ausgabe")
        print("-" * 76)
        print(f"Nur JSON       : {json_path}")
        print(f"Nur MessagePack: {msg_path}")

    print()
    print("Hinweis:")
    print(
        "Das Skript schreibt nichts nach QuestDB, SQLite "
        "oder node_directory.db."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
