#!/usr/bin/env python3
"""
MeshCore PacketTap - Repeater Report v0.9
=========================================

Direkt auf das dokumentierte QuestDB-Datenmodell von meshcore-packettap
zugeschnitten.

Verwendete Tabellen:
    mc_rx
    mc_contacts
    mc_contact_observations
    mc_advert

Wichtige Definitionen
---------------------
- Zeitbasis: ts
- Unscoped: ausschließlich payload_route_type = 1 (Flood)
- Scoped: wird in dieser Version als "nicht unscoped" NICHT automatisch
  interpretiert. Für die Kennzahl "Scoped" werden aktuell Transport-Routen
  payload_route_type IN (0, 3) verwendet.
- Direct (payload_route_type = 2) wird separat behandelt und gehört weder
  zu Unscoped noch zu Scoped.
- Direkt gehörte Repeater:
    mc_contact_observations
    node_role = 'repeater'
    hop_count = 0
- Repeater-Beteiligung:
    Public-Key-Präfix muss passend zu mc_rx.path_hash_size in mc_rx.nodes
    vorkommen.
- Repeater-Nachbarn:
    ausschließlich die Path-ID unmittelbar VOR dem untersuchten Repeater
    in mc_rx.nodes.
- Hop am Repeater:
    zero-based Position des Repeaters innerhalb von mc_rx.nodes. Dadurch wird
    die Hop-Zahl am Repeater von der späteren Gesamtpfadlänge am PacketTap
    getrennt.
- Kontaktmetadaten:
    pro public_key wird der neueste mc_contacts-Datensatz verwendet.

Abhängigkeiten:
    Nur Python-Standardbibliothek.

Beispiel PowerShell:
    python .\\repeater_report.py `
      --questdb-host 192.168.1.2 `
      --questdb-port 9000 `
      --repeater-name "Bruchsal Tower" `
      --from "2026-08-01T00:00:00Z" `
      --to "2026-08-14T23:59:59Z" `
      --receiver-name "Stutensee - Spoeck" `
      --output "reports\\Bruchsal-Tower.html"

Optional zusätzlich JSON:
    --json-output "reports\\Bruchsal-Tower.json"
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError


DEFAULT_QUESTDB_HOST = "localhost"
DEFAULT_QUESTDB_PORT = 9000

RT_TRANSPORT_FLOOD = 0
RT_FLOOD = 1
RT_DIRECT = 2
RT_TRANSPORT_DIRECT = 3

UNSCOPED_ROUTE_TYPES = {RT_FLOOD}
SCOPED_ROUTE_TYPES = {RT_TRANSPORT_FLOOD, RT_TRANSPORT_DIRECT}
DIRECT_ROUTE_TYPES = {RT_DIRECT}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Contact:
    ts: str
    public_key: str
    adv_name: str
    contact_type: str
    node_role: str
    source_type: str


@dataclass
class NeighborInfo:
    path_id: str
    public_key: str
    name: str
    packets: int = 0
    max_hops: int | None = None
    unscoped_gt3_packets: int = 0
    ambiguous: bool = False
    candidates: int = 0


@dataclass
class Metrics:
    observer_location: str
    receiver_id: str
    period_from: str
    period_to: str

    total_packets: int
    directly_heard_repeaters: int

    repeater_name: str
    repeater_public_key: str

    own_adverts_flood: int
    own_adverts_direct: int

    repeater_total_packets: int
    repeater_rank: int | None
    repeater_rank_total: int

    unscoped_packets: int
    unscoped_percent: float

    scoped_packets: int
    scoped_percent: float

    direct_packets: int
    direct_percent: float

    other_route_packets: int

    max_hops: int | None
    max_hops_unscoped: int | None
    max_hops_forwarded_adverts: int | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def norm(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def text_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def to_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def max_or_none(values: Iterable[int | None]) -> int | None:
    valid = [v for v in values if v is not None]
    return max(valid) if valid else None


def fmt_int(value: int | None) -> str:
    if value is None:
        return "–"
    return f"{value:,}".replace(",", ".")


def fmt_pct(value: float) -> str:
    return f"{value:.1f}".replace(".", ",") + " %"


def esc(value: Any) -> str:
    return html.escape(str(value))


def sql_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def validate_iso_time(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}"
        r"(?:[T ][0-2]\d:[0-5]\d"
        r"(?::[0-5]\d(?:\.\d+)?)?"
        r"(?:Z|[+-]\d{2}:\d{2})?)?",
        value,
    ):
        raise argparse.ArgumentTypeError(
            "Bitte ISO-Datum/-Zeit angeben, z.B. 2026-08-14T23:59:59Z"
        )
    return value


def parse_nodes(value: Any) -> list[str]:
    value = text_value(value)
    if not value:
        return []
    return [norm(x) for x in value.split(">") if norm(x)]


def is_full_public_key(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()))


def route_type(row: dict[str, Any]) -> int | None:
    return to_int(row.get("payload_route_type"))


def hop_at_repeater(
    row: dict[str, Any],
    public_key: str,
    resolver: "ContactResolver",
) -> int | None:
    """
    Hop count at the selected repeater, derived from its zero-based position
    in mc_rx.nodes.

    Example:
        A>B>C>11b1>D
              ^ index 3 => hop_at_repeater = 3

    This differs from mc_rx.hop_count, which describes the complete observed
    path at the PacketTap receiver.
    """
    positions = resolver.positions(row, public_key)
    if not positions:
        return None

    # A public-key prefix should normally occur only once in a path.
    # If it occurs repeatedly, use the furthest occurrence conservatively.
    return max(positions)


# ---------------------------------------------------------------------------
# QuestDB
# ---------------------------------------------------------------------------

class QuestDB:
    def __init__(self, host: str, port: int, timeout: int = 60):
        self.host = host
        self.port = port
        self.timeout = timeout

    def query(self, sql: str) -> tuple[list[str], list[list[Any]]]:
        params = urllib.parse.urlencode({"query": sql})
        url = f"http://{self.host}:{self.port}/exec?{params}"

        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            raise RuntimeError(
                f"QuestDB HTTP {exc.code}: {exc.reason}\n"
                f"Antwort: {body or '(kein Response-Body)'}\n"
                f"SQL:\n{sql}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"QuestDB-Abfrage fehlgeschlagen "
                f"({self.host}:{self.port}): {exc}\nSQL:\n{sql}"
            ) from exc

        if "error" in payload:
            raise RuntimeError(
                f"QuestDB: {payload['error']}\nSQL:\n{sql}"
            )

        cols_raw = payload.get("columns") or []
        columns: list[str] = []
        for item in cols_raw:
            if isinstance(item, dict):
                columns.append(str(item.get("name") or ""))
            elif isinstance(item, (list, tuple)) and item:
                columns.append(str(item[0]))
            else:
                columns.append(str(item))

        return columns, payload.get("dataset") or []

    def rows(self, sql: str) -> list[dict[str, Any]]:
        columns, dataset = self.query(sql)
        return [
            {
                columns[i]: row[i] if i < len(row) else None
                for i in range(len(columns))
            }
            for row in dataset
        ]

    def table_columns(self, table: str) -> set[str]:
        cols, _ = self.query(f"SELECT * FROM {table} LIMIT 0")
        return set(cols)


def time_filter(column: str, period_from: str, period_to: str) -> str:
    return (
        f"{column} >= CAST({sql_quote(period_from)} AS TIMESTAMP) "
        f"AND {column} <= CAST({sql_quote(period_to)} AS TIMESTAMP)"
    )


def receiver_filter(
    receiver_id: str | None,
    receiver_name: str | None,
    alias: str = "",
) -> str:
    prefix = f"{alias}." if alias else ""
    parts = []

    if receiver_id:
        parts.append(f"{prefix}receiver_id = {sql_quote(receiver_id)}")
    if receiver_name:
        parts.append(f"{prefix}receiver_name = {sql_quote(receiver_name)}")

    return " AND ".join(parts)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_rx(
    db: QuestDB,
    period_from: str,
    period_to: str,
    receiver_id: str | None,
    receiver_name: str | None,
) -> list[dict[str, Any]]:
    available = db.table_columns("mc_rx")

    required = {
        "ts",
        "repeater",
        "prev_hop",
        "sender_node",
        "payload_type",
        "payload_route_type",
        "hop_count",
        "path_hash_size",
        "nodes",
        "packet_payload_hex",
        "receiver_id",
        "receiver_name",
    }
    missing = required - available
    if missing:
        raise RuntimeError(
            "mc_rx fehlen Spalten: "
            + ", ".join(sorted(missing))
        )

    where = [time_filter("ts", period_from, period_to)]
    rf = receiver_filter(receiver_id, receiver_name)
    if rf:
        where.append(rf)

    sql = f"""
        SELECT
            ts,
            repeater,
            prev_hop,
            sender_node,
            payload_type,
            payload_route_type,
            hop_count,
            path_hash_size,
            nodes,
            packet_payload_hex,
            packet_payload_sha256,
            receiver_id,
            receiver_name,
            rssi_dbm,
            snr_db
        FROM mc_rx
        WHERE {' AND '.join(where)}
        ORDER BY ts
    """
    return db.rows(sql)


def load_contacts(db: QuestDB) -> list[Contact]:
    available = db.table_columns("mc_contacts")
    required = {"ts", "public_key", "adv_name", "node_role"}
    missing = required - available
    if missing:
        raise RuntimeError(
            "mc_contacts fehlen Spalten: "
            + ", ".join(sorted(missing))
        )

    optional = [
        c for c in ("contact_type", "source_type")
        if c in available
    ]

    sql = f"""
        SELECT
            ts,
            public_key,
            adv_name,
            node_role
            {',' if optional else ''}
            {', '.join(optional)}
        FROM mc_contacts
        WHERE public_key IS NOT NULL
        ORDER BY ts
    """

    rows = db.rows(sql)

    # Neuester Snapshot pro public_key.
    latest: dict[str, Contact] = {}
    for row in rows:
        key = norm(row.get("public_key"))
        if not is_full_public_key(key):
            continue

        latest[key] = Contact(
            ts=text_value(row.get("ts")),
            public_key=key,
            adv_name=text_value(row.get("adv_name")),
            contact_type=text_value(row.get("contact_type")),
            node_role=norm(row.get("node_role")),
            source_type=norm(row.get("source_type")),
        )

    return list(latest.values())


def load_contact_observations(
    db: QuestDB,
    period_from: str,
    period_to: str,
    receiver_id: str | None,
    receiver_name: str | None,
) -> list[dict[str, Any]]:
    available = db.table_columns("mc_contact_observations")

    required = {
        "ts",
        "public_key",
        "receiver_id",
        "receiver_name",
        "node_role",
        "hop_count",
        "rssi_dbm",
        "snr_db",
    }
    missing = required - available
    if missing:
        raise RuntimeError(
            "mc_contact_observations fehlen Spalten: "
            + ", ".join(sorted(missing))
        )

    where = [time_filter("ts", period_from, period_to)]
    rf = receiver_filter(receiver_id, receiver_name)
    if rf:
        where.append(rf)

    sql = f"""
        SELECT
            ts,
            public_key,
            receiver_id,
            receiver_name,
            node_role,
            hop_count,
            rssi_dbm,
            snr_db,
            region,
            packet_payload_sha256,
            public_key_bytes,
            discover_tag,
            discover_snr,
            source_type
        FROM mc_contact_observations
        WHERE {' AND '.join(where)}
        ORDER BY ts
    """
    return db.rows(sql)


def load_adverts(
    db: QuestDB,
    period_from: str,
    period_to: str,
) -> list[dict[str, Any]]:
    # mc_advert besitzt laut dokumentiertem Modell keine receiver_id-Spalte.
    available = db.table_columns("mc_advert")
    required = {
        "ts",
        "repeater",
        "sender_node",
        "prev_hop",
        "channel",
        "region",
        "packet_id",
        "advert_text",
    }
    missing = required - available
    if missing:
        raise RuntimeError(
            "mc_advert fehlen Spalten: "
            + ", ".join(sorted(missing))
        )

    sql = f"""
        SELECT
            ts,
            repeater,
            sender_node,
            prev_hop,
            channel,
            region,
            packet_id,
            advert_text
        FROM mc_advert
        WHERE {time_filter("ts", period_from, period_to)}
        ORDER BY ts
    """
    return db.rows(sql)


# ---------------------------------------------------------------------------
# Contact / path resolution
# ---------------------------------------------------------------------------

class ContactResolver:
    def __init__(self, contacts: list[Contact]):
        self.contacts = contacts
        self.repeaters = [
            c for c in contacts
            if c.node_role == "repeater"
        ]
        self.by_key = {
            c.public_key: c for c in contacts
        }

        # prefix length in hex chars -> prefix -> contacts
        self.prefix_index: dict[int, dict[str, list[Contact]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for c in self.repeaters:
            for byte_len in range(1, 9):
                hex_len = byte_len * 2
                self.prefix_index[hex_len][c.public_key[:hex_len]].append(c)

    def exact(self, public_key: str) -> Contact | None:
        return self.by_key.get(norm(public_key))

    def find_repeater_by_name(self, name: str) -> list[Contact]:
        wanted = norm(name)
        return [
            c for c in self.repeaters
            if norm(c.adv_name) == wanted
        ]

    @staticmethod
    def expected_prefix(public_key: str, path_hash_size: int | None) -> str:
        if not path_hash_size or path_hash_size <= 0:
            return ""
        return norm(public_key)[: path_hash_size * 2]

    def selected_prefix_is_unique(
        self,
        public_key: str,
        path_hash_size: int | None,
    ) -> bool:
        prefix = self.expected_prefix(public_key, path_hash_size)
        if not prefix:
            return False
        matches = self.resolve_path_id(prefix, path_hash_size)
        return (
            len(matches) == 1
            and matches[0].public_key == norm(public_key)
        )

    def packet_contains(
        self,
        row: dict[str, Any],
        public_key: str,
    ) -> bool:
        size = to_int(row.get("path_hash_size"))
        prefix = self.expected_prefix(public_key, size)
        if not prefix:
            return False

        # Never attribute a packet to the selected repeater when the path ID
        # is ambiguous among known repeaters.
        if not self.selected_prefix_is_unique(public_key, size):
            return False

        return prefix in parse_nodes(row.get("nodes"))

    def positions(
        self,
        row: dict[str, Any],
        public_key: str,
    ) -> list[int]:
        size = to_int(row.get("path_hash_size"))
        prefix = self.expected_prefix(public_key, size)
        if not prefix:
            return []

        if not self.selected_prefix_is_unique(public_key, size):
            return []

        nodes = parse_nodes(row.get("nodes"))
        return [i for i, node in enumerate(nodes) if node == prefix]

    def resolve_path_id(
        self,
        path_id: str,
        path_hash_size: int | None,
    ) -> list[Contact]:
        pid = norm(path_id)
        if not pid:
            return []

        if path_hash_size and len(pid) != path_hash_size * 2:
            # Trotzdem exakt über die vorhandene Länge versuchen.
            pass

        return self.prefix_index[len(pid)].get(pid, [])

    def unique_repeaters_in_packet(
        self,
        row: dict[str, Any],
    ) -> set[str]:
        size = to_int(row.get("path_hash_size"))
        result: set[str] = set()

        for node in parse_nodes(row.get("nodes")):
            matches = self.resolve_path_id(node, size)
            if len(matches) == 1:
                result.add(matches[0].public_key)

        return result


def resolve_selected_repeater(
    resolver: ContactResolver,
    repeater_public_key: str | None,
    repeater_name: str | None,
) -> Contact:
    if repeater_public_key:
        key = norm(repeater_public_key)
        if not is_full_public_key(key):
            raise RuntimeError(
                "--repeater-public-key muss 64 Hex-Zeichen lang sein."
            )
        found = resolver.exact(key)
        if found:
            return found

        return Contact(
            ts="",
            public_key=key,
            adv_name=repeater_name or "(nicht in mc_contacts)",
            contact_type="",
            node_role="repeater",
            source_type="manual",
        )

    assert repeater_name
    matches = resolver.find_repeater_by_name(repeater_name)

    if not matches:
        raise RuntimeError(
            f"Kein Repeater mit adv_name={repeater_name!r} gefunden."
        )

    if len(matches) > 1:
        lines = "\n".join(
            f"  {c.adv_name}: {c.public_key}"
            for c in matches
        )
        raise RuntimeError(
            f"Repeatername {repeater_name!r} ist nicht eindeutig:\n"
            f"{lines}\nBitte --repeater-public-key verwenden."
        )

    return matches[0]


# ---------------------------------------------------------------------------
# Report analysis
# ---------------------------------------------------------------------------

def determine_observer(
    observations: list[dict[str, Any]],
    rx: list[dict[str, Any]],
    requested_receiver_id: str | None,
    requested_receiver_name: str | None,
) -> tuple[str, str]:
    if requested_receiver_name:
        name = requested_receiver_name
    else:
        names = sorted({
            text_value(r.get("receiver_name"))
            for r in observations + rx
            if text_value(r.get("receiver_name"))
        })
        name = ", ".join(names) if names else "(unbekannt)"

    if requested_receiver_id:
        rid = requested_receiver_id
    else:
        ids = sorted({
            text_value(r.get("receiver_id"))
            for r in observations + rx
            if text_value(r.get("receiver_id"))
        })
        rid = ", ".join(ids) if ids else "(unbekannt)"

    return name, rid


def directly_heard_repeaters(
    observations: list[dict[str, Any]],
) -> set[str]:
    result = set()

    for row in observations:
        if norm(row.get("node_role")) != "repeater":
            continue
        if to_int(row.get("hop_count")) != 0:
            continue

        key = norm(row.get("public_key"))
        if is_full_public_key(key):
            result.add(key)

    return result


def advert_public_key_from_payload(row: dict[str, Any]) -> str | None:
    """
    ADVERT-Payload beginnt nach aktuellem PacketTap-Datenmodell mit dem
    vollständigen 32-Byte Public Key. Nur verwenden, wenn genug Hex-Daten
    vorhanden sind.
    """
    if norm(row.get("payload_type")) != "advert":
        return None

    payload = norm(row.get("packet_payload_hex"))
    if len(payload) < 64:
        return None
    candidate = payload[:64]

    if not is_full_public_key(candidate):
        return None
    return candidate


def build_ranking(
    rx: list[dict[str, Any]],
    resolver: ContactResolver,
) -> tuple[list[tuple[str, int]], dict[str, int]]:
    counts: Counter[str] = Counter()

    for row in rx:
        for key in resolver.unique_repeaters_in_packet(row):
            counts[key] += 1

    ordered = sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0]),
    )
    rank = {
        key: index + 1
        for index, (key, _) in enumerate(ordered)
    }
    return ordered, rank


def build_neighbors(
    repeater_rows: list[dict[str, Any]],
    selected_key: str,
    resolver: ContactResolver,
) -> list[NeighborInfo]:
    result: dict[str, NeighborInfo] = {}

    for row in repeater_rows:
        nodes = parse_nodes(row.get("nodes"))
        size = to_int(row.get("path_hash_size"))
        positions = resolver.positions(row, selected_key)
        repeater_hops = hop_at_repeater(row, selected_key, resolver)
        rt = route_type(row)

        previous_ids: set[str] = set()
        for pos in positions:
            # A neighbor for this report is strictly the repeater/node that
            # appears immediately BEFORE the selected repeater in the path.
            if pos > 0:
                previous_ids.add(nodes[pos - 1])

        for path_id in previous_ids:
            matches = resolver.resolve_path_id(path_id, size)

            if len(matches) == 1:
                contact = matches[0]
                identity = contact.public_key
                public_key = contact.public_key
                name = contact.adv_name or "–"
                ambiguous = False
                candidates = 1
            elif len(matches) > 1:
                identity = f"ambiguous:{path_id}"
                public_key = " / ".join(c.public_key for c in matches)
                names = [c.adv_name for c in matches if c.adv_name]
                name = " / ".join(names) if names else "(mehrdeutig)"
                ambiguous = True
                candidates = len(matches)
            else:
                identity = f"unknown:{path_id}"
                public_key = f"(unaufgelöst: {path_id})"
                name = "–"
                ambiguous = False
                candidates = 0

            info = result.get(identity)
            if info is None:
                info = NeighborInfo(
                    path_id=path_id,
                    public_key=public_key,
                    name=name,
                    ambiguous=ambiguous,
                    candidates=candidates,
                )
                result[identity] = info

            info.packets += 1

            if repeater_hops is not None:
                info.max_hops = (
                    repeater_hops
                    if info.max_hops is None
                    else max(info.max_hops, repeater_hops)
                )

            if (
                rt in UNSCOPED_ROUTE_TYPES
                and repeater_hops is not None
                and repeater_hops > 3
            ):
                info.unscoped_gt3_packets += 1

    return sorted(
        result.values(),
        key=lambda n: (-n.packets, n.name.lower(), n.public_key),
    )


def analyze(
    rx: list[dict[str, Any]],
    contacts: list[Contact],
    observations: list[dict[str, Any]],
    selected: Contact,
    period_from: str,
    period_to: str,
    receiver_id: str | None,
    receiver_name: str | None,
) -> tuple[Metrics, list[NeighborInfo], list[NeighborInfo], list[tuple[str, int]]]:

    resolver = ContactResolver(contacts)

    observer_name, observer_id = determine_observer(
        observations,
        rx,
        receiver_id,
        receiver_name,
    )

    repeater_rows = [
        row for row in rx
        if resolver.packet_contains(row, selected.public_key)
    ]

    unscoped = [
        row for row in repeater_rows
        if route_type(row) in UNSCOPED_ROUTE_TYPES
    ]
    scoped = [
        row for row in repeater_rows
        if route_type(row) in SCOPED_ROUTE_TYPES
    ]
    direct = [
        row for row in repeater_rows
        if route_type(row) in DIRECT_ROUTE_TYPES
    ]
    other = (
        len(repeater_rows)
        - len(unscoped)
        - len(scoped)
        - len(direct)
    )

    own_adverts = [
        row for row in rx
        if advert_public_key_from_payload(row) == selected.public_key
    ]

    own_adverts_flood = sum(
        1 for row in own_adverts
        if route_type(row) == RT_FLOOD
    )
    own_adverts_direct = sum(
        1 for row in own_adverts
        if route_type(row) == RT_DIRECT
    )

    ranking, rank_by_key = build_ranking(rx, resolver)

    neighbors = build_neighbors(
        repeater_rows,
        selected.public_key,
        resolver,
    )
    neighbors_gt3 = [
        n for n in neighbors
        if n.unscoped_gt3_packets > 0
    ]
    neighbors_gt3.sort(
        key=lambda n: (
            -n.unscoped_gt3_packets,
            -n.packets,
            n.name.lower(),
        )
    )

    total = len(repeater_rows)
    denom = total or 1

    metrics = Metrics(
        observer_location=observer_name,
        receiver_id=observer_id,
        period_from=period_from,
        period_to=period_to,
        total_packets=len(rx),
        directly_heard_repeaters=len(
            directly_heard_repeaters(observations)
        ),
        repeater_name=selected.adv_name or "(ohne Namen)",
        repeater_public_key=selected.public_key,
        own_adverts_flood=own_adverts_flood,
        own_adverts_direct=own_adverts_direct,
        repeater_total_packets=total,
        repeater_rank=rank_by_key.get(selected.public_key),
        repeater_rank_total=len(ranking),
        unscoped_packets=len(unscoped),
        unscoped_percent=(100 * len(unscoped) / denom) if total else 0.0,
        scoped_packets=len(scoped),
        scoped_percent=(100 * len(scoped) / denom) if total else 0.0,
        direct_packets=len(direct),
        direct_percent=(100 * len(direct) / denom) if total else 0.0,
        other_route_packets=other,
        max_hops=max_or_none(
            hop_at_repeater(r, selected.public_key, resolver)
            for r in repeater_rows
        ),
        max_hops_unscoped=max_or_none(
            hop_at_repeater(r, selected.public_key, resolver)
            for r in unscoped
        ),
        max_hops_forwarded_adverts=max_or_none(
            hop_at_repeater(r, selected.public_key, resolver)
            for r in repeater_rows
            if norm(r.get("payload_type")) == "advert"
        ),
    )

    return metrics, neighbors, neighbors_gt3, ranking


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def metric_row(label: str, value: str) -> str:
    return (
        "<tr>"
        f"<td>{esc(label)}</td>"
        f"<td class='num'>{esc(value)}</td>"
        "</tr>"
    )


def neighbor_table(
    rows: list[NeighborInfo],
    only_gt3: bool = False,
) -> str:
    if not rows:
        return "<p class='muted'>Keine Einträge ermittelt.</p>"

    count_header = (
        "Unscoped-Pakete &gt; 3 Hops"
        if only_gt3
        else "Beobachtete Pakete"
    )

    body = []
    for n in rows:
        count = (
            n.unscoped_gt3_packets
            if only_gt3
            else n.packets
        )

        note = ""
        if n.ambiguous:
            note = (
                f"<div class='warn'>Path-ID {esc(n.path_id)} ist "
                f"{n.candidates}-fach mehrdeutig.</div>"
            )
        elif n.candidates == 0:
            note = (
                f"<div class='muted small'>Path-ID {esc(n.path_id)} "
                "konnte keinem bekannten Repeater eindeutig "
                "zugeordnet werden.</div>"
            )

        body.append(
            "<tr>"
            f"<td class='mono'>{esc(n.public_key)}{note}</td>"
            f"<td>{esc(n.name)}</td>"
            f"<td class='num'>{fmt_int(count)}</td>"
            f""
            "</tr>"
        )

    return f"""
    <table>
      <thead>
        <tr>
          <th>Public Key</th>
          <th>Name</th>
          <th class="num">{count_header}</th>
          
        </tr>
      </thead>
      <tbody>{''.join(body)}</tbody>
    </table>
    """


def ranking_table(
    ranking: list[tuple[str, int]],
    contacts: list[Contact],
    selected_key: str,
    limit: int = 20,
) -> str:
    cmap = {c.public_key: c for c in contacts}
    rows = []

    for idx, (key, count) in enumerate(ranking[:limit], start=1):
        c = cmap.get(key)
        selected_cls = " class='selected'" if key == selected_key else ""
        rows.append(
            f"<tr{selected_cls}>"
            f"<td class='num'>{idx}</td>"
            f"<td>{esc(c.adv_name if c and c.adv_name else '–')}</td>"
            f"<td class='mono'>{esc(key)}</td>"
            f"<td class='num'>{fmt_int(count)}</td>"
            "</tr>"
        )

    return f"""
    <table>
      <thead>
        <tr>
          <th>Rang</th>
          <th>Name</th>
          <th>Public Key</th>
          <th class="num">Pakete</th>
        </tr>
      </thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def short_key(key: str, left: int = 6, right: int = 6) -> str:
    key = str(key)
    if len(key) <= left + right + 1:
        return key
    return f"{key[:left]}…{key[-right:]}"


def format_period_de(value: str) -> str:
    try:
        from datetime import datetime
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%d.%m.%Y")
    except Exception:
        return value


def short_key(key: str, left: int = 6, right: int = 6) -> str:
    key = str(key)
    if len(key) <= left + right + 1:
        return key
    return f"{key[:left]}…{key[-right:]}"


def format_period_de(value: str) -> str:
    try:
        from datetime import datetime
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%d.%m.%Y")
    except Exception:
        return value


def render_html(
    metrics: Metrics,
    neighbors: list[NeighborInfo],
    neighbors_gt3: list[NeighborInfo],
    ranking: list[tuple[str, int]],
    contacts: list[Contact],
) -> str:

    rank_text = (
        "–"
        if metrics.repeater_rank is None
        else f"{metrics.repeater_rank} / {metrics.repeater_rank_total}"
    )

    period_text = (
        f"{format_period_de(metrics.period_from)} – "
        f"{format_period_de(metrics.period_to)}"
    )

    receiver_cards = [
        ("Beobachtungsstandort", metrics.observer_location),
        ("Beobachtungszeitraum", period_text),
        ("Receiver Public Key", metrics.receiver_id),
        ("Gesamtpakete", fmt_int(metrics.total_packets)),
        ("Direkt gehörte Repeater", fmt_int(metrics.directly_heard_repeaters)),
    ]

    receiver_html = "".join(
        f"""
        <div class="info-card">
          <div class="info-label">{esc(label)}</div>
          <div class="info-value{' mono' if 'Public Key' in label else ''}">
            {esc(value)}
          </div>
        </div>
        """
        for label, value in receiver_cards
    )

    repeater_kpis = [
        ("Pakete über diesen Repeater", fmt_int(metrics.repeater_total_packets)),
        ("Rang", rank_text),
        (
            "Unscoped",
            f"{fmt_pct(metrics.unscoped_percent)} · {fmt_int(metrics.unscoped_packets)} Pakete",
        ),
        (
            "Scoped",
            f"{fmt_pct(metrics.scoped_percent)} · {fmt_int(metrics.scoped_packets)} Pakete",
        ),
        (
            "Direct",
            f"{fmt_pct(metrics.direct_percent)} · {fmt_int(metrics.direct_packets)} Pakete",
        ),
        ("Max. Hops am Repeater", fmt_int(metrics.max_hops)),
        (
            "Max. Unscoped-Hops",
            fmt_int(metrics.max_hops_unscoped),
        ),
        (
            "Max. Hops weitergeleiteter Adverts",
            fmt_int(metrics.max_hops_forwarded_adverts),
        ),
    ]

    repeater_kpi_html = "".join(
        f"""
        <div class="kpi">
          <div class="kpi-value">{esc(value)}</div>
          <div class="kpi-label">{esc(label)}</div>
        </div>
        """
        for label, value in repeater_kpis
    )

    advert_rows = "".join([
        metric_row("Eigene Flood-Adverts (RT 1)", fmt_int(metrics.own_adverts_flood)),
        metric_row("Eigene direkte Adverts (RT 2)", fmt_int(metrics.own_adverts_direct)),
        metric_row(
            "Max. Hops weitergeleiteter Adverts",
            fmt_int(metrics.max_hops_forwarded_adverts),
        ),
    ])

    routing_rows = "".join([
        metric_row(
            "Unscoped Pakete (RT 1)",
            f"{fmt_int(metrics.unscoped_packets)} · {fmt_pct(metrics.unscoped_percent)}",
        ),
        metric_row(
            "Scoped Pakete (RT 0/3)",
            f"{fmt_int(metrics.scoped_packets)} · {fmt_pct(metrics.scoped_percent)}",
        ),
        metric_row(
            "Direct Pakete (RT 2)",
            f"{fmt_int(metrics.direct_packets)} · {fmt_pct(metrics.direct_percent)}",
        ),
        metric_row(
            "Sonstige/unklare Routingtypen",
            fmt_int(metrics.other_route_packets),
        ),
    ])

    if neighbors:
        neighbor_rows = []
        for n in neighbors:
            note = ""
            if n.ambiguous:
                note = (
                    f"<div class='warn'>Path-ID {esc(n.path_id)} ist "
                    f"{n.candidates}-fach mehrdeutig.</div>"
                )
            elif n.candidates == 0:
                note = (
                    f"<div class='muted small'>Path-ID {esc(n.path_id)} "
                    "konnte keinem bekannten Repeater eindeutig zugeordnet "
                    "werden.</div>"
                )

            neighbor_rows.append(
                "<tr>"
                f"<td><strong>{esc(n.name)}</strong>{note}</td>"
                f"<td class='num'>{fmt_int(n.packets)}</td>"
                f"<td class='mono key'>{esc(short_key(n.public_key))}</td>"
                "</tr>"
            )

        neighbors_html = f"""
        <table class="neighbors-table">
          <thead>
            <tr>
              <th>Repeater</th>
              <th class="num">Pakete</th>
              <th>Public Key</th>
            </tr>
          </thead>
          <tbody>{''.join(neighbor_rows)}</tbody>
        </table>
        """
    else:
        neighbors_html = (
            "<p class='status muted'>Keine Repeater-Nachbarn ermittelt.</p>"
        )

    if neighbors_gt3:
        gt3_rows = []
        for n in neighbors_gt3:
            gt3_rows.append(
                "<tr>"
                f"<td><strong>{esc(n.name)}</strong></td>"
                f"<td class='num'>{fmt_int(n.unscoped_gt3_packets)}</td>"
                f"<td class='mono key'>{esc(short_key(n.public_key))}</td>"
                "</tr>"
            )
        gt3_html = f"""
        <p class="section-intro">
          Diese Nachbarn wurden bei unscoped Flood-Paketen (RT 1) mit mehr
          als drei Hops am untersuchten Repeater beobachtet.
        </p>
        <table>
          <thead>
            <tr>
              <th>Repeater</th>
              <th class="num">Pakete</th>
              <th>Public Key</th>
            </tr>
          </thead>
          <tbody>{''.join(gt3_rows)}</tbody>
        </table>
        """
    else:
        gt3_html = """
        <div class="status-ok">
          Keine Repeater-Nachbarn bei Unscoped-Paketen mit mehr als 3 Hops
          beobachtet.
        </div>
        """

    return f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Repeater Report – {esc(metrics.repeater_name)}</title>
<style>
:root {{
  --fg:#171717;
  --muted:#666;
  --line:#d9d9d9;
  --soft:#f5f5f5;
  --soft2:#fafafa;
  --warn:#8a5a00;
}}
* {{ box-sizing:border-box; }}
body {{
  font-family:Arial,Helvetica,sans-serif;
  color:var(--fg);
  max-width:1100px;
  margin:30px auto;
  padding:0 28px 56px;
  line-height:1.45;
  background:#fff;
}}
.report-header {{
  padding-bottom:18px;
}}
.eyebrow {{
  color:var(--muted);
  font-size:.78rem;
  text-transform:uppercase;
  letter-spacing:.09em;
  font-weight:700;
}}
h1 {{
  margin:5px 0 8px;
  font-size:2.05rem;
  line-height:1.15;
}}
.repeater-key {{
  font-size:.88rem;
  color:var(--muted);
}}
.main-separator {{
  border:0;
  border-top:2px solid var(--fg);
  margin:0 0 22px;
}}
h2 {{
  margin-top:34px;
  margin-bottom:10px;
  padding-bottom:7px;
  border-bottom:1px solid var(--line);
  font-size:1.35rem;
}}
.section-intro {{
  color:var(--muted);
  max-width:850px;
  margin-top:0;
}}
.receiver-grid {{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:12px;
}}
.info-card {{
  border:1px solid var(--line);
  border-radius:8px;
  padding:13px 15px;
  background:var(--soft2);
}}
.info-label {{
  color:var(--muted);
  font-size:.84rem;
  margin-bottom:5px;
}}
.info-value {{
  font-size:1.05rem;
  font-weight:650;
}}
.mono {{
  font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
  word-break:break-all;
}}
.repeater-section {{
  margin-top:34px;
}}
.repeater-section-title {{
  margin-bottom:4px;
}}
.repeater-section-subtitle {{
  color:var(--muted);
  margin-top:0;
  margin-bottom:16px;
}}
.kpi-grid {{
  display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:12px;
}}
.kpi {{
  border:1px solid var(--line);
  border-radius:9px;
  padding:16px;
  background:var(--soft2);
  min-height:104px;
}}
.kpi-value {{
  font-size:1.55rem;
  font-weight:700;
  line-height:1.15;
  margin-bottom:8px;
}}
.kpi-label {{
  color:var(--muted);
  font-size:.88rem;
}}
.two-col {{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:22px;
}}
table {{
  width:100%;
  border-collapse:collapse;
  margin:10px 0 18px;
}}
th,td {{
  border-bottom:1px solid var(--line);
  padding:9px 8px;
  vertical-align:top;
  text-align:left;
}}
th {{
  background:var(--soft);
  font-size:.9rem;
}}
.num {{
  text-align:right;
  white-space:nowrap;
}}
.key {{
  color:var(--muted);
  font-size:.86rem;
  white-space:nowrap;
}}
.muted {{ color:var(--muted); }}
.small {{ font-size:.84rem; }}
.warn {{
  color:var(--warn);
  font-size:.82rem;
  margin-top:3px;
}}
.status-ok {{
  border:1px solid var(--line);
  background:var(--soft2);
  border-radius:8px;
  padding:13px 15px;
  font-weight:600;
}}
details {{
  margin-top:34px;
  border:1px solid var(--line);
  border-radius:8px;
}}
summary {{
  cursor:pointer;
  padding:13px 15px;
  font-weight:700;
  background:var(--soft);
}}
.details-inner {{
  padding:4px 15px 16px;
}}
.footer {{
  margin-top:36px;
  padding-top:12px;
  border-top:1px solid var(--line);
  color:var(--muted);
  font-size:.8rem;
}}
.selected {{ font-weight:700; }}
@media (max-width:850px) {{
  .receiver-grid {{ grid-template-columns:1fr 1fr; }}
  .kpi-grid {{ grid-template-columns:1fr 1fr; }}
  .two-col {{ grid-template-columns:1fr; }}
}}
@media (max-width:520px) {{
  body {{ padding:0 16px 40px; }}
  .receiver-grid {{ grid-template-columns:1fr; }}
  .kpi-grid {{ grid-template-columns:1fr; }}
  h1 {{ font-size:1.65rem; }}
}}
@media print {{
  body {{ margin:0;max-width:none;padding:0; }}
  details {{ display:none; }}
  .kpi,.info-card,tr {{ break-inside:avoid; }}
}}
</style>
</head>
<body>

<header class="report-header">
  <div class="eyebrow">MeshCore Repeater Report</div>
  <h1>{esc(metrics.repeater_name)}</h1>
  <div class="repeater-key">
    Public Key:
    <span class="mono">{esc(metrics.repeater_public_key)}</span>
  </div>
</header>

<hr class="main-separator">

<section>
  <h2>Beobachtung</h2>
  <p class="section-intro">
    Diese Angaben beschreiben den PacketTap-Receiver und den betrachteten
    Beobachtungszeitraum.
  </p>
  <div class="receiver-grid">
    {receiver_html}
  </div>
</section>

<section class="repeater-section">
  <h2 class="repeater-section-title">Kennzahlen des untersuchten Repeaters</h2>
  <p class="repeater-section-subtitle">
    Die folgenden Werte beziehen sich ausschließlich auf
    <strong>{esc(metrics.repeater_name)}</strong>.
  </p>
  <div class="kpi-grid">
    {repeater_kpi_html}
  </div>
</section>

<section class="two-col">
  <div>
    <h2>Adverts</h2>
    <table>
      <tbody>{advert_rows}</tbody>
    </table>
  </div>
  <div>
    <h2>Routing-Verteilung</h2>
    <table>
      <tbody>{routing_rows}</tbody>
    </table>
  </div>
</section>

<section>
  <h2>Repeater-Nachbarn</h2>
  <p class="section-intro">
    Als Repeater-Nachbarn werden Repeater bezeichnet, die in den beobachteten
    Paketpfaden unmittelbar vor dem untersuchten Repeater auftreten.
    Die Anzahl der Pakete zeigt, wie häufig dieser Nachbar als vorheriger Hop
    beobachtet wurde.
  </p>
  <p><strong>Anzahl erkannter Nachbarn:</strong> {fmt_int(len(neighbors))}</p>
  {neighbors_html}
</section>

<section>
  <h2>Unscoped-Nachbarn &gt; 3 Hops</h2>
  {gt3_html}
</section>

<details>
  <summary>Methodik und technische Kontrolle</summary>
  <div class="details-inner">
    <h2>Methodik</h2>
    <p class="small muted">
      Unscoped = ausschließlich RT 1 (Flood). Scoped = RT 0 und RT 3.
      RT 2 (Direct) wird separat ausgewiesen.
      „Max. Hops am Repeater“ wird aus der Position des untersuchten Repeaters
      in <span class="mono">mc_rx.nodes</span> berechnet.
      „Max. Hops weitergeleiteter Adverts“ betrachtet alle ADVERT-Pakete, in
      deren Pfad der untersuchte Repeater eindeutig vorkommt, und verwendet
      ebenfalls dessen Position im Pfad.
      Mehrdeutige Path-Präfixe werden dem ausgewählten Repeater nicht
      zugerechnet.
    </p>

    <h2>Rangliste – Kontrolle</h2>
    <p class="small muted">
      Top 20 der eindeutig über Path-ID-Präfixe aufgelösten Repeater.
      Ein Repeater wird pro Paket maximal einmal gezählt.
    </p>
    {ranking_table(ranking, contacts, metrics.repeater_public_key)}
  </div>
</details>

<footer class="footer">
  PacketTap / QuestDB · Report v0.9
</footer>

</body>
</html>
"""



# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MeshCore PacketTap Repeater Report v0.9"
    )

    p.add_argument(
        "--questdb-host",
        default=DEFAULT_QUESTDB_HOST,
        help=f"QuestDB Host (default: {DEFAULT_QUESTDB_HOST})",
    )
    p.add_argument(
        "--questdb-port",
        type=int,
        default=DEFAULT_QUESTDB_PORT,
        help=f"QuestDB HTTP Port (default: {DEFAULT_QUESTDB_PORT})",
    )

    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--repeater-name",
        help="Exakter adv_name aus mc_contacts",
    )
    group.add_argument(
        "--repeater-public-key",
        help="Vollständiger 32-Byte Public Key",
    )

    p.add_argument(
        "--from",
        dest="period_from",
        type=validate_iso_time,
        required=True,
    )
    p.add_argument(
        "--to",
        dest="period_to",
        type=validate_iso_time,
        required=True,
    )

    p.add_argument(
        "--receiver-id",
        help="Optional: nur diesen PacketTap-Receiver auswerten",
    )
    p.add_argument(
        "--receiver-name",
        help="Optional: nur diesen receiver_name auswerten",
    )

    p.add_argument(
        "--output",
        default="repeater_report.html",
        help="HTML-Ausgabedatei",
    )
    p.add_argument(
        "--json-output",
        help="Optional zusätzlich JSON schreiben",
    )

    return p.parse_args()


def main() -> int:
    args = parse_args()
    db = QuestDB(args.questdb_host, args.questdb_port)

    try:
        print(
            f"[REPORT] Lade mc_rx {args.period_from} bis {args.period_to} "
            f"von {args.questdb_host}:{args.questdb_port} ..."
        )
        rx = load_rx(
            db,
            args.period_from,
            args.period_to,
            args.receiver_id,
            args.receiver_name,
        )
        print(f"[REPORT] {len(rx)} mc_rx-Pakete geladen.")

        print("[REPORT] Lade mc_contacts ...")
        contacts = load_contacts(db)
        resolver = ContactResolver(contacts)
        print(
            f"[REPORT] {len(contacts)} eindeutige Kontakte, "
            f"{len(resolver.repeaters)} Repeater."
        )

        selected = resolve_selected_repeater(
            resolver,
            args.repeater_public_key,
            args.repeater_name,
        )
        print(
            f"[REPORT] Repeater: {selected.adv_name or '(ohne Namen)'} "
            f"{selected.public_key}"
        )

        print("[REPORT] Lade mc_contact_observations ...")
        observations = load_contact_observations(
            db,
            args.period_from,
            args.period_to,
            args.receiver_id,
            args.receiver_name,
        )
        print(
            f"[REPORT] {len(observations)} Contact-Observations geladen."
        )

        # Load to validate table and keep v0.4 aligned with documented model.
        # The current report metrics derive own adverts from mc_rx because that
        # contains routing type + full packet payload.
        print("[REPORT] Prüfe mc_advert ...")
        adverts = load_adverts(
            db,
            args.period_from,
            args.period_to,
        )
        print(f"[REPORT] {len(adverts)} mc_advert-Zeilen im Zeitraum.")

        metrics, neighbors, neighbors_gt3, ranking = analyze(
            rx,
            contacts,
            observations,
            selected,
            args.period_from,
            args.period_to,
            args.receiver_id,
            args.receiver_name,
        )

        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            render_html(
                metrics,
                neighbors,
                neighbors_gt3,
                ranking,
                contacts,
            ),
            encoding="utf-8",
        )
        print(f"[REPORT] HTML geschrieben: {output.resolve()}")

        if args.json_output:
            jout = Path(args.json_output)
            jout.parent.mkdir(parents=True, exist_ok=True)
            jout.write_text(
                json.dumps(
                    {
                        "metrics": asdict(metrics),
                        "neighbors": [
                            asdict(n) for n in neighbors
                        ],
                        "neighbors_unscoped_gt3": [
                            asdict(n) for n in neighbors_gt3
                        ],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            print(f"[REPORT] JSON geschrieben: {jout.resolve()}")

        return 0

    except KeyboardInterrupt:
        print("\nAbgebrochen.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[FEHLER] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
