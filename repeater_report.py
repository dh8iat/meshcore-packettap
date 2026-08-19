#!/usr/bin/env python3
"""
MeshCore PacketTap - Repeater Report v0.50
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
- Direct: payload_route_type = 2.
- Für die Routing-Verteilung werden Scoped, Unscoped und Direct gemeinsam
  auf 100 % normiert. Sonstige/unklare Routing-Typen werden nicht in diese
  Prozentverteilung einbezogen.
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
- Eigene Adverts:
    Zuordnung über public_key + packet_payload_sha256 aus den dekodierten
    Contact-Observations und den zugehörigen ADVERT-Paketen.
    Direct = RT 2 bei Hop 0; Flood = RT 0, pro Payload-Hash einmal.
    Der typische Abstand ist der Median zwischen eindeutigen Advert-Ereignissen.
- Bewertungshinweise:
    Richtwerte: flood.max <= 16; flood.max.unscoped = 3
    (bei exponierten Standorten kann 0 sinnvoll sein); flood.max.advert = 3;
    advert.interval > 210 min gilt als günstig, 239 min empfohlen,
    maximal einstellbar 240 min; flood.advert.interval ist von 3-168 h
    einstellbar und >= 70 h empfohlen. Vielfache von 24 h sollten zur
    Kollisionsvermeidung vermieden werden.
    Für die Bewertung der Path-Hash-Größe werden ausschließlich eigene
    Flood-Adverts (RT 0) verwendet; Direct-Adverts (RT 2) bleiben außen vor.
    Für eigene Flood-Adverts werden 2- oder 3-Byte-Path-Hashes empfohlen;
    path.hash.mode 0 entspricht 1 Byte, Wert 1 entspricht 2 Byte.
    Die Hinweise bewerten beobachtetes Verhalten, nicht ausgelesene Konfiguration.

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
    own_adverts_flood_interval_minutes: float | None
    own_adverts_direct: int
    own_adverts_direct_interval_minutes: float | None

    repeater_total_packets: int
    repeater_rank: int | None
    repeater_rank_total: int

    unscoped_packets: int
    unscoped_percent: float

    scoped_packets: int
    scoped_percent: float

    direct_packets: int
    direct_percent: float

    own_advert_path_hash_sizes: tuple[int, ...]

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

    # Je nach Entstehungsweg der QuestDB-Tabelle heißt die designierte
    # Zeitspalte entweder "ts" (ältere/manuell angelegte Tabellen) oder
    # "timestamp" (per ILP automatisch angelegte Tabellen).
    if "ts" in available:
        time_column = "ts"
    elif "timestamp" in available:
        time_column = "timestamp"
    else:
        raise RuntimeError(
            "mc_contact_observations fehlt Zeitspalte: ts oder timestamp"
        )

    required = {
        "public_key",
        "receiver_id",
        "receiver_name",
        "node_role",
        "hop_count",
    }
    missing = required - available
    if missing:
        raise RuntimeError(
            "mc_contact_observations fehlen Spalten: "
            + ", ".join(sorted(missing))
        )

    # Einige Observation-Spalten entstehen in QuestDB bei ILP erst, sobald
    # erstmals ein nicht-NULL-Wert geschrieben wurde. Der Report behandelt
    # diese Felder deshalb als optional.
    optional_columns = (
        "rssi_dbm",
        "snr_db",
        "region",
        "packet_payload_sha256",
        "public_key_bytes",
        "discover_tag",
        "discover_snr",
        "source_type",
    )

    select_optional = [
        column if column in available else f"NULL AS {column}"
        for column in optional_columns
    ]

    where = [time_filter(time_column, period_from, period_to)]
    rf = receiver_filter(receiver_id, receiver_name)
    if rf:
        where.append(rf)

    sql = f"""
        SELECT
            {time_column} AS ts,
            public_key,
            receiver_id,
            receiver_name,
            node_role,
            hop_count,
            {', '.join(select_optional)}
        FROM mc_contact_observations
        WHERE {' AND '.join(where)}
        ORDER BY {time_column}
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


def parse_timestamp(value: Any):
    """Parse QuestDB ISO timestamps for interval calculations."""
    from datetime import datetime
    raw = text_value(value)
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def median_interval_minutes(timestamps: list[str]) -> float | None:
    """Median of positive intervals between chronologically distinct events."""
    parsed = sorted(
        dt for dt in (parse_timestamp(value) for value in timestamps)
        if dt is not None
    )
    if len(parsed) < 2:
        return None

    intervals = [
        (b - a).total_seconds() / 60.0
        for a, b in zip(parsed, parsed[1:])
        if b > a
    ]
    if not intervals:
        return None

    intervals.sort()
    middle = len(intervals) // 2
    if len(intervals) % 2:
        return intervals[middle]
    return (intervals[middle - 1] + intervals[middle]) / 2.0


def own_advert_events(
    rx: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    selected_key: str,
) -> tuple[list[str], list[str]]:
    """
    Identify unique own advert events by linking decoded advert observations
    to ADVERT packets through packet_payload_sha256.

    Direct advert: RT 2, packet hop 0.
    Flood advert:  RT 0. Receptions of the same payload hash are one event;
                   the earliest packet timestamp is used.
    """
    selected_key = norm(selected_key)

    hashes = {
        norm(row.get("packet_payload_sha256"))
        for row in observations
        if norm(row.get("public_key")) == selected_key
        and norm(row.get("source_type")) == "advert"
        and norm(row.get("packet_payload_sha256"))
    }

    by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rx:
        payload_hash = norm(row.get("packet_payload_sha256"))
        if (
            payload_hash in hashes
            and norm(row.get("payload_type")) == "advert"
        ):
            by_hash[payload_hash].append(row)

    direct_times: list[str] = []
    flood_times: list[str] = []

    for rows in by_hash.values():
        direct_rows = [
            row for row in rows
            if route_type(row) == RT_DIRECT
            and to_int(row.get("hop_count")) == 0
        ]
        flood_rows = [
            row for row in rows
            if route_type(row) == RT_TRANSPORT_FLOOD
        ]

        if direct_rows:
            direct_times.append(
                min(text_value(row.get("ts")) for row in direct_rows)
            )
        if flood_rows:
            flood_times.append(
                min(text_value(row.get("ts")) for row in flood_rows)
            )

    return sorted(direct_times), sorted(flood_times)



def own_advert_path_hash_sizes(
    rx: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    selected_key: str,
) -> tuple[int, ...]:
    """Observed path_hash_size values of own flood adverts (RT 0).

    Direct adverts (RT 2) are deliberately excluded: their observed
    path_hash_size is not used to assess path.hash.mode. Advert ownership is
    linked through public_key + packet_payload_sha256; only matching ADVERT
    packets with payload_route_type 0 contribute to this metric.
    """
    selected_key = norm(selected_key)
    hashes = {
        norm(row.get("packet_payload_sha256"))
        for row in observations
        if norm(row.get("public_key")) == selected_key
        and norm(row.get("source_type")) == "advert"
        and norm(row.get("packet_payload_sha256"))
    }

    sizes = {
        size
        for row in rx
        if norm(row.get("payload_type")) == "advert"
        and to_int(row.get("payload_route_type")) == 0
        and norm(row.get("packet_payload_sha256")) in hashes
        for size in [to_int(row.get("path_hash_size"))]
        if size in (1, 2, 3)
    }
    return tuple(sorted(sizes))


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
                public_key = path_id
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

    own_direct_advert_times, own_flood_advert_times = own_advert_events(
        rx,
        observations,
        selected.public_key,
    )
    own_adverts_direct = len(own_direct_advert_times)
    own_adverts_flood = len(own_flood_advert_times)
    own_adverts_direct_interval = median_interval_minutes(
        own_direct_advert_times
    )
    own_adverts_flood_interval = median_interval_minutes(
        own_flood_advert_times
    )
    advert_hash_sizes = own_advert_path_hash_sizes(
        rx,
        observations,
        selected.public_key,
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
    classified_total = len(unscoped) + len(scoped) + len(direct)
    denom = classified_total or 1

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
        own_adverts_flood_interval_minutes=own_adverts_flood_interval,
        own_adverts_direct=own_adverts_direct,
        own_adverts_direct_interval_minutes=own_adverts_direct_interval,
        repeater_total_packets=total,
        repeater_rank=rank_by_key.get(selected.public_key),
        repeater_rank_total=len(ranking),
        unscoped_packets=len(unscoped),
        unscoped_percent=(100 * len(unscoped) / denom) if total else 0.0,
        scoped_packets=len(scoped),
        scoped_percent=(100 * len(scoped) / denom) if total else 0.0,
        direct_packets=len(direct),
        direct_percent=(100 * len(direct) / denom) if total else 0.0,
        own_advert_path_hash_sizes=advert_hash_sizes,
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


def fmt_minutes(value: float | None) -> str:
    if value is None:
        return "–"
    rounded = round(value)
    if abs(value - rounded) < 0.05:
        return f"{rounded} min"
    return f"{value:.1f}".replace(".", ",") + " min"


def fmt_hours_from_minutes(value: float | None) -> str:
    if value is None:
        return "–"
    hours = value / 60.0
    return f"{hours:.1f}".replace(".", ",") + " h"


def assessment_html(kind: str, text: str) -> str:
    if not text:
        return ""
    labels = {
        "positive": "Positiv",
        "warning": "Auffällig",
        "info": "Hinweis",
    }
    label = labels.get(kind, "Hinweis")
    return (
        f"<div class='assessment assessment-{esc(kind)}'>"
        f"<strong>{esc(label)}:</strong> {esc(text)}"
        "</div>"
    )



def fmt_hash_sizes(values: tuple[int, ...]) -> str:
    if not values:
        return "–"
    return " / ".join(f"{value} Byte" for value in values)


def assess_advert_hash_sizes(values: tuple[int, ...]) -> tuple[str, str]:
    if not values:
        return (
            "info",
            "Für eigene Adverts konnte im Beobachtungszeitraum keine "
            "Path-Hash-Größe bestimmt werden.",
        )
    if len(values) > 1:
        rendered = fmt_hash_sizes(values)
        if 1 in values:
            return (
                "warning",
                f"Bei eigenen Flood-Adverts wurden unterschiedliche Path-Hash-Größen "
                f"beobachtet ({rendered}), darunter 1 Byte. Empfohlen werden "
                "2 oder 3 Byte. Prüfe path.hash.mode "
                "(0 = 1 Byte, 1 = 2 Byte).",
            )
        return (
            "info",
            f"Bei eigenen Flood-Adverts wurden unterschiedliche Path-Hash-Größen "
            f"beobachtet ({rendered}). Empfohlen werden 2 oder 3 Byte; eine "
            "Änderung innerhalb des Beobachtungszeitraums ist möglich.",
        )
    value = values[0]
    if value in (2, 3):
        return (
            "positive",
            f"Die eigenen Flood-Adverts verwenden einen {value}-Byte-Path-Hash. "
            "Empfohlen werden 2 oder 3 Byte.",
        )
    return (
        "warning",
        "Die eigenen Flood-Adverts verwenden einen 1-Byte-Path-Hash. Empfohlen "
        "werden 2 oder 3 Byte. Prüfe path.hash.mode "
        "(0 = 1 Byte, 1 = 2 Byte).",
    )



def assess_flood_max(value: int | None) -> tuple[str, str]:
    if value is None:
        return "", ""
    if value <= 16:
        return ("positive", f"Das beobachtete Maximum von {value} Hops liegt innerhalb der Empfehlung flood.max ≤ 16.")
    return ("warning", f"Es wurden bis zu {value} Hops am Repeater beobachtet. Empfohlen wird flood.max ≤ 16.")


def assess_unscoped_max(value: int | None) -> tuple[str, str]:
    if value is None:
        return "", ""
    if value == 0:
        return (
            "info",
            "Unscoped-Pakete wurden nur bei Hop 0 beobachtet. "
            "Für Repeater auf exponierten Standorten kann "
            "flood.max.unscoped = 0 bewusst sinnvoll sein.",
        )
    if value <= 3:
        return (
            "positive",
            f"Das beobachtete Maximum von {value} Hops überschreitet den "
            "empfohlenen Wert flood.max.unscoped = 3 nicht.",
        )
    return (
        "warning",
        f"Unscoped-Pakete wurden mit bis zu {value} Hops am Repeater "
        "beobachtet. Empfohlen wird flood.max.unscoped = 3.",
    )


def assess_advert_max(value: int | None) -> tuple[str, str]:
    if value is None:
        return "", ""
    if value <= 3:
        return (
            "positive",
            f"Weitergeleitete Adverts wurden mit maximal {value} Hops am "
            "Repeater beobachtet. Das entspricht dem Richtwert "
            "flood.max.advert = 3 bzw. liegt darunter.",
        )
    return (
        "warning",
        f"Adverts wurden mit bis zu {value} Hops am Repeater beobachtet. "
        "Als Richtwert wird flood.max.advert = 3 empfohlen.",
    )


def assess_direct_advert_interval(value: float | None) -> tuple[str, str]:
    if value is None:
        return "", ""
    if value > 210:
        return (
            "positive",
            f"Der typische beobachtete Abstand beträgt {fmt_minutes(value)}. "
            "Werte über 210 min gelten als günstig; empfohlen sind 239 min "
            "(maximal einstellbar: 240 min).",
        )
    return (
        "warning",
        f"Der typische beobachtete Abstand beträgt {fmt_minutes(value)}. "
        "Für advert.interval gelten Werte über 210 min als günstig; empfohlen "
        "sind 239 min (maximal einstellbar: 240 min). Empfangslücken können "
        "den beobachteten Abstand beeinflussen.",
    )


def assess_flood_advert_interval(
    event_count: int,
    value: float | None,
) -> tuple[str, str]:
    if event_count == 0:
        return (
            "info",
            "Im Beobachtungszeitraum wurden keine eigenen Flood-Adverts erkannt. "
            "Es liegen daher keine Daten zur Beurteilung des Flood-Advert-Intervalls vor. "
            "Möglicherweise wurden keine Flood-Adverts empfangen oder der Versand ist "
            "mit flood.advert.interval = 0 deaktiviert. Bei aktiviertem Versand werden "
            "≥ 70 h empfohlen; einstellbar sind 3–168 h.",
        )

    if event_count == 1:
        return (
            "info",
            "Im Beobachtungszeitraum wurde nur ein eigenes Flood-Advert erkannt. "
            "Damit kann kein typischer Abstand bestimmt und das Flood-Advert-Intervall "
            "nicht bewertet werden. Bei aktiviertem Versand werden ≥ 70 h empfohlen; "
            "einstellbar sind 3–168 h.",
        )

    if value is None:
        return (
            "info",
            "Es wurden mehrere eigene Flood-Adverts erkannt, aber kein typischer "
            "Abstand konnte bestimmt werden.",
        )

    hours = value / 60.0
    nearest_multiple = round(hours / 24.0) * 24.0
    near_24_multiple = nearest_multiple >= 24.0 and abs(hours - nearest_multiple) <= 1.0

    if hours >= 70.0:
        if near_24_multiple:
            return (
                "info",
                f"Der typische beobachtete Abstand beträgt {fmt_hours_from_minutes(value)} "
                "und erfüllt die Empfehlung von mindestens 70 h. Er liegt jedoch "
                "nahe an einem Vielfachen von 24 h; solche Einstellungen sollten "
                "zur Kollisionsvermeidung vermieden werden.",
            )
        return (
            "positive",
            f"Der typische beobachtete Abstand beträgt {fmt_hours_from_minutes(value)} "
            "und liegt damit innerhalb der Empfehlung flood.advert.interval ≥ 70 h.",
        )

    return (
        "warning",
        f"Der typische beobachtete Abstand beträgt {fmt_hours_from_minutes(value)} "
        "und liegt unter der Empfehlung flood.advert.interval ≥ 70 h. "
        "Einstellbar sind 3–168 h. Der beobachtete Abstand muss nicht exakt "
        "der Konfiguration entsprechen.",
    )


def render_html(
    metrics: Metrics,
    neighbors: list[NeighborInfo],
    neighbors_gt3: list[NeighborInfo],
    ranking: list[tuple[str, int]],
    contacts: list[Contact],
) -> str:

    period_text = (
        f"{format_period_de(metrics.period_from)} – "
        f"{format_period_de(metrics.period_to)}"
    )

    receiver_cards = [
        ("Gesamtpakete", fmt_int(metrics.total_packets)),
        ("Direkt gehörte Repeater", fmt_int(metrics.directly_heard_repeaters)),
        ("Repeater im beobachteten Mesh", fmt_int(metrics.repeater_rank_total)),
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
        (
            "Pakete mit Repeater im Pfad",
            fmt_int(metrics.repeater_total_packets),
            "Pakete",
            ("", ""),
        ),
        (
            "Rang im beobachteten Mesh",
            "–" if metrics.repeater_rank is None else str(metrics.repeater_rank),
            "" if metrics.repeater_rank is None else f"von {metrics.repeater_rank_total} Repeatern",
            ("", ""),
        ),
        (
            "Path-Hash eigener Flood-Adverts",
            fmt_hash_sizes(metrics.own_advert_path_hash_sizes),
            "beobachtete Hash-Größe",
            assess_advert_hash_sizes(metrics.own_advert_path_hash_sizes),
        ),
        (
            "Max. Hops am Repeater",
            fmt_int(metrics.max_hops),
            "Hops",
            assess_flood_max(metrics.max_hops),
        ),
        (
            "Max. Unscoped-Hops",
            fmt_int(metrics.max_hops_unscoped),
            "Hops",
            assess_unscoped_max(metrics.max_hops_unscoped),
        ),
    ]

    def render_repeater_kpis(items: list[tuple[str, str, str, tuple[str, str]]]) -> str:
        return "".join(
            f"""
            <div class="kpi">
              <div class="kpi-value">{esc(main_value)}</div>
              <div class="kpi-subvalue">{esc(sub_value)}</div>
              <div class="kpi-label">{esc(label)}</div>
              {assessment_html(*assessment)}
            </div>
            """
            for label, main_value, sub_value, assessment in items
        )

    repeater_kpi_primary_html = render_repeater_kpis(repeater_kpis[:2])
    repeater_kpi_path_html = render_repeater_kpis(repeater_kpis[2:])

    routing_cards = [
        (
            "Scoped",
            fmt_pct(metrics.scoped_percent),
            f"{fmt_int(metrics.scoped_packets)} Pakete",
            "RT 0 + RT 3",
            "Routing mit Scope/Region",
        ),
        (
            "Unscoped",
            fmt_pct(metrics.unscoped_percent),
            f"{fmt_int(metrics.unscoped_packets)} Pakete",
            "RT 1",
            "Flood-Routing ohne Region",
        ),
        (
            "Direct",
            fmt_pct(metrics.direct_percent),
            f"{fmt_int(metrics.direct_packets)} Pakete",
            "RT 2",
            "Direkte bzw. pfadbasierte Übertragung",
        ),
    ]

    routing_cards_html = "".join(
        f"""
        <div class="routing-card">
          <div class="routing-label">{esc(label)}</div>
          <div class="routing-value">{esc(value)}</div>
          <div class="routing-subvalue">{esc(subvalue)}</div>
          <div class="routing-detail">{esc(detail)}</div>
        </div>
        """
        for label, value, subvalue, route_type_text, detail in routing_cards
    )

    advert_cards = [
        (
            "Eigene Direct-Adverts",
            fmt_int(metrics.own_adverts_direct),
            "Advert-Ereignisse gehört",
            f"Typischer Abstand {fmt_minutes(metrics.own_adverts_direct_interval_minutes)}",
            assess_direct_advert_interval(
                metrics.own_adverts_direct_interval_minutes
            ),
        ),
        (
            "Eigene Flood-Adverts",
            fmt_int(metrics.own_adverts_flood),
            "Advert-Ereignisse gehört",
            f"Typischer Abstand {fmt_hours_from_minutes(metrics.own_adverts_flood_interval_minutes)}",
            assess_flood_advert_interval(
                metrics.own_adverts_flood,
                metrics.own_adverts_flood_interval_minutes,
            ),
        ),
        (
            "Weitergeleitete Adverts",
            "–" if metrics.max_hops_forwarded_adverts is None else str(metrics.max_hops_forwarded_adverts),
            "Max. Hops am Repeater",
            "höchste beobachtete Hop-Position",
            assess_advert_max(metrics.max_hops_forwarded_adverts),
        ),
    ]

    advert_cards_html = "".join(
        f"""
        <div class="advert-card">
          <div class="advert-label">{esc(label)}</div>
          <div class="advert-value">{esc(value)}</div>
          <div class="advert-subvalue">{esc(subvalue)}</div>
          <div class="advert-detail">{esc(detail)}</div>
          {assessment_html(*assessment)}
        </div>
        """
        for label, value, subvalue, detail, assessment in advert_cards
    )

    if neighbors:
        neighbor_rows = []
        for n in neighbors:
            note = ""
            display_name = esc(n.name)
            display_key = esc(short_key(n.public_key))

            if n.ambiguous:
                note = (
                    f"<div class='warn'>Path-ID {esc(n.path_id)} ist "
                    f"{n.candidates}-fach mehrdeutig.</div>"
                )

                # Mögliche Repeater nicht inline, sondern jeweils in eigener Zeile.
                candidate_names = [
                    part.strip()
                    for part in n.name.split(" / ")
                    if part.strip()
                ]
                display_name = (
                    "<div class='neighbor-candidates'>"
                    + "".join(
                        f"<div>{esc(name)}</div>"
                        for name in candidate_names
                    )
                    + "</div>"
                    if candidate_names
                    else "<span class='muted'>mehrdeutig</span>"
                )

                # Bei einer Hash-Kollision keinen Kandidaten-Public-Key zeigen.
                # Stattdessen die tatsächlich beobachtete Path-ID ausgeben.
                display_key = esc(n.path_id)

            elif n.candidates == 0:
                note = (
                    f"<div class='muted small'>Path-ID {esc(n.path_id)} "
                    "konnte keinem bekannten Repeater eindeutig zugeordnet "
                    "werden.</div>"
                )
                display_key = esc(n.path_id)

            neighbor_rows.append(
                "<tr>"
                f"<td class='mono path-id'>{esc(n.path_id)}</td>"
                f"<td class='neighbor-name'>{display_name}{note}</td>"
                f"<td class='mono key'>{display_key}</td>"
                f"<td class='num'>{fmt_int(n.packets)}</td>"
                "</tr>"
            )

        neighbors_html = f"""
        <table class="neighbors-table repeater-neighbors-table gt3-table">
          <colgroup>
            <col class="gt3-col-path">
            <col class="gt3-col-name">
            <col class="gt3-col-key">
            <col class="gt3-col-count">
          </colgroup>
          <thead>
            <tr>
              <th>Path-ID</th>
              <th>Repeater</th>
              <th>Public Key</th>
              <th class="num">Pakete</th>
            </tr>
          </thead>
          <tbody>{''.join(neighbor_rows)}</tbody>
        </table>
        """
    else:
        neighbors_html = (
            "<p class='status muted'>Keine Repeater-Nachbarn ermittelt.</p>"
        )

    # Bei kurzen Path-Hashes kann eine Path-ID zu mehreren bekannten
    # Repeatern passen. Solche Hash-Kollisionen dürfen nicht als fest
    # identifizierter Nachbar dargestellt oder einem einzelnen Repeater
    # zugerechnet werden.
    gt3_unique = [
        n for n in neighbors_gt3
        if not n.ambiguous and n.candidates == 1
    ]
    gt3_ambiguous = [
        n for n in neighbors_gt3
        if n.ambiguous and n.candidates > 1
    ]
    gt3_unknown = [
        n for n in neighbors_gt3
        if not n.ambiguous and n.candidates == 0
    ]

    gt3_parts = [
        """
        <p class="section-intro">
          Diese eindeutig aufgelösten Nachbarn wurden bei unscoped
          Flood-Paketen mit mehr als drei Hops am untersuchten Repeater
          beobachtet. Mehrdeutige Path-IDs werden hier bewusst nicht als
          Repeater gezählt.
        </p>
        """
    ]

    if gt3_unique:
        gt3_rows = []
        for n in gt3_unique:
            gt3_rows.append(
                "<tr>"
                f"<td class='mono path-id'>{esc(n.path_id)}</td>"
                f"<td class='neighbor-name'>{esc(n.name)}</td>"
                f"<td class='mono key'>{esc(short_key(n.public_key))}</td>"
                f"<td class='num'>{fmt_int(n.unscoped_gt3_packets)}</td>"
                "</tr>"
            )

        gt3_parts.append(
            f"""
            <h3>Eindeutig aufgelöste Repeater</h3>
            <table class="neighbors-table gt3-table compact-neighbor-table">
              <colgroup>
                <col class="gt3-col-path">
                <col class="gt3-col-name">
                <col class="gt3-col-key">
                <col class="gt3-col-count">
              </colgroup>
              <thead>
                <tr>
                  <th>Path-ID</th>
                  <th>Repeater</th>
                  <th>Public Key</th>
                  <th class="num">Pakete</th>
                </tr>
              </thead>
              <tbody>{''.join(gt3_rows)}</tbody>
            </table>
            """
        )
    else:
        gt3_parts.append(
            """
            <div class="status-ok">
              Keine eindeutig identifizierten Repeater-Nachbarn bei
              Unscoped-Paketen mit mehr als 3 Hops beobachtet.
            </div>
            """
        )

    if gt3_ambiguous:
        ambiguous_rows = []
        for n in gt3_ambiguous:
            matches = [
                part.strip()
                for part in n.name.split(" / ")
                if part.strip()
            ]
            candidate_html = (
                "<div class='neighbor-candidates'>"
                + "".join(
                    f"<div>{esc(name)}</div>"
                    for name in matches
                )
                + "</div>"
                if matches
                else "<span class='muted'>(keine Namen verfügbar)</span>"
            )
            ambiguous_rows.append(
                "<tr>"
                f"<td class='mono path-id'>{esc(n.path_id)}</td>"
                f"<td>{candidate_html}</td>"
                f"<td class='num'>{fmt_int(n.candidates)}</td>"
                f"<td class='num'>{fmt_int(n.unscoped_gt3_packets)}</td>"
                "</tr>"
            )

        gt3_parts.append(
            f"""
            <div class="ambiguous-subsection">
              <h3>Nicht eindeutig auflösbare Path-IDs</h3>
              <p class="section-intro">
                Aufgrund der verwendeten Path-Hash-Größe können diese
                Pfadpositionen keinem einzelnen bekannten Repeater eindeutig
                zugeordnet werden. Die Paketanzahl beschreibt das Auftreten
                der mehrdeutigen Path-ID und wird keinem der möglichen
                Repeater zugerechnet.
              </p>
              <table class="neighbors-table ambiguous-table gt3-table compact-neighbor-table">
                <colgroup>
                  <col class="gt3-col-path">
                  <col class="gt3-col-name">
                  <col class="gt3-col-key">
                  <col class="gt3-col-count">
                </colgroup>
                <thead>
                  <tr>
                    <th>Path-ID</th>
                    <th>Mögliche Repeater</th>
                    <th class="num">Kandidaten</th>
                    <th class="num">Pakete</th>
                  </tr>
                </thead>
                <tbody>{''.join(ambiguous_rows)}</tbody>
              </table>
            </div>
            """
        )

    if gt3_unknown:
        unknown_rows = []
        for n in gt3_unknown:
            unknown_rows.append(
                "<tr>"
                f"<td class='mono path-id'>{esc(n.path_id)}</td>"
                "<td class='muted'>nicht bekannt</td>"
                "<td class='mono key muted'>–</td>"
                f"<td class='num'>{fmt_int(n.unscoped_gt3_packets)}</td>"
                "</tr>"
            )

        gt3_parts.append(
            f"""
            <div class="ambiguous-subsection">
              <h3>Nicht bekannte Path-IDs</h3>
              <p class="section-intro">
                Diese Path-IDs konnten keinem aktuell bekannten Repeater
                zugeordnet werden und werden deshalb ebenfalls nicht als
                Repeater-Nachbarn gezählt.
              </p>
              <table class="neighbors-table gt3-table compact-neighbor-table">
                <colgroup>
                  <col class="gt3-col-path">
                  <col class="gt3-col-name">
                  <col class="gt3-col-key">
                  <col class="gt3-col-count">
                </colgroup>
                <thead>
                  <tr>
                    <th>Path-ID</th>
                    <th>Repeater</th>
                    <th>Public Key</th>
                    <th class="num">Pakete</th>
                  </tr>
                </thead>
                <tbody>{''.join(unknown_rows)}</tbody>
              </table>
            </div>
            """
        )

    gt3_html = "".join(gt3_parts)

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
  line-height:1.4;
  background:#fff;
}}
.report-header {{
  border-bottom:2px solid var(--fg);
  padding-bottom:18px;
  margin-bottom:22px;
}}
.report-brand {{
  color:var(--muted);
  font-size:.82rem;
  font-weight:700;
  letter-spacing:.08em;
  text-transform:uppercase;
}}
.report-type {{
  margin:4px 0 3px;
  font-size:1.7rem;
}}
.report-object {{
  font-size:1.12rem;
  font-weight:700;
  margin-top:7px;
}}
.report-object-key {{
  color:var(--muted);
  font-size:.8rem;
  margin-top:3px;
  margin-bottom:16px;
}}
.report-context-grid {{
  display:grid;
  grid-template-columns:2fr 1fr;
  gap:14px;
}}
.report-context-card {{
  border:1px solid var(--line);
  border-radius:8px;
  background:var(--soft2);
  padding:10px 12px;
}}
.report-context-label {{
  color:var(--muted);
  font-size:.78rem;
  margin-bottom:4px;
}}
.report-context-value {{
  font-weight:700;
}}
.report-context-sub {{
  margin-top:3px;
  color:var(--muted);
  font-size:.8rem;
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
.methodology-intro {{
  color:var(--muted);
  max-width:none;
  width:100%;
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
.rank-explainer {{
  margin-top:10px;
  font-size:.86rem;
}}
.kpi-grid {{
  display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:12px;
}}
.repeater-kpi-primary-grid {{
  grid-template-columns:repeat(2,minmax(0,1fr));
}}
.repeater-kpi-path-grid {{
  grid-template-columns:repeat(3,minmax(0,1fr));
  margin-top:12px;
}}
.kpi {{
  border:1px solid var(--line);
  border-radius:9px;
  padding:16px;
  background:var(--soft2);
  min-height:104px;
}}
.kpi-value {{
  font-size:1.05rem;
  font-weight:700;
  line-height:1.08;
  margin-bottom:4px;
}}
.kpi-subvalue {{
  color:var(--muted);
  font-size:.88rem;
  line-height:1.2;
  min-height:1.1em;
  margin-bottom:10px;
}}
.kpi-label {{
  color:var(--muted);
  font-size:.86rem;
}}
.routing-subsection {{
  margin-top:28px;
  padding-top:20px;
  border-top:1px solid var(--line);
}}
.routing-subsection h3 {{
  margin:0 0 6px;
  font-size:1.08rem;
}}
.routing-intro {{
  margin-bottom:0;
}}
.routing-grid {{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:12px;
  margin-top:14px;
}}
.routing-card {{
  border:1px solid var(--line);
  border-radius:9px;
  padding:16px;
  background:var(--soft2);
  min-height:150px;
}}
.routing-label {{
  color:var(--muted);
  font-size:.86rem;
  margin-bottom:8px;
}}
.routing-value {{
  font-size:1.05rem;
  font-weight:700;
  line-height:1.08;
  margin-bottom:4px;
}}
.routing-subvalue {{
  color:var(--muted);
  font-size:.88rem;
  margin-bottom:10px;
}}
.routing-type {{
  font-size:.9rem;
  font-weight:700;
  margin-bottom:4px;
}}
.routing-detail {{
  color:var(--muted);
  font-size:.84rem;
  line-height:1.35;
}}
.advert-subsection {{
  margin-top:28px;
  padding-top:20px;
  border-top:1px solid var(--line);
}}
.advert-subsection h3 {{
  margin:0 0 6px;
  font-size:1.08rem;
}}
.advert-intro {{
  margin-bottom:0;
}}
.advert-grid {{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:12px;
  margin-top:14px;
}}
.advert-card {{
  border:1px solid var(--line);
  border-radius:9px;
  padding:16px;
  background:var(--soft2);
  min-height:128px;
}}
.advert-label {{
  color:var(--muted);
  font-size:.86rem;
  margin-bottom:8px;
}}
.advert-value {{
  font-size:1.05rem;
  font-weight:700;
  line-height:1.08;
  margin-bottom:4px;
}}
.advert-subvalue {{
  color:var(--muted);
  font-size:.88rem;
  margin-bottom:10px;
}}
.advert-detail {{
  font-size:.9rem;
  font-weight:600;
}}
.assessment {{
  margin-top:12px;
  padding-top:9px;
  border-top:1px solid var(--line);
  font-size:.82rem;
  line-height:1.35;
}}
.assessment-positive {{
  color:#246b3c;
}}
.assessment-warning {{
  color:#9a4c00;
}}
.assessment-info {{
  color:var(--muted);
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

.neighbors-table {{
  width:100%;
  table-layout:fixed;
}}
.neighbors-table .neighbor-col-name {{ width:73%; }}
.neighbors-table .neighbor-col-count {{ width:8%; }}
.neighbors-table .neighbor-col-key {{ width:19%; }}

.repeater-neighbors-table {{
  margin-top:7px;
  margin-bottom:12px;
  font-size:.84rem;
}}
.repeater-neighbors-table th {{
  padding:6px 8px;
  font-size:.84rem;
}}
.repeater-neighbors-table th.num,
.compact-neighbor-table th.num {{
  font-weight:700;
}}
.repeater-neighbors-table td {{
  padding:5px 8px;
  line-height:1.2;
}}
.repeater-neighbors-table .neighbor-name {{
  font-family:Arial,Helvetica,sans-serif;
  font-size:.84rem;
  font-weight:400;
}}
.repeater-neighbors-table .num {{
  font-size:.84rem;
  font-weight:400;
}}
.repeater-neighbors-table .key {{
  font-size:.78rem;
}}
.repeater-neighbors-table .path-id {{
  font-size:.78rem;
}}
.neighbor-candidates {{
  display:grid;
  gap:2px;
}}
.neighbor-candidates > div {{
  line-height:1.15;
}}
.repeater-neighbors-table .neighbor-name .warn,
.repeater-neighbors-table .neighbor-name .small,
.repeater-neighbors-table .neighbor-name .muted {{
  font-size:.74rem;
  line-height:1.15;
}}
.compact-neighbor-table {{
  margin-top:7px;
  margin-bottom:12px;
  font-size:.84rem;
}}
.compact-neighbor-table th {{
  padding:6px 8px;
  font-size:.84rem;
}}
.compact-neighbor-table td {{
  padding:5px 8px;
  line-height:1.2;
}}
.compact-neighbor-table .neighbor-name {{
  font-family:Arial,Helvetica,sans-serif;
  font-size:.84rem;
  font-weight:400;
}}
.compact-neighbor-table .num {{
  font-size:.84rem;
  font-weight:400;
}}
.compact-neighbor-table .key,
.compact-neighbor-table .path-id {{
  font-size:.78rem;
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
.gt3-table {{
  table-layout:fixed;
}}
.gt3-col-path {{
  width:18%;
}}
.gt3-col-name {{
  width:50%;
}}
.gt3-col-key {{
  width:20%;
}}
.gt3-col-count {{
  width:12%;
}}
.gt3-table .path-id {{
  white-space:nowrap;
}}
.gt3-table .muted {{
  color:var(--muted);
}}
.ambiguous-subsection {{
  margin-top:28px;
  padding-top:4px;
}}
.ambiguous-subsection h3 {{
  margin-bottom:6px;
}}
.ambiguous-table td {{
  vertical-align:top;
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
  .report-context-grid {{ grid-template-columns:1fr; }}
  .kpi-grid {{ grid-template-columns:1fr 1fr; }}
  .routing-grid {{ grid-template-columns:1fr; }}
  .two-col {{ grid-template-columns:1fr; }}
}}
@media (max-width:520px) {{
  body {{ padding:0 16px 40px; }}
  .receiver-grid {{ grid-template-columns:1fr; }}
  .kpi-grid {{ grid-template-columns:1fr; }}
  h1 {{ font-size:1.65rem; }}
}}
@page {{
  margin:10mm;
}}
@media print {{
  body {{ margin:0;max-width:none;padding:0; }}
  details {{ display:none; }}
  .report-header {{ break-after:avoid-page; }}

  /* Beobachtungsstandort und Beobachtungszeitraum im PDF immer nebeneinander. */
  .report-context-grid {{
    grid-template-columns:2fr 1fr !important;
  }}


  h2,h3 {{ break-after:avoid-page; }}
  .section-intro,.repeater-section-subtitle {{ break-after:avoid-page; }}

  /* Beobachtungskennzahlen und der Beginn der Repeater-Kennzahlen
     gehören bewusst auf die erste Seite. */
  .observer-metrics-section {{
    break-before:auto;
    margin-top:0;
  }}
  .receiver-grid {{
    grid-template-columns:repeat(3,minmax(0,1fr));
    gap:10px;
  }}
  .repeater-kpi-primary-grid {{
    grid-template-columns:repeat(2,minmax(0,1fr)) !important;
  }}
  .repeater-kpi-path-grid {{
    grid-template-columns:repeat(3,minmax(0,1fr)) !important;
    gap:10px;
  }}
  .routing-grid {{
    grid-template-columns:repeat(3,minmax(0,1fr)) !important;
    gap:10px;
  }}
  .info-card {{
    padding:12px 13px;
  }}
  .repeater-section {{
    break-before:auto;
    margin-top:24px;
  }}

  /* Die späteren Haupt-/Unterkapitel bleiben sauber getrennt. */
  .print-chapter {{ break-before:page; }}
  .print-subchapter {{ break-before:page; }}
  .advert-subsection {{
    break-before:auto;
    margin-top:24px;
  }}

  .kpi,.info-card,.routing-card,.advert-card,.assessment {{
    break-inside:avoid-page;
  }}
  table thead {{ display:table-header-group; }}
  tr {{ break-inside:avoid-page; }}
}}
</style>
</head>
<body>

<header class="report-header">
  <div class="report-brand">MESHCORE PACKETTAP</div>
  <h1 class="report-type">Repeater-Report</h1>
  <div class="report-object">{esc(metrics.repeater_name)}</div>
  <div class="report-object-key mono">
    Public Key: {esc(metrics.repeater_public_key)}
  </div>
  <div class="report-context-grid">
    <div class="report-context-card">
      <div class="report-context-label">Beobachtungsstandort</div>
      <div class="report-context-value">{esc(metrics.observer_location)}</div>
      <div class="report-context-sub mono">
        Public Key: {esc(short_key(metrics.receiver_id, 8, 8))}
      </div>
    </div>
    <div class="report-context-card">
      <div class="report-context-label">Beobachtungszeitraum</div>
      <div class="report-context-value">{esc(period_text)}</div>
    </div>
  </div>
</header>

<section class="observer-metrics-section">
  <h2>Kennzahlen des Beobachtungsstandorts</h2>
  <p class="section-intro">
    Kennzahlen des Beobachtungsstandorts im ausgewerteten Zeitraum.
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
  <div class="kpi-grid repeater-kpi-primary-grid">
    {repeater_kpi_primary_html}
  </div>
  <div class="kpi-grid repeater-kpi-path-grid">
    {repeater_kpi_path_html}
  </div>
  <div class="routing-subsection print-subchapter">
    <h3>Routing-Verhalten</h3>
    <p class="section-intro routing-intro">
      Die Routing-Typen zeigen, wie die Pakete geroutet wurden, in deren
      beobachtetem Pfad der untersuchte Repeater vorkommt. Scoped, Unscoped
      und Direct bilden gemeinsam 100&nbsp;% der eindeutig klassifizierten
      Pakete.
    </p>
    <div class="routing-grid">
      {routing_cards_html}
    </div>
    {(
        f"<p class='small muted'>Hinweis: {fmt_int(metrics.other_route_packets)} "
        "Pakete mit sonstigem oder nicht eindeutig klassifizierbarem Routing-Typ "
        "sind nicht in der 100-%-Verteilung enthalten.</p>"
        if metrics.other_route_packets > 0
        else ""
    )}
  </div>
  <div class="advert-subsection">
    <h3>Advert-Verhalten</h3>
    <p class="section-intro advert-intro">
      Die folgenden Kennzahlen zeigen das beobachtete Aussendeverhalten des
      Repeaters sowie seine Beteiligung an der Weiterleitung von Adverts im Mesh.
    </p>
    <div class="advert-grid">
      {advert_cards_html}
    </div>
  </div>
</section>

<section class="print-chapter">
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

<section class="print-chapter">
  <h2>Unscoped-Nachbarn &gt; 3 Hops</h2>
  {gt3_html}
</section>

<section class="print-chapter">
  <h2>Methodik der Auswertung</h2>

  <p class="methodology-intro">
    Dieser Report bewertet das im Beobachtungszeitraum tatsächlich sichtbare
    Verhalten des untersuchten Repeaters. Die Kennzahlen werden aus empfangenen
    Paketen, deren beobachteten Pfaden und den darin erkannten Repeatern
    abgeleitet.
  </p>

  <p class="methodology-intro">
    Grundlage der Auswertung sind ausschließlich Pakete und Repeater-Aktivitäten,
    die vom angegebenen Receiver im Beobachtungszeitraum empfangen wurden.
    Vorgänge im Mesh, die der Receiver nicht empfangen hat, können entsprechend
    nicht in die Auswertung einfließen.
  </p>

  <p class="methodology-intro">
    <strong>Mehrdeutige Path-IDs:</strong> Wenn eine verkürzte Path-ID aufgrund
    der verwendeten Path-Hash-Größe zu mehreren bekannten Repeatern passt,
    wird sie keinem einzelnen Repeater zugerechnet. Im Abschnitt
    „Unscoped-Nachbarn &gt; 3 Hops“ werden solche Hash-Kollisionen getrennt
    von eindeutig identifizierten Repeater-Nachbarn ausgewiesen.
  </p>

  <p class="methodology-intro">
    Die Ergebnisse stellen keine direkt ausgelesene Repeater-Konfiguration dar.
    Empfangslücken, nicht eindeutig auflösbare Path-IDs und außerhalb des
    Empfangsbereichs liegende Übertragungen können die beobachteten Werte
    beeinflussen.
  </p>

  <p class="methodology-intro">
    Die folgenden Erläuterungen beschreiben, wie die wesentlichen Kennzahlen
    des Reports ermittelt und bewertet werden.
  </p>

  <div class="methodology">
    <p class="small muted">
      <strong>Bewertungshinweise:</strong>
      Positive Hinweise, Hinweise und Auffälligkeiten vergleichen das
      beobachtete Verhalten mit empfohlenen Richtwerten für ein gut
      funktionierendes Mesh. Sie stellen keine direkte Auslesung der
      Repeater-Konfiguration dar. Insbesondere können beobachtete
      Advert-Abstände durch nicht empfangene Pakete größer als das tatsächlich
      konfigurierte Intervall erscheinen.
    </p>

    <p class="small muted">
      <strong>Routingtypen:</strong>
      Unscoped bezeichnet ausschließlich Flood-Pakete des Routing-Typs RT 1.
      Scoped umfasst die Routing-Typen RT 0 und RT 3.
      Direct entspricht RT 2. Die Prozentwerte von Scoped, Unscoped und Direct
      werden gemeinsam auf 100&nbsp;% normiert. Sonstige oder nicht eindeutig
      klassifizierbare Routing-Typen werden nicht in diese Prozentverteilung
      einbezogen.
    </p>

    <p class="small muted">
      <strong>Hop-Auswertung:</strong>
      „Max. Hops am Repeater“ beschreibt die Position des untersuchten Repeaters
      innerhalb des beobachteten Paketpfades. Damit wird die Hop-Anzahl zum
      Zeitpunkt der Weiterleitung durch den Repeater betrachtet und nicht die
      Länge des später vollständig beobachteten Pfades.
    </p>

    <p class="small muted">
      <strong>Path-Hash-Auswertung:</strong>
      Für die Zuordnung eines Pakets zu einem Repeater wird die im Paket
      verwendete Path-Hash-Länge berücksichtigt. 1-, 2- und 3-Byte-Path-Hashes
      werden ausgewertet. Ein Paket wird dem untersuchten Repeater jedoch nur
      dann zugerechnet, wenn der verwendete Public-Key-Präfix unter den bekannten
      Repeatern eindeutig ist. Mehrdeutige Präfixe werden nicht berücksichtigt.
    </p>

    <p class="small muted">
      <strong>Beobachtete Mesh-Größe:</strong>
      Die Anzahl „Repeater im beobachteten Mesh“ umfasst alle Repeater, die im
      Beobachtungszeitraum in Paketpfaden eindeutig identifiziert werden
      konnten. Sie ist nicht mit der Anzahl der direkt gehörten Repeater
      gleichzusetzen und bildet zugleich die Grundgesamtheit für den Rang des
      untersuchten Repeaters.
    </p>

    <p class="small muted">
      <strong>Path-Hash eigener Flood-Adverts:</strong>
      Bewertet wird ausschließlich die bei eigenen Flood-Adverts (RT 0)
      beobachtete Path-Hash-Größe. Direct-Adverts (RT 2) werden hierfür
      bewusst nicht verwendet. Empfohlen werden 2 oder 3 Byte. Bei 1 Byte
      wird auf <code>path.hash.mode</code> hingewiesen
      (0 = 1 Byte, 1 = 2 Byte). Unterschiedliche beobachtete Größen können
      auf eine Änderung innerhalb des Beobachtungszeitraums hindeuten.
    </p>

    <p class="small muted">
      <strong>Advert-Auswertung:</strong>
      Eigene Direct-Adverts werden als direkt gehörte Advert-Ereignisse des
      untersuchten Repeaters ausgewertet. Eigene Flood-Adverts werden anhand
      ihres Advert-Inhalts dem untersuchten Repeater zugeordnet. Mehrfach über
      verschiedene Wege empfangene Kopien desselben Flood-Adverts zählen dabei
      nur als ein Advert-Ereignis. Der typische Abstand ist der Median der
      Zeitabstände zwischen aufeinanderfolgenden eindeutig erkannten
      Advert-Ereignissen. Bei weniger als zwei Ereignissen wird kein Abstand
      angegeben.
    </p>

    <p class="small muted">
      <strong>Repeater-Nachbarn:</strong>
      Als Nachbar gilt ausschließlich der Repeater, der im beobachteten
      Paketpfad unmittelbar vor dem untersuchten Repeater steht.
    </p>

    <p class="small muted">
      <strong>Advert-Hop-Auswertung:</strong>
      „Max. Hops weitergeleiteter Adverts“ betrachtet alle Advert-Pakete, die
      über den untersuchten Repeater weitergeleitet wurden, und gibt die höchste
      dabei beobachtete Hop-Position am Repeater an.
    </p>

    <p class="small muted">
      <strong>Rang des Repeaters:</strong>
      Der Rang basiert auf der Anzahl der Pakete, in deren beobachtetem Pfad
      der Repeater eindeutig erkannt wurde.
    </p>
  </div>
</section>

<footer class="footer">
  MeshCore PacketTap · Repeater-Report
</footer>

</body>
</html>
"""



# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MeshCore PacketTap Repeater Report v0.49"
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
