#!/usr/bin/env python3
"""
MeshCore PacketTap - historische GRP_TXT-Channelkorrektur

Version: 0.2.3

Zweck
-----
Korrigiert historische mc_rx-GRP_TXT-Datensätze, die noch mit der alten
1-Byte-Hash-Zuordnung geschrieben wurden.

Die aktuelle meshcore_decoder.py (v0.2 oder neuer) wird verwendet:
    1-Byte-Hash -> alle Kandidaten -> 2-Byte-MAC prüfen -> eindeutiger Channel

Sicherheitskonzept
------------------
* Standard ist DRY-RUN. Ohne --apply wird nichts in QuestDB geändert.
* v0.2.1 verarbeitet große historische Bestände in Zeitfenstern (Default: 1 Tag).
* Datensätze ohne packet_payload_hex werden bewusst übersprungen.
* Alte grp_txt_sender_name/grp_txt_body-Felder werden NICHT aus QuestDB gelesen.
  Dadurch können historische Steuerzeichen in diesen Feldern die JSON-Antwort
  nicht mehr beschädigen.
* Verifizierte Payloads schreiben channel, grp_txt_sender_name und grp_txt_body
  vollständig neu.
* Bei channel_resolution_status=mac_failed werden channel,
  grp_txt_sender_name und grp_txt_body auf NULL gesetzt, weil die alte
  Channel-Zuordnung mit dem aktuellen MAC-Check widerlegt wurde.
* Bei channel_resolution_status=unknown bleibt der historische Datensatz
  unverändert, da aktuell keine sichere Aussage über den Channel möglich ist.
* Standardmäßig werden alle historischen GRP_TXT-Pakete neu bewertet.
  Dadurch werden sowohl frühere Hash-Kollisionen korrigiert als auch bislang
  unbekannte Channels nachträglich erkannt, sofern sie inzwischen in den
  lokalen Channel-JSON-Dateien vorhanden sind.
* Mit --collisions-only kann die Prüfung optional auf aktuelle Hash-Kollisionen
  beschränkt werden.
* Es werden nur Zeilen aktualisiert, deren neu berechnete Werte vom Bestand
  abweichen.
* channel, grp_txt_sender_name und grp_txt_body werden gemeinsam korrigiert.

Beispiele
---------
Nur prüfen:
    python tools/correct_grp_txt_channels_v0.2.3.py

Seit 1. August prüfen:
    python tools/correct_grp_txt_channels_v0.2.3.py --from 2026-08-01

Änderungen tatsächlich schreiben:
    python tools/correct_grp_txt_channels_v0.2.3.py --from 2026-08-01 --apply

Nur aktuelle Hash-Kollisionen prüfen:
    python tools/correct_grp_txt_channels_v0.2.3.py --collisions-only

Gesamten Bestand schreiben:
    python tools/correct_grp_txt_channels_v0.2.3.py --apply
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

APP_VERSION = "0.2.3"


def import_decoder():
    """Import project-local meshcore_decoder.py."""
    try:
        import meshcore_decoder as decoder
    except ImportError:
        # Script may live in tools/, decoder one directory above.
        project_root = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(project_root))
        import meshcore_decoder as decoder

    version = getattr(decoder, "APP_VERSION", None)
    if version is None:
        print(
            "WARNUNG: meshcore_decoder.py hat keine APP_VERSION. "
            "Für diese Korrektur wird v0.2 oder neuer empfohlen.",
            file=sys.stderr,
        )
    return decoder


def questdb_exec(
    base_url: str,
    query: str,
    *,
    timeout: float = 60.0,
) -> dict[str, Any]:
    url = (
        base_url.rstrip("/")
        + "/exec?"
        + urllib.parse.urlencode({"query": query})
    )
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()

    if not raw:
        return {}

    data = json.loads(raw.decode("utf-8"))
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(str(data["error"]))
    return data


def result_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    columns = result.get("columns") or []
    dataset = result.get("dataset") or []

    names: list[str] = []
    for column in columns:
        if isinstance(column, dict):
            names.append(str(column.get("name")))
        else:
            names.append(str(column))

    return [
        dict(zip(names, row))
        for row in dataset
    ]


def sql_string(value: Any) -> str:
    """Return safe SQL VARCHAR literal."""
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "''") + "'"


def sql_timestamp(value: Any) -> str:
    """Return QuestDB timestamp literal text."""
    return sql_string(value)


def parse_date_arg(value: str | None, *, end: bool = False) -> str | None:
    if not value:
        return None

    text = value.strip()

    # Allow YYYY-MM-DD or complete ISO timestamp.
    if len(text) == 10:
        datetime.strptime(text, "%Y-%m-%d")
        return (
            text + "T23:59:59.999999Z"
            if end
            else text + "T00:00:00.000000Z"
        )

    normalized = text.replace("Z", "+00:00")
    datetime.fromisoformat(normalized)
    return text


def collision_hashes(decoder) -> dict[str, list[dict[str, str]]]:
    mapping = decoder.get_public_channels(reload=True)
    return {
        channel_hash: candidates
        for channel_hash, candidates in mapping.items()
        if len(candidates) > 1
    }




def normalize_db_value(value: Any) -> str | None:
    """Normalize QuestDB/decoder values to str or None without altering content."""
    if value is None:
        return None

    text = str(value)
    if text == "":
        return None

    return text


def parse_questdb_ts(value: Any) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        from datetime import timezone
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def iso_z(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def load_time_bounds(
    questdb_url: str,
    *,
    date_from: str | None,
    date_to: str | None,
) -> tuple[datetime | None, datetime | None, int]:
    where = [
        "payload_type = 'GRP_TXT'",
        "packet_payload_hex IS NOT NULL",
        "packet_payload_hex != ''",
    ]
    if date_from:
        where.append(f"ts >= {sql_timestamp(date_from)}")
    if date_to:
        where.append(f"ts <= {sql_timestamp(date_to)}")

    sql = f"""
SELECT
    min(ts) AS erstes,
    max(ts) AS letztes,
    count(*) AS pakete
FROM mc_rx
WHERE {' AND '.join(where)};
""".strip()

    rows = result_rows(questdb_exec(questdb_url, sql))
    if not rows:
        return None, None, 0

    row = rows[0]
    count = int(row.get("pakete") or 0)
    if count <= 0 or not row.get("erstes") or not row.get("letztes"):
        return None, None, 0

    return (
        parse_questdb_ts(row["erstes"]),
        parse_questdb_ts(row["letztes"]),
        count,
    )


def load_batch_groups(
    questdb_url: str,
    batch_from: datetime,
    batch_to: datetime,
) -> list[dict[str, Any]]:
    """
    Read only fields that are safe and needed for re-decoding.

    grp_txt_sender_name and grp_txt_body are deliberately omitted because old
    Hornisgrinde rows can contain control characters that break QuestDB's JSON
    response for strict JSON clients.
    """
    sql = f"""
SELECT
    packet_payload_hex,
    channel,
    count(*) AS pakete
FROM mc_rx
WHERE payload_type = 'GRP_TXT'
  AND packet_payload_hex IS NOT NULL
  AND packet_payload_hex != ''
  AND ts >= {sql_timestamp(iso_z(batch_from))}
  AND ts < {sql_timestamp(iso_z(batch_to))}
GROUP BY
    packet_payload_hex,
    channel
ORDER BY packet_payload_hex;
""".strip()

    return result_rows(questdb_exec(questdb_url, sql, timeout=180.0))


def build_group_update_sql(
    *,
    batch_from: datetime,
    batch_to: datetime,
    packet_payload_hex: str,
    channel: str | None,
    sender: str | None,
    body: str | None,
) -> str:
    """
    Correct every reception of the same encrypted GRP_TXT payload in the
    current time window with one UPDATE.
    """
    return f"""
UPDATE mc_rx
SET
    channel = {sql_string(channel)},
    grp_txt_sender_name = {sql_string(sender)},
    grp_txt_body = {sql_string(body)}
WHERE payload_type = 'GRP_TXT'
  AND packet_payload_hex = {sql_string(packet_payload_hex)}
  AND ts >= {sql_timestamp(iso_z(batch_from))}
  AND ts < {sql_timestamp(iso_z(batch_to))};
""".strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Historische GRP_TXT-Datensätze robust und batchweise mit "
            "meshcore_decoder v0.2+ neu bewerten."
        )
    )
    parser.add_argument(
        "--questdb-url",
        default="http://127.0.0.1:9000",
        help="QuestDB HTTP URL (Default: http://127.0.0.1:9000)",
    )
    parser.add_argument(
        "--from",
        dest="date_from",
        default=None,
        help="Startdatum/-zeit, z.B. 2026-05-04",
    )
    parser.add_argument(
        "--to",
        dest="date_to",
        default=None,
        help="Enddatum/-zeit, z.B. 2026-08-21",
    )
    parser.add_argument(
        "--batch-days",
        type=int,
        default=1,
        help="Größe eines Zeitfensters in Tagen (Default: 1)",
    )
    parser.add_argument(
        "--collisions-only",
        action="store_true",
        help=(
            "Nur GRP_TXT-Pakete mit aktuell mehrfach belegtem "
            "1-Byte-Channel-Hash prüfen."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Änderungen wirklich in QuestDB schreiben.",
    )
    parser.add_argument(
        "--show",
        type=int,
        default=30,
        help="Maximale Anzahl Beispieländerungen anzeigen (Default: 30).",
    )
    args = parser.parse_args()

    if args.batch_days < 1:
        parser.error("--batch-days muss mindestens 1 sein.")

    try:
        date_from = parse_date_arg(args.date_from, end=False)
        date_to = parse_date_arg(args.date_to, end=True)
    except ValueError as exc:
        parser.error(f"Ungültiges Datum: {exc}")

    decoder = import_decoder()
    if not hasattr(decoder, "get_channel_candidates"):
        raise RuntimeError(
            "Die produktive meshcore_decoder.py ist zu alt. "
            "Benötigt wird der kollisionssichere Decoder v0.2 oder neuer."
        )

    collisions = collision_hashes(decoder)
    channel_map = decoder.get_public_channels(reload=True)
    candidate_count = sum(len(items) for items in channel_map.values())

    print("MeshCore GRP_TXT Historical Channel Corrector")
    print("=" * 78)
    print(f"Tool-Version       : {APP_VERSION}")
    print(
        "Decoder-Version    : "
        f"{getattr(decoder, 'APP_VERSION', 'unbekannt')}"
    )
    print(f"Bekannte Hashes     : {len(channel_map)}")
    print(f"Channel-Kandidaten  : {candidate_count}")
    print(f"QuestDB            : {args.questdb_url}")
    print(
        "Modus              : "
        + ("APPLY / SCHREIBEND" if args.apply else "DRY-RUN")
    )
    print(
        "Auswahl             : "
        + (
            f"nur Hash-Kollisionen ({len(collisions)} Hashes)"
            if args.collisions_only
            else "alle GRP_TXT mit packet_payload_hex"
        )
    )
    print(f"Batch-Größe         : {args.batch_days} Tag(e)")
    print(f"Von                : {date_from or 'unbegrenzt'}")
    print(f"Bis                : {date_to or 'unbegrenzt'}")
    print()

    first_ts, last_ts, total_eligible = load_time_bounds(
        args.questdb_url,
        date_from=date_from,
        date_to=date_to,
    )

    if first_ts is None or last_ts is None:
        print("Keine korrigierbaren GRP_TXT-Datensätze mit packet_payload_hex gefunden.")
        return 0

    # Respect explicit boundaries even if the first/last eligible packet is
    # inside them.
    if date_from:
        requested_from = parse_questdb_ts(date_from)
        first_ts = max(first_ts, requested_from)
    if date_to:
        requested_to = parse_questdb_ts(date_to)
        last_ts = min(last_ts, requested_to)

    print("Korrigierbarer Bestand")
    print("-" * 78)
    print(f"Pakete             : {total_eligible}")
    print(f"Erstes             : {iso_z(first_ts)}")
    print(f"Letztes            : {iso_z(last_ts)}")
    print()

    stats = Counter()
    examples: list[str] = []

    cursor = first_ts
    # Use an exclusive end that safely includes the last timestamp.
    overall_end = last_ts + timedelta(microseconds=1)
    batch_delta = timedelta(days=args.batch_days)
    batch_no = 0

    while cursor < overall_end:
        batch_no += 1
        batch_end = min(cursor + batch_delta, overall_end)

        groups = load_batch_groups(
            args.questdb_url,
            cursor,
            batch_end,
        )

        batch_packets = 0
        batch_updates = 0

        for row in groups:
            packet_payload_hex = normalize_db_value(
                row.get("packet_payload_hex")
            )
            if not packet_payload_hex:
                continue

            packet_count = int(row.get("pakete") or 0)
            batch_packets += packet_count

            channel_hash = packet_payload_hex[:2].lower()
            if args.collisions_only and channel_hash not in collisions:
                stats["übersprungen_nicht_kollision"] += packet_count
                continue

            decoded = decoder.decode_grp_txt({
                "packet_payload_hex": packet_payload_hex,
            })

            decoded_channel = normalize_db_value(decoded.get("channel_name"))
            decoded_sender = normalize_db_value(decoded.get("grp_txt_sender_name"))
            decoded_body = normalize_db_value(decoded.get("grp_txt_body"))
            status = normalize_db_value(
                decoded.get("channel_resolution_status")
            ) or "unknown"

            old_channel = normalize_db_value(row.get("channel"))

            stats[f"status:{status}"] += packet_count
            stats["geprüft"] += packet_count

            if status == "verified":
                new_channel = decoded_channel
                new_sender = decoded_sender
                new_body = decoded_body
                stats["verifiziert"] += packet_count

            elif status == "mac_failed":
                # The historic 1-byte-hash assignment is contradicted by the
                # current 2-byte MAC verification. Remove the stale assignment.
                new_channel = None
                new_sender = None
                new_body = None
                stats["mac_failed_bereinigt"] += packet_count

            else:
                # Unknown (or another unresolved status) means we cannot make a
                # safe correction. Keep the historic row untouched.
                stats["unverändert_ungeklärt"] += packet_count
                continue

            if old_channel != new_channel:
                stats["channel_geändert"] += packet_count
                if len(examples) < args.show:
                    examples.append(
                        f"{iso_z(cursor)}..{iso_z(batch_end)}  "
                        f"hash={channel_hash}  n={packet_count}  "
                        f"{old_channel!r} -> {new_channel!r}  status={status}"
                    )

            stats["neu_geschrieben"] += packet_count
            batch_updates += 1

            if args.apply:
                update_sql = build_group_update_sql(
                    batch_from=cursor,
                    batch_to=batch_end,
                    packet_payload_hex=packet_payload_hex,
                    channel=new_channel,
                    sender=new_sender,
                    body=new_body,
                )
                questdb_exec(
                    args.questdb_url,
                    update_sql,
                    timeout=120.0,
                )

        print(
            f"Batch {batch_no:4d}: "
            f"{iso_z(cursor)} .. {iso_z(batch_end)} | "
            f"{batch_packets:7d} Pakete | "
            f"{len(groups):6d} Gruppen | "
            f"{batch_updates:6d} "
            f"{'UPDATEs' if args.apply else 'würden geschrieben'}"
        )

        cursor = batch_end

    print()
    print("Auswertung")
    print("-" * 78)
    print(f"Geprüft            : {stats['geprüft']}")
    print(f"Neu geschrieben    : {stats['neu_geschrieben']}")
    print(f"Channel geändert   : {stats['channel_geändert']}")
    print(f"Verifiziert        : {stats['verifiziert']}")
    print(f"MAC-failed berein. : {stats['mac_failed_bereinigt']}")
    print(f"Unverändert/unklar : {stats['unverändert_ungeklärt']}")
    if args.collisions_only:
        print(
            "Nicht-Kollisionen   : "
            f"{stats['übersprungen_nicht_kollision']} übersprungen"
        )
    print()

    status_items = sorted(
        (
            key.removeprefix("status:"),
            count,
        )
        for key, count in stats.items()
        if key.startswith("status:")
    )
    if status_items:
        print("Decoder-Status")
        print("-" * 78)
        for status, count in status_items:
            print(f"{status:20s} {count:8d}")
        print()

    if examples:
        print("Beispielhafte Channel-Änderungen")
        print("-" * 78)
        for example in examples:
            print(example)
        print()

    if not args.apply:
        print(
            "DRY-RUN beendet. Es wurde nichts geändert.\n"
            "Datensätze ohne packet_payload_hex wurden nicht gelesen und bleiben "
            "unverändert.\n"
            "Wenn die Auswertung plausibel ist, erneut mit --apply starten."
        )
        return 0

    print("Fertig")
    print("-" * 78)
    print(f"Neu geschrieben    : {stats['neu_geschrieben']}")
    print("Fehler             : 0")
    print()
    print(
        "Hinweis: channel, grp_txt_sender_name und grp_txt_body wurden "
        "batchweise aus dem aktuellen Decoder neu bestimmt. Datensätze ohne "
        "packet_payload_hex blieben unangetastet."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
