#!/usr/bin/env python3
"""
MeshCore PacketTap - Historical Region Backfill
Version: 0.2

Ermittelt fehlende historische mc_rx.region-Werte erneut mit der aktuellen
regions.json und meshcore_decoder.py.

Sicherheitsprinzip:
- Standard ist DRY-RUN.
- Es werden ausschließlich Datensätze mit region IS NULL betrachtet.
- Bestehende Region-Zuordnungen werden niemals überschrieben.
- Eine Region wird nur berücksichtigt, wenn meshcore_decoder.resolve_region()
  mit payload_type + region_code + packet_payload_hex einen Treffer liefert.
- Für einen Backfill muss dieselbe Region durch mindestens 2 unterschiedliche
  packet_payload_hex bestätigt sein. Mehrfache Empfänge derselben Payload
  zählen für diese Schwelle nur einmal.
- Updates werden auf Zeitfenster und die exakte Payload-Gruppe eingeschränkt.

Beispiele:
    python tools/backfill_regions_v0.1.py --questdb-url http://10.9.32.2:9000

    python tools/backfill_regions_v0.1.py --questdb-url http://10.9.32.2:9000 --apply

    python tools/backfill_regions_v0.1.py --questdb-url http://10.9.32.2:9000 \
        --from 2026-08-01 --to 2026-08-22
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

APP_VERSION = "0.2"
DEFAULT_QUESTDB_URL = "http://127.0.0.1:9000"


def sqlq(value: Any) -> str:
    """Quote a string value for QuestDB SQL."""
    return "'" + str(value).replace("'", "''") + "'"


def qdb(base_url: str, sql: str, timeout: float = 120.0) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/exec?" + urllib.parse.urlencode({"query": sql})
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if data.get("error"):
        raise RuntimeError(str(data["error"]))
    return data


def rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    columns = [
        str(column.get("name")) if isinstance(column, dict) else str(column)
        for column in (result.get("columns") or [])
    ]
    return [
        dict(zip(columns, row))
        for row in (result.get("dataset") or [])
    ]


def normalize_date(value: str | None, *, end: bool = False) -> datetime | None:
    if not value:
        return None
    value = value.strip()

    if len(value) == 10:
        dt = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if end:
            dt += timedelta(days=1)
        return dt

    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_questdb_ts(value: Any) -> datetime:
    text = str(value).strip()
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def missing_where(date_from: datetime | None, date_to: datetime | None) -> list[str]:
    where = [
        "region IS NULL",
        "region_code IS NOT NULL",
        "region_code != ''",
        "payload_type IS NOT NULL",
        "packet_payload_hex IS NOT NULL",
        "packet_payload_hex != ''",
    ]
    if date_from is not None:
        where.append(f"ts >= {sqlq(iso_z(date_from))}")
    if date_to is not None:
        where.append(f"ts < {sqlq(iso_z(date_to))}")
    return where


def inventory(
    questdb_url: str,
    date_from: datetime | None,
    date_to: datetime | None,
) -> dict[str, Any]:
    where = " AND ".join(missing_where(date_from, date_to))
    sql = f"""
SELECT
    count(*) AS pakete,
    min(ts) AS erstes,
    max(ts) AS letztes
FROM mc_rx
WHERE {where};
"""
    result_rows = rows(qdb(questdb_url, sql))
    return result_rows[0] if result_rows else {}


def load_groups(
    questdb_url: str,
    batch_from: datetime,
    batch_to: datetime,
) -> list[dict[str, Any]]:
    sql = f"""
SELECT
    payload_type,
    region_code,
    packet_payload_hex,
    count(*) AS pakete,
    min(ts) AS zuerst,
    max(ts) AS zuletzt
FROM mc_rx
WHERE region IS NULL
  AND region_code IS NOT NULL
  AND region_code != ''
  AND payload_type IS NOT NULL
  AND packet_payload_hex IS NOT NULL
  AND packet_payload_hex != ''
  AND ts >= {sqlq(iso_z(batch_from))}
  AND ts < {sqlq(iso_z(batch_to))}
GROUP BY payload_type, region_code, packet_payload_hex
ORDER BY pakete DESC;
"""
    return rows(qdb(questdb_url, sql))


def build_update_sql(
    *,
    batch_from: datetime,
    batch_to: datetime,
    payload_type: str,
    region_code: str,
    packet_payload_hex: str,
    region_name: str,
) -> str:
    return f"""
UPDATE mc_rx
SET region = {sqlq(region_name)}
WHERE region IS NULL
  AND ts >= {sqlq(iso_z(batch_from))}
  AND ts < {sqlq(iso_z(batch_to))}
  AND payload_type = {sqlq(payload_type)}
  AND region_code = {sqlq(region_code)}
  AND packet_payload_hex = {sqlq(packet_payload_hex)};
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fehlende historische mc_rx.region-Werte mit der aktuellen "
            "MeshCore-Regionenliste nachtragen."
        )
    )
    parser.add_argument(
        "--questdb-url",
        default=DEFAULT_QUESTDB_URL,
        help=f"QuestDB HTTP URL. Default: {DEFAULT_QUESTDB_URL}",
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="MeshCore-PacketTap Projektverzeichnis.",
    )
    parser.add_argument("--from", dest="date_from")
    parser.add_argument("--to", dest="date_to")
    parser.add_argument(
        "--batch-days",
        type=int,
        default=1,
        help="Zeitfenster pro Batch in Tagen. Default: 1",
    )
    parser.add_argument(
        "--show",
        type=int,
        default=30,
        help="Maximale Anzahl Beispieltreffer. Default: 30",
    )
    parser.add_argument(
        "--min-distinct-payloads",
        type=int,
        default=2,
        help=(
            "Mindestzahl unterschiedlicher packet_payload_hex pro Region, "
            "bevor diese Region geschrieben wird. Default: 2"
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Gefundene Regionen tatsächlich in QuestDB schreiben.",
    )
    args = parser.parse_args()

    if args.batch_days < 1:
        parser.error("--batch-days muss >= 1 sein.")
    if args.show < 0:
        parser.error("--show muss >= 0 sein.")
    if args.min_distinct_payloads < 1:
        parser.error("--min-distinct-payloads muss >= 1 sein.")

    project = args.project_dir.resolve()
    if str(project) not in sys.path:
        sys.path.insert(0, str(project))

    import meshcore_decoder as decoder

    # regions.json sicher neu laden, falls sie während eines länger laufenden
    # PacketTap-Prozesses bereits im Decoder-Cache gelegen haben sollte.
    region_names = decoder.get_region_names(reload=True)
    if not region_names:
        raise RuntimeError(
            f"Keine Regionen geladen. Prüfe {project / 'regions.json'}."
        )

    date_from = normalize_date(args.date_from)
    date_to = normalize_date(args.date_to, end=True)

    print("MeshCore Historical Region Backfill")
    print("=" * 78)
    print(f"Tool-Version        : {APP_VERSION}")
    print(f"Decoder-Version     : {getattr(decoder, 'APP_VERSION', 'unbekannt')}")
    print(f"Bekannte Regionen   : {len(region_names)}")
    print(f"QuestDB             : {args.questdb_url}")
    print(f"Modus               : {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"Batch-Größe         : {args.batch_days} Tag(e)")
    print(f"Min. versch. Payloads: {args.min_distinct_payloads}")
    print(f"Von                 : {iso_z(date_from) if date_from else 'unbegrenzt'}")
    print(f"Bis                 : {iso_z(date_to) if date_to else 'unbegrenzt'}")
    print()

    inv = inventory(args.questdb_url, date_from, date_to)
    packet_count = int(inv.get("pakete") or 0)

    print("Fehlender Regionsbestand")
    print("-" * 78)
    print(f"Pakete              : {packet_count}")
    print(f"Erstes              : {inv.get('erstes') or '-'}")
    print(f"Letztes             : {inv.get('letztes') or '-'}")
    print()

    if packet_count == 0:
        print("Keine fehlenden Region-Zuordnungen gefunden.")
        return 0

    first_ts = parse_questdb_ts(inv["erstes"])
    last_ts = parse_questdb_ts(inv["letztes"])

    cursor = date_from or first_ts
    end_limit = date_to or (last_ts + timedelta(microseconds=1))
    batch_delta = timedelta(days=args.batch_days)

    stats: Counter[str] = Counter()
    by_region: Counter[str] = Counter()
    by_payload_type: Counter[str] = Counter()
    examples: list[str] = []
    errors: list[str] = []

    # Region -> unterschiedliche Payloads. Empfangsduplikate derselben Payload
    # zählen bewusst nur einmal zur Vertrauensschwelle.
    distinct_payloads_by_region: dict[str, set[str]] = {}

    # Gefundene Update-Gruppen werden zunächst gesammelt. Erst nach dem Scan
    # entscheidet die Mindestzahl unterschiedlicher Payloads pro Region darüber,
    # ob sie im APPLY-Lauf tatsächlich geschrieben werden.
    pending_updates: list[dict[str, Any]] = []

    batch_no = 0

    while cursor < end_limit:
        batch_no += 1
        batch_end = min(cursor + batch_delta, end_limit)

        print(
            f"[Batch {batch_no}] {iso_z(cursor)} .. {iso_z(batch_end)}",
            flush=True,
        )

        try:
            groups = load_groups(args.questdb_url, cursor, batch_end)
        except Exception as exc:
            stats["fehler"] += 1
            errors.append(
                f"{iso_z(cursor)}..{iso_z(batch_end)}: Query: {exc}"
            )
            cursor = batch_end
            continue

        batch_packets = 0
        batch_resolved = 0
        batch_groups_resolved = 0

        for row in groups:
            count = int(row.get("pakete") or 0)
            batch_packets += count
            stats["geprüft"] += count

            payload_type = str(row.get("payload_type") or "").strip()
            region_code = str(row.get("region_code") or "").strip().lower()
            packet_payload_hex = str(
                row.get("packet_payload_hex") or ""
            ).strip().lower()

            if not payload_type or not region_code or not packet_payload_hex:
                stats["weiterhin_unbekannt"] += count
                continue

            try:
                region_name = decoder.resolve_region(
                    region_code,
                    payload_type,
                    packet_payload_hex,
                )
            except Exception as exc:
                stats["fehler"] += count
                errors.append(
                    f"{iso_z(cursor)} hash={region_code} "
                    f"type={payload_type}: {exc}"
                )
                continue

            if not region_name:
                stats["weiterhin_unbekannt"] += count
                continue

            stats["neu_auflösbar_roh"] += count
            by_region[region_name] += count
            by_payload_type[payload_type] += count
            batch_resolved += count
            batch_groups_resolved += 1

            distinct_payloads_by_region.setdefault(region_name, set()).add(
                packet_payload_hex
            )

            pending_updates.append({
                "batch_from": cursor,
                "batch_to": batch_end,
                "payload_type": payload_type,
                "region_code": region_code,
                "packet_payload_hex": packet_payload_hex,
                "region_name": region_name,
                "count": count,
                "zuerst": row.get("zuerst"),
            })

            if len(examples) < args.show:
                examples.append(
                    f"{row.get('zuerst')}  n={count}  "
                    f"type={payload_type}  code={region_code}  "
                    f"-> {region_name}"
                )

        print(
            f"  Pakete: {batch_packets}, "
            f"neu auflösbar: {batch_resolved}, "
            f"Gruppen: {batch_groups_resolved}",
            flush=True,
        )

        cursor = batch_end

    qualified_regions = {
        region_name
        for region_name, payloads in distinct_payloads_by_region.items()
        if len(payloads) >= args.min_distinct_payloads
    }

    for item in pending_updates:
        if item["region_name"] in qualified_regions:
            stats["neu_auflösbar"] += int(item["count"])
        else:
            stats["verworfen_zu_wenig_payloads"] += int(item["count"])

    if args.apply:
        for item in pending_updates:
            if item["region_name"] not in qualified_regions:
                continue
            try:
                qdb(
                    args.questdb_url,
                    build_update_sql(
                        batch_from=item["batch_from"],
                        batch_to=item["batch_to"],
                        payload_type=item["payload_type"],
                        region_code=item["region_code"],
                        packet_payload_hex=item["packet_payload_hex"],
                        region_name=item["region_name"],
                    ),
                    timeout=120.0,
                )
                stats["geschrieben"] += int(item["count"])
            except Exception as exc:
                stats["fehler"] += int(item["count"])
                errors.append(
                    f"{iso_z(item['batch_from'])} {item['region_name']} "
                    f"type={item['payload_type']} code={item['region_code']}: "
                    f"UPDATE: {exc}"
                )

    print()
    print("Auswertung")
    print("-" * 78)
    print(f"Geprüft             : {stats['geprüft']}")
    print(f"Roh auflösbar       : {stats['neu_auflösbar_roh']}")
    print(f"Qualifiziert        : {stats['neu_auflösbar']}")
    print(f"Verworfen (<{args.min_distinct_payloads} Payloads): "
          f"{stats['verworfen_zu_wenig_payloads']}")
    print(f"Weiterhin unbekannt : {stats['weiterhin_unbekannt']}")
    if args.apply:
        print(f"Geschrieben          : {stats['geschrieben']}")
    print(f"Fehler               : {stats['fehler']}")

    qualified_region_counts = [
        (region_name, count)
        for region_name, count in by_region.items()
        if region_name in qualified_regions
    ]
    qualified_region_counts.sort(key=lambda item: (-item[1], item[0]))

    if qualified_region_counts:
        print()
        print("Qualifiziert nach Region")
        print("-" * 78)
        print(f"{'Region':<40} {'Pakete':>10} {'Payloads':>10}")
        for region_name, count in qualified_region_counts:
            distinct_count = len(distinct_payloads_by_region[region_name])
            print(f"{region_name:<40} {count:>10} {distinct_count:>10}")

    if by_payload_type:
        print()
        print("Neu auflösbar nach Payload-Typ")
        print("-" * 78)
        for payload_type, count in by_payload_type.most_common():
            print(f"{payload_type:<40} {count:>10}")

    qualified_examples = []
    for item in pending_updates:
        if item["region_name"] not in qualified_regions:
            continue
        qualified_examples.append(
            f"{item['zuerst']}  n={item['count']}  "
            f"type={item['payload_type']}  code={item['region_code']}  "
            f"-> {item['region_name']}"
        )
        if len(qualified_examples) >= args.show:
            break

    if qualified_examples:
        print()
        print("Beispiele")
        print("-" * 78)
        for example in qualified_examples:
            print(example)

    if errors:
        print()
        print("Fehlerbeispiele")
        print("-" * 78)
        for error in errors[:20]:
            print(error)
        if len(errors) > 20:
            print(f"... und {len(errors) - 20} weitere")

    print()
    print("Fertig")
    print("-" * 78)
    if args.apply:
        print(f"Neu geschrieben     : {stats['geschrieben']}")
    else:
        print("DRY-RUN: QuestDB wurde nicht verändert.")
        print(f"Qualifiziert        : {stats['neu_auflösbar']}")
    print(f"Fehler              : {stats['fehler']}")

    return 1 if stats["fehler"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
