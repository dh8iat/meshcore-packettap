#!/usr/bin/env python3
"""Backfill mc_rx.repeater for historical rt=2 packets.

The script re-decodes PacketTap capture records with the current
meshcore_decoder.py logic and updates only historical mc_rx rows where:

  * payload_route_type = '2'
  * repeater IS NULL
  * packet_payload_sha256 matches a packet for which the current decoder
    can determine an unambiguous repeater origin

Currently this covers:
  * ADVERT packets from nodes with role=repeater
  * CONTROL / DISCOVER_RESP packets from nodes with role=repeater

The script does not insert new mc_rx rows and does not touch the importer
checkpoint. By default it is DRY-RUN only. Use --apply to execute UPDATEs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from meshcore_decoder import decode_mc_rx_record


DEFAULT_CAPTURE_FILE = Path("packettap_capture.log")
DEFAULT_QUESTDB_HOST = "192.168.1.2"
DEFAULT_QUESTDB_PORT = 9000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Backfill mc_rx.repeater for historical route_type=2 "
            "ADVERT and DISCOVER_RESP packets."
        )
    )
    parser.add_argument(
        "capture_file",
        nargs="?",
        type=Path,
        default=DEFAULT_CAPTURE_FILE,
        help=f"PacketTap JSONL capture (default: {DEFAULT_CAPTURE_FILE})",
    )
    parser.add_argument(
        "--questdb-host",
        default=DEFAULT_QUESTDB_HOST,
    )
    parser.add_argument(
        "--questdb-port",
        type=int,
        default=DEFAULT_QUESTDB_PORT,
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually execute QuestDB UPDATE statements.",
    )
    parser.add_argument(
        "--show",
        type=int,
        default=10,
        help="Show the first N candidate mappings (default: 10).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process at most N unique packet hashes; 0 means unlimited.",
    )
    return parser.parse_args()


def questdb_query(
    sql: str,
    *,
    host: str,
    port: int,
) -> dict[str, Any]:
    params = urllib.parse.urlencode({"query": sql})
    url = f"http://{host}:{port}/exec?{params}"

    with urllib.request.urlopen(url, timeout=30) as response:
        body = response.read().decode("utf-8")

    if not body:
        return {}

    return json.loads(body)


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def candidate_from_decoded(
    decoded: dict[str, Any] | None,
) -> tuple[str, str, str] | None:
    """Return (packet_hash, repeater, reason) for an eligible packet."""
    if not decoded:
        return None

    if str(decoded.get("payload_route_type")) != "2":
        return None

    repeater = str(decoded.get("repeater") or "").strip()
    packet_hash = str(
        decoded.get("packet_payload_sha256") or ""
    ).strip()

    if not repeater or not packet_hash:
        return None

    payload_type = decoded.get("payload_type")

    if (
        payload_type == "ADVERT"
        and decoded.get("advert_node_role") == "repeater"
        and decoded.get("advert_public_key")
    ):
        return packet_hash, repeater, "ADVERT"

    if (
        payload_type == "CONTROL"
        and decoded.get("control_subtype_name") == "DISCOVER_RESP"
        and decoded.get("control_node_role") == "repeater"
        and decoded.get("control_public_key")
    ):
        return packet_hash, repeater, "DISCOVER_RESP"

    return None


async def run(args: argparse.Namespace) -> int:
    if not args.capture_file.is_file():
        print(f"[FEHLER] Capture-Datei nicht gefunden: {args.capture_file}")
        return 2

    mappings: dict[str, tuple[str, str]] = {}
    conflicts: dict[str, set[str]] = {}

    lines_total = 0
    invalid_json = 0
    decoded_total = 0
    candidates_total = 0
    duplicate_candidates = 0

    with args.capture_file.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            lines_total += 1
            text = line.strip()
            if not text:
                continue

            try:
                capture = json.loads(text)
            except json.JSONDecodeError:
                invalid_json += 1
                continue

            if not isinstance(capture, dict):
                continue

            payload_hex = str(capture.get("payload_hex") or "").strip()
            if not payload_hex:
                continue

            decoded = decode_mc_rx_record(
                payload_hex,
                dict(capture),
            )
            if not decoded:
                continue

            decoded_total += 1
            candidate = candidate_from_decoded(decoded)
            if candidate is None:
                continue

            candidates_total += 1
            packet_hash, repeater, reason = candidate

            existing = mappings.get(packet_hash)
            if existing is None:
                mappings[packet_hash] = (repeater, reason)
            else:
                duplicate_candidates += 1
                if existing[0] != repeater:
                    conflicts.setdefault(packet_hash, set()).update(
                        {existing[0], repeater}
                    )

            if args.limit > 0 and len(mappings) >= args.limit:
                break

    if conflicts:
        print("[FEHLER] Konflikte gefunden. Es wird nichts geändert.")
        for packet_hash, repeaters in list(conflicts.items())[:20]:
            print(
                f"  {packet_hash}: "
                + ", ".join(sorted(repeaters))
            )
        return 3

    shown = 0
    for packet_hash, (repeater, reason) in mappings.items():
        if shown >= max(0, args.show):
            break
        shown += 1
        print(
            f"[KANDIDAT {shown}] {reason} "
            f"hash={packet_hash} "
            f"repeater={repeater}"
        )

    print()
    print("=== Analyse ===")
    print(f"Capture-Zeilen             : {lines_total}")
    print(f"Ungültige JSON-Zeilen      : {invalid_json}")
    print(f"Dekodierte Pakete          : {decoded_total}")
    print(f"Treffer gesamt             : {candidates_total}")
    print(f"Duplikate im Capture       : {duplicate_candidates}")
    print(f"Eindeutige Packet-Hashes   : {len(mappings)}")

    if not mappings:
        print("Keine Backfill-Kandidaten gefunden.")
        return 0

    if not args.apply:
        print()
        print("DRY-RUN: QuestDB wurde nicht verändert.")
        print(
            "Zum Anwenden denselben Befehl mit --apply starten."
        )
        return 0

    updated_hashes = 0
    update_errors = 0

    print()
    print("[BACKFILL] Führe QuestDB UPDATEs aus ...")

    for index, (packet_hash, (repeater, reason)) in enumerate(
        mappings.items(),
        start=1,
    ):
        sql = (
            "UPDATE mc_rx "
            f"SET repeater = {sql_literal(repeater)} "
            "WHERE payload_route_type = '2' "
            "AND repeater IS NULL "
            f"AND packet_payload_sha256 = {sql_literal(packet_hash)}"
        )

        try:
            await asyncio.to_thread(
                questdb_query,
                sql,
                host=args.questdb_host,
                port=args.questdb_port,
            )
        except Exception as exc:
            update_errors += 1
            print(
                f"[FEHLER] UPDATE {index}/{len(mappings)} "
                f"({reason}, {packet_hash[:12]}...): {exc}"
            )
            continue

        updated_hashes += 1

        if index % 50 == 0 or index == len(mappings):
            print(
                f"[BACKFILL] {index}/{len(mappings)} "
                "Packet-Hashes verarbeitet"
            )

    print()
    print("=== Backfill Ergebnis ===")
    print(f"UPDATEs erfolgreich        : {updated_hashes}")
    print(f"UPDATE-Fehler              : {update_errors}")

    # Verification counts.
    try:
        remaining = await asyncio.to_thread(
            questdb_query,
            """
            SELECT count() AS remaining
            FROM mc_rx
            WHERE payload_route_type = '2'
              AND repeater IS NULL
              AND payload_type IN ('ADVERT', 'CONTROL')
            """,
            host=args.questdb_host,
            port=args.questdb_port,
        )
        dataset = remaining.get("dataset") or []
        if dataset and dataset[0]:
            print(
                "Verbleibende rt=2 ADVERT/CONTROL mit repeater=NULL: "
                f"{dataset[0][0]}"
            )
    except Exception as exc:
        print(f"[WARNUNG] Abschlussprüfung fehlgeschlagen: {exc}")

    return 0 if update_errors == 0 else 4


def main() -> None:
    args = parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
