#!/usr/bin/env python3
"""Backfill passive CONTROL / DISCOVER_RESP observations from PacketTap capture.

This utility intentionally writes only to mc_contact_observations.

It does NOT:
  * write or modify mc_rx
  * write or modify mc_contacts
  * touch state/importer.state
  * generate any MeshCore radio traffic

Existing DISCOVER_RESP observations are detected by packet_payload_sha256 and
skipped, so the script can be run repeatedly.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from mc_db import QuestDBWriter, configure_writer
from mc_writer import write_mc_contact_observation
from meshcore_decoder import decode_mc_rx_record


DEFAULT_CAPTURE_FILE = Path("packettap_capture.log")
DEFAULT_QUESTDB_HOST = "192.168.1.2"
DEFAULT_QUESTDB_PORT = 9000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Backfill CONTROL/DISCOVER_RESP packets from a PacketTap "
            "capture into mc_contact_observations."
        )
    )
    parser.add_argument(
        "capture_file",
        nargs="?",
        type=Path,
        default=DEFAULT_CAPTURE_FILE,
        help=f"JSON-lines capture file (default: {DEFAULT_CAPTURE_FILE})",
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
        "--dry-run",
        action="store_true",
        help="Decode and count candidates, but do not write QuestDB.",
    )
    parser.add_argument(
        "--show",
        type=int,
        default=10,
        help="Print the first N decoded DISCOVER_RESP candidates (default: 10).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Stop after N new observations; 0 means unlimited.",
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

    with urllib.request.urlopen(url, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def load_existing_discover_hashes(
    *,
    host: str,
    port: int,
) -> set[str]:
    """Load hashes already stored as discover_resp observations."""
    sql = """
        SELECT packet_payload_sha256
        FROM mc_contact_observations
        WHERE source_type = 'discover_resp'
          AND packet_payload_sha256 IS NOT NULL
    """

    result = questdb_query(sql, host=host, port=port)
    dataset = result.get("dataset") or []

    hashes: set[str] = set()
    for row in dataset:
        if not row:
            continue
        value = row[0]
        if value:
            hashes.add(str(value))

    return hashes


def payload_sha256(decoded: dict[str, Any]) -> str | None:
    value = decoded.get("packet_payload_sha256")
    if value:
        return str(value)

    packet_payload_hex = decoded.get("packet_payload_hex")
    if not packet_payload_hex:
        return None

    try:
        raw = bytes.fromhex(str(packet_payload_hex))
    except ValueError:
        return None

    return hashlib.sha256(raw).hexdigest()


def is_discover_resp(decoded: dict[str, Any] | None) -> bool:
    return bool(
        decoded
        and decoded.get("payload_type") == "CONTROL"
        and decoded.get("control_subtype_name") == "DISCOVER_RESP"
        and decoded.get("control_public_key")
    )


async def run(args: argparse.Namespace) -> int:
    if not args.capture_file.is_file():
        print(f"[FEHLER] Capture-Datei nicht gefunden: {args.capture_file}")
        return 2

    existing_hashes: set[str] = set()

    if not args.dry_run:
        try:
            existing_hashes = await asyncio.to_thread(
                load_existing_discover_hashes,
                host=args.questdb_host,
                port=args.questdb_port,
            )
        except Exception as exc:
            print(
                "[FEHLER] Vorhandene DISCOVER_RESP-Hashes konnten nicht "
                f"aus QuestDB gelesen werden: {exc}"
            )
            print(
                "Abbruch, damit kein unkontrollierter Doppelimport entsteht."
            )
            return 3

        print(
            "[BACKFILL] Bereits vorhanden: "
            f"{len(existing_hashes)} DISCOVER_RESP-Hash(es)"
        )

    writer: QuestDBWriter | None = None
    writer_task: asyncio.Task[None] | None = None

    if not args.dry_run:
        writer = QuestDBWriter(
            host=args.questdb_host,
            port=args.questdb_port,
        )
        configure_writer(writer)
        writer_task = asyncio.create_task(writer.run())

    lines_total = 0
    invalid_json = 0
    decoded_control = 0
    discover_total = 0
    duplicates_db = 0
    duplicates_capture = 0
    missing_hash = 0
    written = 0
    shown = 0

    seen_this_run: set[str] = set()

    try:
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

                if decoded.get("payload_type") == "CONTROL":
                    decoded_control += 1

                if not is_discover_resp(decoded):
                    continue

                discover_total += 1
                packet_hash = payload_sha256(decoded)

                if not packet_hash:
                    missing_hash += 1
                    continue

                if packet_hash in seen_this_run:
                    duplicates_capture += 1
                    continue
                seen_this_run.add(packet_hash)

                if packet_hash in existing_hashes:
                    duplicates_db += 1
                    continue

                if shown < max(0, args.show):
                    shown += 1
                    print(
                        f"[DISCOVER_RESP {shown}] line={line_number} "
                        f"role={decoded.get('control_node_role')} "
                        f"hops={decoded.get('control_hop_count')} "
                        f"rssi={decoded.get('rssi_dbm')} "
                        f"snr={decoded.get('snr_db')} "
                        f"discover_snr={decoded.get('control_discover_snr')} "
                        f"key_bytes={decoded.get('control_public_key_bytes')}"
                    )
                    print(
                        "    public_key="
                        f"{decoded.get('control_public_key')}"
                    )
                    print(
                        "    tag="
                        f"{decoded.get('control_discover_tag')} "
                        f"hash={packet_hash}"
                    )

                if not args.dry_run:
                    await write_mc_contact_observation(
                        recv_time=decoded.get("recv_time"),
                        public_key=decoded.get("control_public_key"),
                        receiver_id=decoded.get("receiver_id"),
                        receiver_name=decoded.get("receiver_name"),
                        node_role=decoded.get("control_node_role"),
                        hop_count=decoded.get("control_hop_count"),
                        rssi_dbm=decoded.get("rssi_dbm"),
                        snr_db=decoded.get("snr_db"),
                        region_name=decoded.get("region_name"),
                        packet_payload_sha256=packet_hash,
                        source_type="discover_resp",
                        discover_snr=decoded.get("control_discover_snr"),
                        discover_tag=decoded.get("control_discover_tag"),
                        public_key_bytes=decoded.get(
                            "control_public_key_bytes"
                        ),
                    )

                written += 1

                if args.limit > 0 and written >= args.limit:
                    break

        if writer is not None:
            print("[BACKFILL] Warte auf bestätigten QuestDB-Flush ...")
            await writer.flush()

    finally:
        if writer is not None:
            await writer.stop()
            configure_writer(None)

        if writer_task is not None:
            await writer_task

    print()
    print("=== Backfill Zusammenfassung ===")
    print(f"Capture-Zeilen             : {lines_total}")
    print(f"Ungültige JSON-Zeilen      : {invalid_json}")
    print(f"CONTROL-Pakete             : {decoded_control}")
    print(f"DISCOVER_RESP erkannt      : {discover_total}")
    print(f"Duplikate im Capture       : {duplicates_capture}")
    print(f"Bereits in QuestDB         : {duplicates_db}")
    print(f"Ohne Paket-Hash            : {missing_hash}")

    if args.dry_run:
        print(f"Würden neu geschrieben     : {written}")
        print("QuestDB wurde nicht verändert.")
    else:
        print(f"Neu geschrieben            : {written}")

    return 0


def main() -> None:
    args = parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
