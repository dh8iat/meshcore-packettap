#!/usr/bin/env python3
"""PacketTap capture log analyzer.

Reads the JSON-lines log written by receiver.py and prints valid PacketTap
payloads. It can process an existing capture or follow the file live.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Iterator

from meshcore_decoder import decode_mc_rx_record


DEFAULT_LOG_FILE = Path("packettap_capture.log")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze PacketTap JSON-lines capture logs"
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help=f"Capture log file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Wait for and process new log entries continuously",
    )
    parser.add_argument(
        "--include-bad-crc",
        action="store_true",
        help="Also display frames whose CRC check failed",
    )
    parser.add_argument(
        "--payload-only",
        action="store_true",
        help="Print only payload_hex, one payload per line",
    )
    return parser.parse_args()


def follow_lines(path: Path, follow: bool) -> Iterator[tuple[int, str]]:
    """Yield line number and line content, optionally waiting for new data."""
    with path.open("r", encoding="utf-8") as handle:
        line_number = 0

        while True:
            line = handle.readline()

            if line:
                line_number += 1
                yield line_number, line
                continue

            if not follow:
                break

            time.sleep(0.25)


def require_int(record: dict[str, Any], key: str, default: int = 0) -> int:
    value = record.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def require_float(
    record: dict[str, Any],
    key: str,
    default: float = 0.0,
) -> float:
    value = record.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def analyze_record(
    record: dict[str, Any],
    *,
    include_bad_crc: bool,
    payload_only: bool,
) -> bool:
    crc_ok = bool(record.get("crc_ok", False))
    if not crc_ok and not include_bad_crc:
        return False

    payload_hex = str(record.get("payload_hex", "")).strip().lower()
    if not payload_hex:
        return False

    if payload_only:
        print(payload_hex, flush=True)
        return True

    decoded = decode_mc_rx_record(payload_hex, record)
    if decoded is None:
        print(
            "[WARNUNG] MeshCore-Paket konnte nicht dekodiert werden: "
            f"{payload_hex}",
            flush=True,
        )
        return False

    sequence = require_int(record, "sequence")
    received_utc = str(record.get("received_utc", "?"))
    payload_length = require_int(
        record,
        "payload_length",
        len(payload_hex) // 2,
    )
    rssi_dbm = require_int(record, "rssi_dbm")
    snr_db = require_float(record, "snr_db")
    crc_text = "OK" if crc_ok else "FEHLER"

    print(
        f"[{sequence:05d}] {received_utc} "
        f"len={payload_length} rssi={rssi_dbm} dBm "
        f"snr={snr_db:.1f} dB crc={crc_text}"
    )
    print(
        f"          payload_type={decoded['payload_type']} "
        f"route_type={decoded['payload_route_type']}"
    )
    print(
        f"          sender_node={decoded['sender_node']} "
        f"prev_hop={decoded['prev_hop']} "
        f"repeater={decoded['repeater']}"
    )
    print(
        f"          hop_count={decoded['hop_count']} "
        f"path_hash_size={decoded['path_hash_size']}"
    )
    print(f"          nodes={decoded['nodes']}")
    print(
        f"          frame_bytes={decoded['frame_bytes']} "
        f"frame_bits={decoded['frame_bits']} "
        f"airtime_ms={decoded['airtime_ms']}"
    )
    print(
        "          packet_payload_sha256="
        f"{decoded['packet_payload_sha256']}"
    )

    if decoded["payload_type"] == "TEXT_MSG":
        print(
            f"          txt_msg_dest_hash={decoded['txt_msg_dest_hash']} "
            f"txt_msg_src_hash={decoded['txt_msg_src_hash']}"
        )

    print(
        "          packet_payload_hex="
        f"{decoded['packet_payload_hex']}"
    )
    print(f"          payload_hex={decoded['payload_hex']}", flush=True)

    return True


def main() -> None:
    args = parse_args()

    if not args.log_file.exists():
        raise SystemExit(f"Logdatei nicht gefunden: {args.log_file}")

    print(f"Analysiere: {args.log_file}")
    if args.follow:
        print(
            "Live-Modus aktiv. "
            "Beenden mit q im Receiver oder Strg+Pause hier.\n"
        )
    else:
        print()

    valid_records = 0
    invalid_lines = 0
    skipped_records = 0

    try:
        for line_number, line in follow_lines(args.log_file, args.follow):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                invalid_lines += 1
                print(
                    f"[WARNUNG] Ungültiges JSON in Zeile "
                    f"{line_number}: {exc}",
                    flush=True,
                )
                continue

            if not isinstance(record, dict):
                invalid_lines += 1
                print(
                    f"[WARNUNG] Zeile {line_number} enthält "
                    "kein JSON-Objekt.",
                    flush=True,
                )
                continue

            if analyze_record(
                record,
                include_bad_crc=args.include_bad_crc,
                payload_only=args.payload_only,
            ):
                valid_records += 1
            else:
                skipped_records += 1

    except KeyboardInterrupt:
        print("\nAnalyse beendet.")

    if not args.follow:
        print(
            f"\nFertig: {valid_records} Frames angezeigt, "
            f"{skipped_records} übersprungen, "
            f"{invalid_lines} ungültige Zeilen."
        )


if __name__ == "__main__":
    main()