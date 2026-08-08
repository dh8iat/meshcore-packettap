#!/usr/bin/env python3
"""Import PacketTap JSON-lines captures into the existing QuestDB mc_rx table."""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import time
from pathlib import Path
from typing import Any, AsyncIterator

from mc_db import QuestDBWriter, configure_writer
from mc_writer import write_decoded_packet, write_mc_companion_info
from meshcore_decoder import decode_mc_rx_record


DEFAULT_CAPTURE_FILE = Path("packettap_capture.log")
DEFAULT_QUESTDB_HOST = "192.168.1.2"
DEFAULT_QUESTDB_PORT = 9000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Decode PacketTap capture records and write them to "
            "the existing QuestDB mc_rx table."
        )
    )
    parser.add_argument(
        "capture_file",
        nargs="?",
        type=Path,
        default=DEFAULT_CAPTURE_FILE,
        help=(
            "PacketTap JSON-lines capture "
            f"(default: {DEFAULT_CAPTURE_FILE})"
        ),
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
        "--follow",
        action="store_true",
        help="Wait for new capture lines continuously.",
    )
    parser.add_argument(
        "--include-bad-crc",
        action="store_true",
        help="Import frames even when PacketTap CRC is invalid.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Decode and print records without writing QuestDB.",
    )
    parser.add_argument(
        "--repeater",
        default=None,
        help=(
            "Optional fixed repeater label. When omitted, the last "
            "path hash is used, matching the decoder fallback."
        ),
    )
    parser.add_argument(
        "--start-at-end",
        action="store_true",
        help=(
            "With --follow, ignore existing lines and process only "
            "new records."
        ),
    )
    return parser.parse_args()


async def iter_json_lines(
    path: Path,
    *,
    follow: bool,
    start_at_end: bool,
) -> AsyncIterator[tuple[int, str]]:
    with path.open("r", encoding="utf-8") as handle:
        if follow and start_at_end:
            handle.seek(0, 2)

        line_number = 0

        while True:
            line = handle.readline()
            if line:
                line_number += 1
                yield line_number, line
                continue

            if not follow:
                break

            await asyncio.sleep(0.25)


def parse_peer(peer: Any) -> tuple[str | None, int | None]:
    if peer is None:
        return None, None

    value = peer
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None, None
        try:
            value = ast.literal_eval(text)
        except (ValueError, SyntaxError):
            return text, None

    if isinstance(value, (tuple, list)) and len(value) >= 2:
        ip = str(value[0]).strip() or None
        try:
            port = int(value[1])
        except (TypeError, ValueError):
            port = None
        return ip, port

    return str(value).strip() or None, None


def build_metadata(
    capture_record: dict[str, Any],
    repeater: str | None,
) -> dict[str, Any]:
    """Build metadata only from the capture record and CLI overrides.

    Receiver identity is supplied by receiver.py from the PKTH HELLO frame.
    No local config file is used.
    """
    metadata = dict(capture_record)

    if repeater:
        metadata["repeater"] = repeater

    receiver_ip, receiver_port = parse_peer(capture_record.get("peer"))
    metadata["receiver_ip"] = receiver_ip
    metadata["receiver_port"] = receiver_port
    metadata["receiver_time_ns"] = capture_record.get("received_unix_ns")

    return metadata

def print_record(
    sequence: Any,
    decoded: dict[str, Any],
    *,
    dry_run: bool,
) -> None:
    prefix = "[DRY] " if dry_run else ""
    print(
        f"{prefix}[{sequence}] "
        f"type={decoded['payload_type']} "
        f"sender={decoded['sender_node']} "
        f"prev_hop={decoded['prev_hop']} "
        f"repeater={decoded['repeater']} "
        f"hops={decoded['hop_count']} "
        f"region={decoded['region_name']} "
        f"channel={decoded['channel_name']} "
        f"rssi={decoded.get('rssi_dbm')}dBm "
        f"snr={decoded.get('snr_db')}dB "
        f"crc={decoded.get('crc_ok')} "
        f"receiver={decoded.get('receiver_id')} "
        f"ip={decoded.get('receiver_ip')}"
    )

    if decoded["payload_type"] == "GRP_TXT":
        print(
            f"       sender={decoded['grp_txt_sender_name']} "
            f"msg={decoded['grp_txt_body']}"
        )


async def run_import(args: argparse.Namespace) -> int:
    if not args.capture_file.is_file():
        raise SystemExit(
            f"Capture file not found: {args.capture_file}"
        )

    writer: QuestDBWriter | None = None
    writer_task: asyncio.Task[None] | None = None

    if not args.dry_run:
        writer = QuestDBWriter(
            args.questdb_host,
            args.questdb_port,
            enabled=True,
        )
        configure_writer(writer)
        writer_task = asyncio.create_task(writer.run())

    imported = 0
    skipped = 0
    invalid = 0
    seen_receiver_ids: set[str] = set()

    try:
        async for line_number, line in iter_json_lines(
            args.capture_file,
            follow=args.follow,
            start_at_end=args.start_at_end,
        ):
            text = line.strip()
            if not text:
                continue

            try:
                capture_record = json.loads(text)
            except json.JSONDecodeError as exc:
                invalid += 1
                print(
                    f"[WARNUNG] Ungültiges JSON in Zeile "
                    f"{line_number}: {exc}"
                )
                continue

            if not isinstance(capture_record, dict):
                invalid += 1
                continue

            if (
                not args.include_bad_crc
                and not bool(capture_record.get("crc_ok", False))
            ):
                skipped += 1
                continue

            payload_hex = str(
                capture_record.get("payload_hex", "")
            ).strip()
            if not payload_hex:
                skipped += 1
                continue

            metadata = build_metadata(
                capture_record,
                args.repeater,
            )

            receiver_id = str(metadata.get("receiver_id") or "").strip()
            if receiver_id and receiver_id not in seen_receiver_ids:
                seen_receiver_ids.add(receiver_id)
                print(
                    "[NODE] "
                    f"name={metadata.get('receiver_name')} "
                    f"model={metadata.get('receiver_type')} "
                    f"firmware={metadata.get('receiver_version')} "
                    f"role={metadata.get('node_role')} "
                    f"public_key={receiver_id}"
                )

                if not args.dry_run:
                    received_unix_ns = metadata.get("received_unix_ns")
                    recv_time = (
                        float(received_unix_ns) / 1_000_000_000
                        if received_unix_ns is not None
                        else time.time()
                    )
                    await write_mc_companion_info(
                        recv_time=recv_time,
                        model=metadata.get("receiver_type"),
                        firmware=metadata.get("receiver_version"),
                        build=metadata.get("receiver_build"),
                        noise_floor=None,
                        node_name=metadata.get("receiver_name"),
                        public_key=receiver_id,
                        tcp_connected=1,
                        node_role=metadata.get("node_role"),
                    )

            decoded = decode_mc_rx_record(
                payload_hex,
                metadata,
            )
            if decoded is None:
                skipped += 1
                print(
                    "[WARNUNG] Paket konnte nicht dekodiert werden: "
                    f"Zeile {line_number}"
                )
                continue

            print_record(
                capture_record.get("sequence", line_number),
                decoded,
                dry_run=args.dry_run,
            )

            if not args.dry_run:
                await write_decoded_packet(decoded)

            imported += 1

    except KeyboardInterrupt:
        print("\nImport beendet.")
    finally:
        if writer is not None:
            await writer.stop()

        if writer_task is not None:
            try:
                await asyncio.wait_for(writer_task, timeout=10)
            except asyncio.TimeoutError:
                writer_task.cancel()
                try:
                    await writer_task
                except asyncio.CancelledError:
                    pass

        configure_writer(None)

    print(
        f"\nFertig: {imported} Datensätze verarbeitet, "
        f"{skipped} übersprungen, {invalid} ungültig."
    )
    return 0


def main() -> None:
    args = parse_args()
    raise SystemExit(asyncio.run(run_import(args)))


if __name__ == "__main__":
    main()