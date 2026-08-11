#!/usr/bin/env python3
"""Import PacketTap JSON-lines captures into the existing QuestDB mc_rx table."""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from mc_db import QuestDBWriter, configure_writer
from mc_writer import (
    write_decoded_packet,
    write_mc_companion_info,
    write_mc_contact,
    write_mc_contact_observation,
)
from meshcore_decoder import decode_mc_rx_record


DEFAULT_CAPTURE_FILE = Path("packettap_capture.log")
DEFAULT_QUESTDB_HOST = "192.168.1.2"
DEFAULT_QUESTDB_PORT = 9000
DEFAULT_CHECKPOINT_FILE = Path("state/importer.state")
DEFAULT_CHECKPOINT_ROWS = 100
DEFAULT_CHECKPOINT_SECONDS = 5.0


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
    parser.add_argument(
        "--checkpoint-file",
        type=Path,
        default=DEFAULT_CHECKPOINT_FILE,
        help=(
            "Checkpoint state file used with --follow "
            f"(default: {DEFAULT_CHECKPOINT_FILE})"
        ),
    )
    parser.add_argument(
        "--checkpoint-rows",
        type=int,
        default=DEFAULT_CHECKPOINT_ROWS,
        help=(
            "Advance checkpoint after this many consumed records "
            f"(default: {DEFAULT_CHECKPOINT_ROWS})."
        ),
    )
    parser.add_argument(
        "--checkpoint-seconds",
        type=float,
        default=DEFAULT_CHECKPOINT_SECONDS,
        help=(
            "Also advance a pending checkpoint after this many seconds "
            f"(default: {DEFAULT_CHECKPOINT_SECONDS})."
        ),
    )
    parser.add_argument(
        "--no-checkpoint",
        action="store_true",
        help="Disable persistent checkpointing in --follow mode.",
    )
    parser.add_argument(
        "--reset-checkpoint",
        action="store_true",
        help="Delete the stored checkpoint before startup.",
    )
    return parser.parse_args()


async def iter_json_lines(
    path: Path,
    *,
    follow: bool,
    start_offset: int,
) -> AsyncIterator[tuple[int, str, int]]:
    """Yield line number, text and byte offset immediately after the line."""
    with path.open("rb") as handle:
        handle.seek(start_offset)
        line_number = 0

        while True:
            raw_line = handle.readline()

            if raw_line:
                line_number += 1
                end_offset = handle.tell()
                yield (
                    line_number,
                    raw_line.decode("utf-8", errors="replace"),
                    end_offset,
                )
                continue

            if not follow:
                break

            await asyncio.sleep(0.25)




def checkpoint_enabled(args: argparse.Namespace) -> bool:
    return (
        args.follow
        and not args.dry_run
        and not args.no_checkpoint
    )


def load_checkpoint(path: Path, capture_file: Path) -> int | None:
    if not path.is_file():
        return None

    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[CHECKPOINT] Ungültiger Zustand, ignoriere ihn: {exc}")
        return None

    if not isinstance(state, dict):
        return None

    if state.get("capture_file") != str(capture_file.resolve()):
        print(
            "[CHECKPOINT] Zustand gehört zu einer anderen Capture-Datei; "
            "ignoriere ihn."
        )
        return None

    try:
        offset = int(state.get("offset", 0))
    except (TypeError, ValueError):
        return None

    file_size = capture_file.stat().st_size
    if offset < 0 or offset > file_size:
        print(
            "[CHECKPOINT] Offset passt nicht zur aktuellen Dateigröße; "
            "starte bei Offset 0."
        )
        return 0

    return offset


def save_checkpoint(path: Path, capture_file: Path, offset: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    state = {
        "version": 1,
        "capture_file": str(capture_file.resolve()),
        "offset": int(offset),
        "updated_utc": datetime.now(timezone.utc).isoformat(),
    }

    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(
        json.dumps(state, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temp_path, path)


def reset_checkpoint(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return

    print(f"[CHECKPOINT] Gelöscht: {path}")

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
    """Build metadata directly from the PacketTap capture record.

    Receiver identity comes from receiver.py via the PKTH HELLO frame.
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

    if decoded["payload_type"] == "ADVERT":
        print(
            "       advert "
            f"name={decoded.get('advert_name')} "
            f"role={decoded.get('advert_node_role')} "
            f"hops={decoded.get('advert_hop_count')} "
            f"key={decoded.get('advert_public_key')}"
        )


async def run_import(args: argparse.Namespace) -> int:
    if not args.capture_file.is_file():
        raise SystemExit(
            f"Capture file not found: {args.capture_file}"
        )

    if args.reset_checkpoint:
        reset_checkpoint(args.checkpoint_file)

    use_checkpoint = checkpoint_enabled(args)
    start_offset = 0

    if use_checkpoint:
        saved_offset = load_checkpoint(
            args.checkpoint_file,
            args.capture_file,
        )
        if saved_offset is not None:
            start_offset = saved_offset
            print(
                f"[CHECKPOINT] Fortsetzen bei Byte-Offset {start_offset} "
                f"aus {args.checkpoint_file}"
            )
        elif args.start_at_end:
            start_offset = args.capture_file.stat().st_size
            print(
                "[CHECKPOINT] Kein gespeicherter Stand; "
                f"Start am Dateiende bei Offset {start_offset}."
            )
    elif args.follow and args.start_at_end:
        start_offset = args.capture_file.stat().st_size

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
    seen_contact_public_keys: set[str] = set()

    checkpoint_pending_offset: int | None = None
    checkpoint_records = 0
    checkpoint_db_dirty = False
    last_checkpoint_time = time.monotonic()

    async def advance_checkpoint(
        end_offset: int,
        *,
        db_dirty: bool,
        force: bool = False,
    ) -> None:
        nonlocal checkpoint_pending_offset
        nonlocal checkpoint_records
        nonlocal checkpoint_db_dirty
        nonlocal last_checkpoint_time

        if not use_checkpoint:
            return

        checkpoint_pending_offset = end_offset
        checkpoint_records += 1
        checkpoint_db_dirty = checkpoint_db_dirty or db_dirty

        due_by_rows = checkpoint_records >= max(1, args.checkpoint_rows)
        due_by_time = (
            time.monotonic() - last_checkpoint_time
            >= max(0.1, args.checkpoint_seconds)
        )

        if not force and not due_by_rows and not due_by_time:
            return

        # A checkpoint may only pass data that QuestDB has confirmed.
        if checkpoint_db_dirty and writer is not None:
            await writer.flush()

        save_checkpoint(
            args.checkpoint_file,
            args.capture_file,
            checkpoint_pending_offset,
        )

        checkpoint_records = 0
        checkpoint_db_dirty = False
        last_checkpoint_time = time.monotonic()

    try:
        async for line_number, line, end_offset in iter_json_lines(
            args.capture_file,
            follow=args.follow,
            start_offset=start_offset,
        ):
            line_db_dirty = False
            text = line.strip()
            if not text:
                await advance_checkpoint(
                    end_offset,
                    db_dirty=False,
                )
                continue

            try:
                capture_record = json.loads(text)
            except json.JSONDecodeError as exc:
                invalid += 1
                print(
                    f"[WARNUNG] Ungültiges JSON in Zeile "
                    f"{line_number}: {exc}"
                )
                await advance_checkpoint(
                    end_offset,
                    db_dirty=False,
                )
                continue

            if not isinstance(capture_record, dict):
                invalid += 1
                await advance_checkpoint(
                    end_offset,
                    db_dirty=False,
                )
                continue

            if (
                not args.include_bad_crc
                and not bool(capture_record.get("crc_ok", False))
            ):
                skipped += 1
                await advance_checkpoint(
                    end_offset,
                    db_dirty=False,
                )
                continue

            payload_hex = str(
                capture_record.get("payload_hex", "")
            ).strip()
            if not payload_hex:
                skipped += 1
                await advance_checkpoint(
                    end_offset,
                    db_dirty=False,
                )
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
                await advance_checkpoint(
                    end_offset,
                    db_dirty=False,
                )
                continue

            print_record(
                capture_record.get("sequence", line_number),
                decoded,
                dry_run=args.dry_run,
            )

            if not args.dry_run:
                await write_decoded_packet(decoded)
                line_db_dirty = True

                if decoded.get("payload_type") == "ADVERT":
                    public_key = str(
                        decoded.get("advert_public_key") or ""
                    ).strip()

                    # A structurally valid ADVERT always carries its public key.
                    if public_key:
                        # mc_contacts is treated as a compact node/contact
                        # directory. During one importer run we write one
                        # snapshot row per observed public key.
                        if public_key not in seen_contact_public_keys:
                            seen_contact_public_keys.add(public_key)

                            await write_mc_contact(
                                recv_time=decoded.get("recv_time"),
                                public_key=public_key,
                                adv_name=decoded.get("advert_name"),
                                contact_type=None,
                                flags=decoded.get("advert_flags"),
                                out_path_hash_mode=None,
                                out_path_len=None,
                                out_path=None,
                                last_advert=decoded.get(
                                    "advert_timestamp"
                                ),
                                adv_lat=decoded.get("advert_lat"),
                                adv_lon=decoded.get("advert_lon"),
                                lastmod=decoded.get(
                                    "advert_timestamp"
                                ),
                                node_role=decoded.get(
                                    "advert_node_role"
                                ),
                                source_type="advert",
                            )

                        # mc_contact_observations is deliberately historical:
                        # every received ADVERT is stored with RF/path data.
                        await write_mc_contact_observation(
                            recv_time=decoded.get("recv_time"),
                            public_key=public_key,
                            receiver_id=decoded.get("receiver_id"),
                            receiver_name=decoded.get("receiver_name"),
                            node_role=decoded.get(
                                "advert_node_role"
                            ),
                            hop_count=decoded.get(
                                "advert_hop_count"
                            ),
                            rssi_dbm=decoded.get("rssi_dbm"),
                            snr_db=decoded.get("snr_db"),
                            region_name=decoded.get("region_name"),
                            packet_payload_sha256=decoded.get(
                                "packet_payload_sha256"
                            ),
                        )

            imported += 1
            await advance_checkpoint(
                end_offset,
                db_dirty=line_db_dirty,
            )

    except KeyboardInterrupt:
        print("\nImport beendet.")
    finally:
        if (
            use_checkpoint
            and checkpoint_pending_offset is not None
            and checkpoint_records > 0
        ):
            if checkpoint_db_dirty and writer is not None:
                await writer.flush()

            save_checkpoint(
                args.checkpoint_file,
                args.capture_file,
                checkpoint_pending_offset,
            )

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