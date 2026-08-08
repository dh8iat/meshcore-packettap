
#!/usr/bin/env python3
"""
Standalone MeshCore packet decoder.

Supported forms:

    python decode_packet.py
    python decode_packet.py <payload_hex>
    python decode_packet.py packettap_capture.log 21
    type payload.txt | python decode_packet.py

When a JSON-lines capture file and sequence number are supplied, the matching
PacketTap record is loaded and decoded.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from meshcore_decoder import (
    decode_mc_rx_record,
    decode_packet,
    decode_payload_metadata,
)


def show(label: str, value: Any) -> None:
    print(f"{label:<20}: {value}")


def prompt_payload() -> str:
    try:
        value = input("Enter payload hex: ").strip()
    except EOFError:
        value = ""

    if not value:
        raise SystemExit("No payload supplied.")

    return value


def read_payload_from_stdin() -> str | None:
    if sys.stdin.isatty():
        return None

    value = sys.stdin.read().strip()
    return value or None


def load_capture_record(path: Path, sequence: int) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"Capture file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue

            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                continue

            try:
                record_sequence = int(record.get("sequence"))
            except (TypeError, ValueError):
                continue

            if record_sequence == sequence:
                return record

    raise SystemExit(
        f"Sequence {sequence} was not found in {path}."
    )


def resolve_input(argv: list[str]) -> tuple[str, dict[str, Any] | None]:
    # No arguments:
    # - use piped stdin when available
    # - otherwise ask interactively
    if not argv:
        piped = read_payload_from_stdin()
        return (piped or prompt_payload()), None

    # One argument: treat it as a raw payload.
    if len(argv) == 1:
        return argv[0].strip(), None

    # Two arguments: capture file + sequence number.
    if len(argv) == 2:
        capture_path = Path(argv[0])
        try:
            sequence = int(argv[1])
        except ValueError as exc:
            raise SystemExit(
                "Second argument must be a numeric sequence value."
            ) from exc

        record = load_capture_record(capture_path, sequence)
        payload = str(record.get("payload_hex", "")).strip()
        if not payload:
            raise SystemExit(
                f"Sequence {sequence} has no payload_hex value."
            )
        return payload, record

    raise SystemExit(
        "Usage:\n"
        "  python decode_packet.py\n"
        "  python decode_packet.py <payload_hex>\n"
        "  python decode_packet.py <capture.jsonl> <sequence>\n"
        "  type payload.txt | python decode_packet.py"
    )


def print_packet(
    decoded: dict[str, Any],
    metadata: dict[str, Any],
    capture_record: dict[str, Any] | None,
) -> None:
    print("=" * 64)
    print("MeshCore Packet")
    print("=" * 64)

    if capture_record is not None:
        print("\nPacketTap")
        print("-" * 64)
        show("Sequence", capture_record.get("sequence"))
        show("Received UTC", capture_record.get("received_utc"))
        show("RSSI dBm", capture_record.get("rssi_dbm"))
        show("SNR dB", capture_record.get("snr_db"))
        show("CRC OK", capture_record.get("crc_ok"))

    print("\nFrame")
    print("-" * 64)
    show("Frame bytes", decoded["frame_bytes"])
    show("Frame bits", decoded["frame_bits"])
    show("Payload SHA256", decoded["packet_payload_sha256"])

    print("\nHeader")
    print("-" * 64)
    show(
        "Route",
        f"{decoded['route_type_name']} ({decoded['route_type']})",
    )
    show(
        "Payload",
        f"{decoded['payload_type_name']} ({decoded['payload_type']})",
    )
    show("Version", decoded["payload_version"])
    show("Transport 1", decoded["transport1"])
    show("Transport 2", decoded["transport2"])

    print("\nPath")
    print("-" * 64)
    show("Path length", decoded["path_len"])
    show("Path hash size", decoded["path_hash_size"])

    nodes = decoded["path_nodes"]
    if not nodes:
        print("(empty)")
    else:
        for index, node in enumerate(nodes):
            roles: list[str] = []
            if index == 0:
                roles.append("Sender")
            if len(nodes) >= 2 and index == len(nodes) - 2:
                roles.append("Prev Hop")
            if index == len(nodes) - 1:
                roles.append("Repeater")
            suffix = f" <- {', '.join(roles)}" if roles else ""
            print(f"{index + 1:2d}  {node}{suffix}")

    print("\nPacket payload")
    print("-" * 64)
    print(decoded["packet_payload_hex"])

    payload_name = decoded["payload_type_name"]
    print(f"\n{payload_name}")
    print("-" * 64)

    if payload_name == "TEXT_MSG":
        show("Destination hash", metadata["txt_msg_dest_hash"])
        show("Source hash", metadata["txt_msg_src_hash"])

    if payload_name in {"GRP_TXT", "GRP_DATA"}:
        show("Channel hash", metadata["channel_hash_hex"])
        show("Channel", metadata["channel_name"])

    if payload_name == "GRP_TXT":
        show("MAC valid", metadata["grp_txt_mac_ok"])
        show("Decode error", metadata["grp_txt_error"])
        show("Timestamp", metadata["grp_txt_msg_timestamp"])
        show("Flags", metadata["grp_txt_msg_flags"])
        show("Sender", metadata["grp_txt_sender_name"])
        show("Message", metadata["grp_txt_body"])
        show("Full text", metadata["grp_txt_msg_text"])
        show("Plaintext hex", metadata["grp_txt_plaintext_hex"])


def main() -> None:
    payload_hex, capture_record = resolve_input(sys.argv[1:])

    decoded = decode_packet(payload_hex)
    if decoded is None:
        raise SystemExit("Unable to decode packet.")

    metadata = decode_payload_metadata(decoded)
    record = decode_mc_rx_record(payload_hex, capture_record or {})
    print_packet(decoded, metadata, capture_record)

    print("\nmc_rx compatibility")
    print("-" * 64)
    if record is None:
        print("Unable to build mc_rx record.")
    else:
        show("Region code", record["region_code"])
        show("Region", record["region_name"])
        show("Packet ID", record["pkt_hash"])
        if record["pkt_hash"] is None:
            print(
                "Note: PacketTap does not provide Companion pkt_hash; "
                "value remains None."
            )


if __name__ == "__main__":
    main()