#!/usr/bin/env python3
"""PacketTap TCP receiver and diagnostic capture writer.

Supports:
- PKTH v1: receiver identity sent once after TCP connect
- PKTP v1: radio packet frames

The existing PKTP capture format remains unchanged. When a valid PKTH hello
has been received, its receiver identity is added to every JSON log record.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import struct
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, TextIO


PACKET_MAGIC = b"PKTP"
HELLO_MAGIC = b"PKTH"

DEFAULT_HOST = "192.168.1.90"
DEFAULT_PORT = 9000

PACKET_HEADER_SIZE = 16
HELLO_HEADER_SIZE = 8
CRC_SIZE = 4
HELLO_LENGTH_TABLE_SIZE = 5

MAX_PAYLOAD_SIZE = 4096
MAX_HELLO_PAYLOAD_SIZE = 4096
READ_SIZE = 65536


@dataclass(frozen=True)
class PacketTapFrame:
    raw: bytes
    version: int
    flags: int
    payload_length: int
    timestamp_ms: int
    rssi_dbm: int
    snr_x10: int
    payload: bytes
    crc_received: int
    crc_calculated: int

    @property
    def crc_ok(self) -> bool:
        return self.crc_received == self.crc_calculated

    @property
    def snr_db(self) -> float:
        return self.snr_x10 / 10.0


@dataclass(frozen=True)
class PacketTapHello:
    raw: bytes
    version: int
    flags: int
    payload_length: int
    receiver_id: str
    receiver_name: str
    receiver_type: str
    receiver_version: str
    receiver_build: str
    crc_received: int
    crc_calculated: int

    @property
    def crc_ok(self) -> bool:
        return self.crc_received == self.crc_calculated


PacketTapEvent = PacketTapFrame | PacketTapHello


class PacketTapParser:
    """Incremental parser for mixed PKTH/PKTP TCP streams."""

    def __init__(
        self,
        max_payload_size: int = MAX_PAYLOAD_SIZE,
        max_hello_payload_size: int = MAX_HELLO_PAYLOAD_SIZE,
    ) -> None:
        self.buffer = bytearray()
        self.max_payload_size = max_payload_size
        self.max_hello_payload_size = max_hello_payload_size
        self.discarded_bytes = 0

    def _find_next_magic(self) -> int:
        packet_pos = self.buffer.find(PACKET_MAGIC)
        hello_pos = self.buffer.find(HELLO_MAGIC)

        positions = [
            position
            for position in (packet_pos, hello_pos)
            if position >= 0
        ]

        return min(positions) if positions else -1

    def _discard_until_possible_magic(self) -> None:
        # Both magics are four bytes and share the "PKT" prefix.
        keep = 3
        discard = max(0, len(self.buffer) - keep)
        if discard:
            del self.buffer[:discard]
            self.discarded_bytes += discard

    def feed(self, data: bytes) -> list[PacketTapEvent]:
        self.buffer.extend(data)
        events: list[PacketTapEvent] = []

        while True:
            if len(self.buffer) < 4:
                break

            magic_pos = self._find_next_magic()

            if magic_pos < 0:
                self._discard_until_possible_magic()
                break

            if magic_pos > 0:
                del self.buffer[:magic_pos]
                self.discarded_bytes += magic_pos

            magic = bytes(self.buffer[:4])

            if magic == PACKET_MAGIC:
                frame = self._parse_packet()
                if frame is None:
                    break
                if frame is False:
                    continue
                events.append(frame)
                continue

            if magic == HELLO_MAGIC:
                hello = self._parse_hello()
                if hello is None:
                    break
                if hello is False:
                    continue
                events.append(hello)
                continue

            # Defensive fallback.
            del self.buffer[0]
            self.discarded_bytes += 1

        return events

    def _parse_packet(self) -> PacketTapFrame | bool | None:
        if len(self.buffer) < PACKET_HEADER_SIZE:
            return None

        payload_length = struct.unpack_from("<H", self.buffer, 6)[0]
        if payload_length > self.max_payload_size:
            del self.buffer[0]
            self.discarded_bytes += 1
            return False

        frame_size = PACKET_HEADER_SIZE + payload_length + CRC_SIZE
        if len(self.buffer) < frame_size:
            return None

        raw = bytes(self.buffer[:frame_size])
        del self.buffer[:frame_size]

        version = raw[4]
        flags = raw[5]
        timestamp_ms = struct.unpack_from("<I", raw, 8)[0]
        rssi_dbm = struct.unpack_from("<h", raw, 12)[0]
        snr_x10 = struct.unpack_from("<h", raw, 14)[0]
        payload = raw[
            PACKET_HEADER_SIZE:
            PACKET_HEADER_SIZE + payload_length
        ]

        crc_received = struct.unpack_from(
            "<I",
            raw,
            PACKET_HEADER_SIZE + payload_length,
        )[0]
        crc_calculated = (
            zlib.crc32(raw[:PACKET_HEADER_SIZE + payload_length])
            & 0xFFFFFFFF
        )

        return PacketTapFrame(
            raw=raw,
            version=version,
            flags=flags,
            payload_length=payload_length,
            timestamp_ms=timestamp_ms,
            rssi_dbm=rssi_dbm,
            snr_x10=snr_x10,
            payload=payload,
            crc_received=crc_received,
            crc_calculated=crc_calculated,
        )

    def _parse_hello(self) -> PacketTapHello | bool | None:
        if len(self.buffer) < HELLO_HEADER_SIZE:
            return None

        payload_length = struct.unpack_from("<H", self.buffer, 6)[0]

        if (
            payload_length < HELLO_LENGTH_TABLE_SIZE
            or payload_length > self.max_hello_payload_size
        ):
            del self.buffer[0]
            self.discarded_bytes += 1
            return False

        frame_size = HELLO_HEADER_SIZE + payload_length + CRC_SIZE
        if len(self.buffer) < frame_size:
            return None

        raw = bytes(self.buffer[:frame_size])
        del self.buffer[:frame_size]

        version = raw[4]
        flags = raw[5]
        payload = raw[
            HELLO_HEADER_SIZE:
            HELLO_HEADER_SIZE + payload_length
        ]

        crc_received = struct.unpack_from(
            "<I",
            raw,
            HELLO_HEADER_SIZE + payload_length,
        )[0]
        crc_calculated = (
            zlib.crc32(raw[:HELLO_HEADER_SIZE + payload_length])
            & 0xFFFFFFFF
        )

        lengths = list(payload[:HELLO_LENGTH_TABLE_SIZE])
        field_bytes = payload[HELLO_LENGTH_TABLE_SIZE:]

        if sum(lengths) != len(field_bytes):
            # Structurally invalid hello. Keep it visible, but with empty
            # identity fields so it cannot become active receiver metadata.
            fields = ["", "", "", "", ""]
        else:
            fields: list[str] = []
            offset = 0

            for length in lengths:
                raw_value = field_bytes[offset:offset + length]
                offset += length
                fields.append(
                    raw_value.decode("utf-8", errors="replace").strip()
                )

        return PacketTapHello(
            raw=raw,
            version=version,
            flags=flags,
            payload_length=payload_length,
            receiver_id=fields[0],
            receiver_name=fields[1],
            receiver_type=fields[2],
            receiver_version=fields[3],
            receiver_build=fields[4],
            crc_received=crc_received,
            crc_calculated=crc_calculated,
        )


class CaptureFiles:
    def __init__(self, output_dir: Path, append: bool) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)

        bin_mode = "ab" if append else "wb"
        text_mode = "a" if append else "w"

        self.frames_path = output_dir / "packettap_capture.bin"
        self.log_path = output_dir / "packettap_capture.log"
        self.stream_path = output_dir / "packettap_stream.bin"

        self.frames_file: BinaryIO = self.frames_path.open(bin_mode)
        self.log_file: TextIO = self.log_path.open(
            text_mode,
            encoding="utf-8",
        )
        self.stream_file: BinaryIO = self.stream_path.open(bin_mode)

    def write_stream_chunk(self, data: bytes) -> None:
        # Raw stream contains both PKTH and PKTP.
        self.stream_file.write(data)
        self.stream_file.flush()

    def write_frame(
        self,
        frame: PacketTapFrame,
        sequence: int,
        peer: str,
        received_unix_ns: int,
        hello: PacketTapHello | None,
    ) -> None:
        # Preserve historical behavior: capture.bin contains PKTP frames only.
        self.frames_file.write(frame.raw)
        self.frames_file.flush()

        record = {
            "sequence": sequence,
            "received_utc": datetime.fromtimestamp(
                received_unix_ns / 1_000_000_000,
                tz=timezone.utc,
            ).isoformat(),
            "received_unix_ns": received_unix_ns,
            "peer": peer,
            "frame_length": len(frame.raw),
            "raw_frame_hex": frame.raw.hex(),
            "magic": "PKTP",
            "version": frame.version,
            "flags": frame.flags,
            "payload_length": frame.payload_length,
            "timestamp_ms": frame.timestamp_ms,
            "rssi_dbm": frame.rssi_dbm,
            "snr_x10": frame.snr_x10,
            "snr_db": frame.snr_db,
            "payload_hex": frame.payload.hex(),
            "crc_received_hex": f"{frame.crc_received:08x}",
            "crc_calculated_hex": f"{frame.crc_calculated:08x}",
            "crc_ok": frame.crc_ok,

            # Receiver identity from the latest valid PKTH on this TCP
            # connection. Old firmware simply leaves these fields null.
            "receiver_id": hello.receiver_id if hello else None,
            "receiver_name": hello.receiver_name if hello else None,
            "receiver_type": hello.receiver_type if hello else None,
            "receiver_version": hello.receiver_version if hello else None,
            "receiver_build": hello.receiver_build if hello else None,
            "hello_protocol_version": hello.version if hello else None,
        }

        self.log_file.write(
            json.dumps(record, ensure_ascii=False) + "\n"
        )
        self.log_file.flush()

    def close(self) -> None:
        self.frames_file.close()
        self.log_file.close()
        self.stream_file.close()


class CaptureServer:
    def __init__(
        self,
        host: str,
        port: int,
        files: CaptureFiles,
        max_frames: int | None,
        stop_after_seconds: float | None,
        max_payload_size: int,
    ) -> None:
        self.host = host
        self.port = port
        self.files = files
        self.max_frames = max_frames
        self.stop_after_seconds = stop_after_seconds
        self.max_payload_size = max_payload_size
        self.stop_event = asyncio.Event()
        self.frame_count = 0
        self.connection_count = 0

    def request_stop(self) -> None:
        self.stop_event.set()

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.connection_count += 1

        peer = str(writer.get_extra_info("peername"))
        parser = PacketTapParser(self.max_payload_size)
        active_hello: PacketTapHello | None = None

        print(f"[TCP] Verbunden: {peer}")

        try:
            while not self.stop_event.is_set():
                data = await reader.read(READ_SIZE)

                if not data:
                    print(f"[TCP] Verbindung beendet: {peer}")
                    break

                self.files.write_stream_chunk(data)

                for event in parser.feed(data):
                    if isinstance(event, PacketTapHello):
                        crc_state = "OK" if event.crc_ok else "FEHLER"

                        print(
                            f"[HELLO] v={event.version} "
                            f"flags=0x{event.flags:02x} "
                            f"len={event.payload_length} "
                            f"crc={crc_state}"
                        )
                        print(
                            f"        id={event.receiver_id or '-'}"
                        )
                        print(
                            f"        name={event.receiver_name or '-'}"
                        )
                        print(
                            f"        type={event.receiver_type or '-'}"
                        )
                        print(
                            f"        firmware="
                            f"{event.receiver_version or '-'}"
                        )
                        print(
                            f"        build={event.receiver_build or '-'}"
                        )

                        if (
                            event.crc_ok
                            and event.receiver_id
                        ):
                            active_hello = event
                            print(
                                "[HELLO] Receiver-Identität übernommen.\n"
                            )
                        else:
                            print(
                                "[HELLO] Ungültig; Identität nicht "
                                "übernommen.\n"
                            )

                        continue

                    frame = event
                    self.frame_count += 1
                    received_unix_ns = time.time_ns()

                    self.files.write_frame(
                        frame,
                        self.frame_count,
                        peer,
                        received_unix_ns,
                        active_hello,
                    )

                    crc_state = "OK" if frame.crc_ok else "FEHLER"

                    receiver_suffix = ""
                    if active_hello is not None:
                        receiver_suffix = (
                            f" receiver={active_hello.receiver_name}"
                        )

                    print(
                        f"[{self.frame_count:05d}] "
                        f"v={frame.version} "
                        f"flags=0x{frame.flags:02x} "
                        f"len={frame.payload_length} "
                        f"ts_ms={frame.timestamp_ms} "
                        f"rssi={frame.rssi_dbm} dBm "
                        f"snr={frame.snr_db:.1f} dB "
                        f"crc={crc_state}"
                        f"{receiver_suffix}"
                    )
                    print(
                        f"          payload={frame.payload.hex()}"
                    )

                    if (
                        self.max_frames is not None
                        and self.frame_count >= self.max_frames
                    ):
                        print(
                            f"[STOP] Ziel von {self.max_frames} "
                            "Frames erreicht."
                        )
                        self.request_stop()
                        break

            if parser.discarded_bytes:
                print(
                    f"[Parser] {parser.discarded_bytes} Byte bei der "
                    "Synchronisierung verworfen."
                )

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            print(
                f"[TCP] Fehler bei {peer}: "
                f"{type(exc).__name__}: {exc}"
            )

        finally:
            writer.close()

            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def duration_watchdog(self) -> None:
        if self.stop_after_seconds is None:
            return

        await asyncio.sleep(self.stop_after_seconds)
        print(
            f"[STOP] Laufzeit von "
            f"{self.stop_after_seconds:g} Sekunden erreicht."
        )
        self.request_stop()

    async def run(self) -> None:
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
        )

        addresses = ", ".join(
            str(sock.getsockname())
            for sock in server.sockets or []
        )

        print(f"PacketTap Receiver lauscht auf {addresses}")
        print(f"Frames: {self.files.frames_path}")
        print(f"Log:    {self.files.log_path}")
        print(f"Stream: {self.files.stream_path}")
        print(
            "Unterstützt: PKTH v1 (HELLO) + PKTP v1 (Radio Frames)"
        )
        print(
            "Beenden mit q + Enter, Strg+C oder Strg+Pause.\n"
        )

        watchdog = asyncio.create_task(self.duration_watchdog())

        try:
            async with server:
                await self.stop_event.wait()

        finally:
            server.close()
            await server.wait_closed()

            watchdog.cancel()

            try:
                await watchdog
            except asyncio.CancelledError:
                pass


async def keyboard_monitor(server: CaptureServer) -> None:
    """Wait for q, quit or exit and stop the server cleanly."""
    while not server.stop_event.is_set():
        try:
            command = await asyncio.to_thread(input)
        except (EOFError, OSError):
            return

        if command.strip().lower() in {"q", "quit", "exit"}:
            print("\n[STOP] Beenden angefordert.")
            server.request_stop()
            return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PacketTap TCP receiver and capture writer"
    )

    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Listen-Adresse (Standard: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP-Port (Standard: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Ausgabeverzeichnis",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Dateien fortsetzen statt überschreiben",
    )
    parser.add_argument(
        "--max-frames",
        type=int,
        default=None,
        help="Nach N Frames stoppen",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=None,
        help="Nach N Sekunden stoppen",
    )
    parser.add_argument(
        "--max-payload",
        type=int,
        default=MAX_PAYLOAD_SIZE,
        help=(
            "Maximale PKTP-Payload-Länge "
            f"(Standard: {MAX_PAYLOAD_SIZE})"
        ),
    )

    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> None:
    files = CaptureFiles(
        args.output_dir,
        append=args.append,
    )

    server = CaptureServer(
        args.host,
        args.port,
        files,
        args.max_frames,
        args.seconds,
        args.max_payload,
    )

    loop = asyncio.get_running_loop()
    keyboard_task = asyncio.create_task(
        keyboard_monitor(server)
    )

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(
                sig,
                server.request_stop,
            )
        except (NotImplementedError, RuntimeError):
            pass

    try:
        await server.run()

    finally:
        keyboard_task.cancel()

        try:
            await keyboard_task
        except asyncio.CancelledError:
            pass

        files.close()

        print(
            f"\nFertig: {server.frame_count} Frames aus "
            f"{server.connection_count} TCP-Verbindung(en) gespeichert."
        )


def main() -> None:
    args = parse_args()

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()