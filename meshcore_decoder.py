#!/usr/bin/env python3
"""Shared MeshCore packet decoding helpers.

The functions in this module operate on the raw MeshCore packet bytes carried
inside PacketTap's ``payload_hex`` field.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

try:
    from Crypto.Cipher import AES as _PyCryptoAES
except ImportError:  # pragma: no cover
    _PyCryptoAES = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    Cipher = algorithms = modes = None


def _aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-128 ECB with either pycryptodome or cryptography."""
    if _PyCryptoAES is not None:
        return _PyCryptoAES.new(key, _PyCryptoAES.MODE_ECB).decrypt(ciphertext)

    if Cipher is not None and algorithms is not None and modes is not None:
        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    raise RuntimeError(
        "AES backend missing; install pycryptodome or cryptography"
    )


ROUTE_TYPE_NAMES = {
    0: "TRANSPORT_FLOOD",
    1: "FLOOD",
    2: "DIRECT",
    3: "TRANSPORT_DIRECT",
}

PAYLOAD_TYPE_NAMES = {
    0x00: "REQ",
    0x01: "RESPONSE",
    0x02: "TEXT_MSG",
    0x03: "ACK",
    0x04: "ADVERT",
    0x05: "GRP_TXT",
    0x06: "GRP_DATA",
    0x07: "ANON_REQ",
    0x08: "PATH",
    0x09: "TRACE",
    0x0A: "MULTIPART",
    0x0B: "CONTROL",
    0x0F: "CUSTOM",
}


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_CHANNELS_FILE = os.path.join(BASE_DIR, "public_channels.json")
PUBLIC_CHANNEL_KEYS_FILE = os.path.join(BASE_DIR, "public_channel_keys.json")
REGIONS_FILE = os.path.join(BASE_DIR, "regions.json")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_PUBLIC_CHANNELS_CACHE: dict[str, dict[str, str]] | None = None
_REGION_NAMES_CACHE: list[str] | None = None


def derive_public_channel_secret(channel_name: Any) -> str | None:
    """Derive the 16-byte public-channel AES key used by Companion."""
    try:
        name = str(channel_name).strip()
        if not name:
            return None
        return hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]
    except Exception:
        return None


def derive_channel_hash_from_secret(secret_hex: Any) -> str | None:
    """Derive the one-byte GRP channel hash from a 16-byte key."""
    try:
        raw = bytes.fromhex(str(secret_hex).strip().lower())
        if len(raw) != 16:
            return None
        return hashlib.sha256(raw).hexdigest()[:2]
    except Exception:
        return None


def _load_json_file(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def load_public_channels(
    channels_file: str = PUBLIC_CHANNELS_FILE,
    keys_file: str = PUBLIC_CHANNEL_KEYS_FILE,
) -> dict[str, dict[str, str]]:
    """Load derived public channels and explicit channel keys.

    ``public_channels.json`` contains a list of names whose keys are derived
    from the channel name. ``public_channel_keys.json`` contains objects with
    ``name`` and a 32-character ``key_hex`` value.
    """
    mapping: dict[str, dict[str, str]] = {}

    def add_channel(name: Any, secret_hex: Any) -> None:
        channel_name = str(name).strip()
        secret = str(secret_hex).strip().lower()
        if not channel_name or len(secret) != 32:
            return
        try:
            if len(bytes.fromhex(secret)) != 16:
                return
        except ValueError:
            return

        channel_hash = derive_channel_hash_from_secret(secret)
        if channel_hash:
            mapping[channel_hash] = {
                "name": channel_name,
                "secret_hex": secret,
            }

    names = _load_json_file(channels_file)
    if isinstance(names, list):
        for name in names:
            secret = derive_public_channel_secret(name)
            if secret:
                add_channel(name, secret)

    entries = _load_json_file(keys_file)
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                add_channel(entry.get("name"), entry.get("key_hex"))

    return mapping


def get_public_channels(*, reload: bool = False) -> dict[str, dict[str, str]]:
    """Return the cached channel map."""
    global _PUBLIC_CHANNELS_CACHE
    if reload or _PUBLIC_CHANNELS_CACHE is None:
        _PUBLIC_CHANNELS_CACHE = load_public_channels()
    return _PUBLIC_CHANNELS_CACHE


def resolve_channel(channel_hash_hex: Any) -> str | None:
    """Resolve a one-byte channel hash to its configured channel name."""
    if channel_hash_hex is None:
        return None
    channel_hash = str(channel_hash_hex).strip().lower()
    info = get_public_channels().get(channel_hash)
    return info["name"] if info else None


def get_channel_secret_hex(channel_name: Any) -> str | None:
    """Return the configured/derived 16-byte key for a channel name."""
    if channel_name is None:
        return None
    wanted = str(channel_name).strip()
    if not wanted:
        return None

    for info in get_public_channels().values():
        if info["name"] == wanted:
            return info["secret_hex"]
    return None



def load_region_names(regions_file: str = REGIONS_FILE) -> list[str]:
    """Load region names from the Companion-compatible regions.json file."""
    data = _load_json_file(regions_file)
    if not isinstance(data, list):
        return []

    result: list[str] = []
    for item in data:
        if item is None:
            continue
        name = str(item).strip()
        if name:
            result.append(name)
    return result


def get_region_names(*, reload: bool = False) -> list[str]:
    """Return cached region names."""
    global _REGION_NAMES_CACHE
    if reload or _REGION_NAMES_CACHE is None:
        _REGION_NAMES_CACHE = load_region_names()
    return _REGION_NAMES_CACHE


def calc_region_key(region_name: Any) -> bytes | None:
    """Derive the 16-byte region key used by MeshCore transport codes."""
    try:
        name = str(region_name).strip()
        if not name:
            return None
        return hashlib.sha256(name.encode("utf-8")).digest()[:16]
    except Exception:
        return None


def calc_transport_code_for_region(
    region_name: Any,
    payload_type_byte: Any,
    packet_payload_bytes: bytes,
) -> int | None:
    """Calculate the Companion-compatible two-byte transport code."""
    try:
        region_key = calc_region_key(region_name)
        payload_type_value = safe_int(payload_type_byte)
        if region_key is None or payload_type_value is None:
            return None

        message = bytes([payload_type_value]) + packet_payload_bytes
        digest = hmac.new(region_key, message, hashlib.sha256).digest()
        code = int.from_bytes(digest[:2], byteorder="little", signed=False)

        if code == 0x0000:
            code = 0x0001
        elif code == 0xFFFF:
            code = 0xFFFE
        return code
    except Exception:
        return None


def resolve_region(
    region_code: Any,
    payload_type: Any,
    packet_payload_hex: Any,
) -> str | None:
    """Resolve transport code to a configured region name."""
    if not region_code or payload_type is None or not packet_payload_hex:
        return None

    if isinstance(payload_type, str):
        payload_type_byte = next(
            (
                value
                for value, name in PAYLOAD_TYPE_NAMES.items()
                if name == payload_type
            ),
            None,
        )
    else:
        payload_type_byte = safe_int(payload_type)

    if payload_type_byte is None:
        return None

    try:
        payload_bytes = bytes.fromhex(str(packet_payload_hex).strip())
        wanted_code = int(str(region_code), 16)
    except (TypeError, ValueError):
        return None

    for region_name in get_region_names():
        calculated = calc_transport_code_for_region(
            region_name,
            payload_type_byte,
            payload_bytes,
        )
        if calculated == wanted_code:
            return region_name
    return None

def extract_channel_hash(packet_payload_hex: Any) -> str | None:
    """Extract the first byte of a GRP_TXT/GRP_DATA packet payload."""
    normalized = normalize_payload_hex(packet_payload_hex)
    if normalized is None:
        return None
    raw = bytes.fromhex(normalized)
    return raw[:1].hex() or None


def split_grp_txt_sender_and_body(
    msg_text: Any,
) -> tuple[str | None, str | None]:
    """Split ``sender: body`` exactly like the Companion analyzer."""
    if not msg_text:
        return None, None

    text = str(msg_text).strip()
    if ": " in text:
        sender, body = text.split(": ", 1)
        return sender.strip() or None, body.strip() or None
    if ":" in text:
        sender, body = text.split(":", 1)
        return sender.strip() or None, body.strip() or None
    return None, text or None


def clean_decoded_text(value: Any, max_len: int) -> str | None:
    """Remove control characters before values reach QuestDB."""
    if value is None:
        return None
    text = ANSI_RE.sub("", str(value))
    text = "".join(
        character
        for character in text
        if character.isprintable() and character not in "\r\n\t"
    ).strip()
    return text[:max_len] or None


def looks_like_human_text(value: Any, min_ratio: float = 0.85) -> bool:
    """Reject obvious binary data and failed UTF-8 decryption."""
    if not value:
        return False
    text = str(value)
    if "\ufffd" in text or any(not char.isprintable() for char in text):
        return False
    printable = sum(char.isprintable() for char in text)
    return printable / max(len(text), 1) >= min_ratio


def decrypt_grp_txt(
    packet_payload_hex: Any,
    channel_name: Any,
) -> dict[str, Any]:
    """Decrypt a Companion-compatible GRP_TXT packet payload.

    Layout::

        channel_hash (1 byte)
        cipher_mac   (2 bytes)
        ciphertext   (AES-128 ECB, block aligned)

    The plaintext begins with a four-byte little-endian timestamp and one
    flags byte, followed by UTF-8 ``sender: message`` text.
    """
    result: dict[str, Any] = {
        "ok": False,
        "error": None,
        "channel_hash_hex": extract_channel_hash(packet_payload_hex),
        "cipher_mac_hex": None,
        "calc_mac_hex": None,
        "mac_ok": None,
        "msg_timestamp": None,
        "msg_flags": None,
        "msg_text": None,
        "plaintext_hex": None,
        "sender_name": None,
        "body": None,
    }

    normalized = normalize_payload_hex(packet_payload_hex)
    secret_hex = get_channel_secret_hex(channel_name)
    if normalized is None:
        result["error"] = "invalid_packet_payload"
        return result
    if not secret_hex:
        result["error"] = "missing_channel_key"
        return result

    try:
        grp_part = bytes.fromhex(normalized)
        if len(grp_part) < 3:
            result["error"] = "grp_part_too_short"
            return result

        key = bytes.fromhex(secret_hex)
        rx_mac = grp_part[1:3]
        ciphertext = grp_part[3:]

        result["cipher_mac_hex"] = rx_mac.hex()

        if not ciphertext:
            result["error"] = "empty_ciphertext"
            return result
        if len(ciphertext) % 16:
            result["error"] = "ciphertext_not_block_aligned"
            return result

        calc_mac = hmac.new(key, ciphertext, hashlib.sha256).digest()[:2]
        result["calc_mac_hex"] = calc_mac.hex()
        result["mac_ok"] = hmac.compare_digest(calc_mac, rx_mac)

        # Do not expose plausible-looking garbage when authentication fails.
        if not result["mac_ok"]:
            result["error"] = "mac_mismatch"
            return result

        plaintext = _aes_ecb_decrypt(key, ciphertext)
        plaintext = plaintext.rstrip(b"\x00 ")
        result["plaintext_hex"] = plaintext.hex()

        if len(plaintext) < 5:
            result["error"] = "plaintext_too_short"
            return result

        result["msg_timestamp"] = int.from_bytes(
            plaintext[0:4],
            byteorder="little",
            signed=False,
        )
        result["msg_flags"] = plaintext[4]

        msg_text = plaintext[5:].rstrip(b"\x00 ").decode(
            "utf-8",
            errors="strict",
        ).strip()
        msg_text = clean_decoded_text(msg_text, max_len=2000)

        if not msg_text or not looks_like_human_text(msg_text):
            result["error"] = "invalid_message_text"
            return result

        sender_name, body = split_grp_txt_sender_and_body(msg_text)
        sender_name = clean_decoded_text(sender_name, max_len=200)
        body = clean_decoded_text(body, max_len=2000)

        if sender_name and not looks_like_human_text(sender_name):
            sender_name = None
        if body and not looks_like_human_text(body):
            body = None

        result.update({
            "ok": True,
            "error": None,
            "msg_text": msg_text,
            "sender_name": sender_name,
            "body": body,
        })
        return result
    except (ValueError, UnicodeDecodeError) as exc:
        result["error"] = f"decode_error:{exc}"
        return result
    except Exception as exc:
        result["error"] = f"exception:{exc}"
        return result


def normalize_payload_hex(payload_hex: Any) -> str | None:
    """Normalize and validate a hexadecimal MeshCore packet string."""
    if payload_hex is None:
        return None

    value = str(payload_hex).strip().lower()
    if not value or len(value) % 2 != 0:
        return None

    try:
        bytes.fromhex(value)
    except ValueError:
        return None

    return value


def short_sha256_hex(value: Any) -> str | None:
    """Return the first 16 hex characters of SHA-256 for a text value.

    This intentionally matches the existing Companion analyzer, which hashes
    the normalized hexadecimal string rather than the decoded raw bytes.
    """
    if value is None:
        return None

    text = str(value).strip().lower()
    if not text:
        return None

    try:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return None


def extract_txt_msg_hashes(
    packet_payload_hex: Any,
    path_hash_size: int = 1,
) -> tuple[str | None, str | None]:
    """Extract destination and source hashes from a TEXT_MSG payload.

    MeshCore TEXT_MSG packet payload::

        destination_hash
        source_hash
        MAC + encrypted message data

    Destination and source hashes use the packet's path hash size.
    """
    normalized = normalize_payload_hex(packet_payload_hex)
    if normalized is None:
        return None, None

    try:
        hash_size = int(path_hash_size)
    except (TypeError, ValueError):
        return None, None

    if hash_size not in (1, 2, 3):
        return None, None

    raw = bytes.fromhex(normalized)
    required_length = 2 * hash_size

    if len(raw) < required_length:
        return None, None

    destination_hash = raw[0:hash_size].hex() or None
    source_hash = raw[hash_size:required_length].hex() or None

    return destination_hash, source_hash


def parse_meshcore_header(payload_hex: Any) -> dict[str, Any] | None:
    """Parse the MeshCore packet header, transport codes and routing path."""
    normalized = normalize_payload_hex(payload_hex)
    if normalized is None:
        return None

    raw = bytes.fromhex(normalized)
    if len(raw) < 2:
        return None

    header = raw[0]
    route_type = header & 0x03
    payload_type = (header >> 2) & 0x0F
    payload_version = (header >> 6) & 0x03

    index = 1
    transport1 = None
    transport2 = None

    if route_type in (0, 3):
        if len(raw) < index + 4:
            return None

        transport1 = raw[index:index + 2][::-1].hex()
        transport2 = raw[index + 2:index + 4][::-1].hex()
        index += 4

    if len(raw) <= index:
        return None

    path_length_byte = raw[index]
    index += 1

    path_len = path_length_byte & 0x3F
    path_hash_size_code = (path_length_byte >> 6) & 0x03

    # Codes 0, 1 and 2 represent hash sizes of 1, 2 and 3 bytes.
    # Code 3 is reserved/unsupported.
    if path_hash_size_code == 3:
        return None

    path_hash_size = path_hash_size_code + 1
    path_byte_length = path_len * path_hash_size

    if len(raw) < index + path_byte_length:
        return None

    path_start = index
    path_end = path_start + path_byte_length
    path_raw = raw[path_start:path_end]
    packet_payload_raw = raw[path_end:]

    path_nodes = [
        path_raw[offset:offset + path_hash_size].hex()
        for offset in range(0, len(path_raw), path_hash_size)
    ]

    return {
        "header_byte": header,
        "header_hex": f"{header:02x}",
        "route_type": route_type,
        "route_type_name": ROUTE_TYPE_NAMES.get(route_type),
        "payload_type": payload_type,
        "payload_type_name": PAYLOAD_TYPE_NAMES.get(
            payload_type,
            f"UNKNOWN_{payload_type}",
        ),
        "payload_version": payload_version,
        "has_transport_codes": route_type in (0, 3),
        "transport1": transport1,
        "transport2": transport2,
        "path_length_byte": path_length_byte,
        "path_length_hex": f"{path_length_byte:02x}",
        "path_len": path_len,
        "path_hash_size_code": path_hash_size_code,
        "path_hash_size": path_hash_size,
        "path_byte_length": path_byte_length,
        "path_hex": path_raw.hex() or None,
        "path_nodes": path_nodes,
        "packet_payload_offset": path_end,
        "packet_payload_hex": packet_payload_raw.hex() or None,
        "frame_bytes": len(raw),
        "frame_bits": len(raw) * 8,
    }


def decode_packet(payload_hex: Any) -> dict[str, Any] | None:
    """Decode packet-wide routing and framing fields.

    Payload-specific parsing is delegated to ``decode_payload_metadata``.
    """
    normalized = normalize_payload_hex(payload_hex)
    if normalized is None:
        return None

    header = parse_meshcore_header(normalized)
    if header is None:
        return None

    packet_payload_hex = header["packet_payload_hex"]

    return {
        "payload_hex": normalized,
        "frame_bytes": header["frame_bytes"],
        "frame_bits": header["frame_bits"],
        "route_type": header["route_type"],
        "route_type_name": header["route_type_name"],
        "payload_type": header["payload_type"],
        "payload_type_name": header["payload_type_name"],
        "payload_version": header["payload_version"],
        "has_transport_codes": header["has_transport_codes"],
        "transport1": header["transport1"],
        "transport2": header["transport2"],
        "path_len": header["path_len"],
        "path_hash_size": header["path_hash_size"],
        "path_byte_length": header["path_byte_length"],
        "path_hex": header["path_hex"],
        "path_nodes": header["path_nodes"],
        "packet_payload_offset": header["packet_payload_offset"],
        "packet_payload_hex": packet_payload_hex,
        "packet_payload_sha256": short_sha256_hex(packet_payload_hex),
    }


def decode_text_msg(decoded: dict[str, Any]) -> dict[str, Any]:
    """Decode metadata specific to a MeshCore TEXT_MSG payload."""
    destination_hash, source_hash = extract_txt_msg_hashes(
        packet_payload_hex=decoded.get("packet_payload_hex"),
        path_hash_size=decoded.get("path_hash_size", 1),
    )
    return {
        "txt_msg_dest_hash": destination_hash,
        "txt_msg_src_hash": source_hash,
    }


def decode_grp_txt(decoded: dict[str, Any]) -> dict[str, Any]:
    """Resolve and decrypt a GRP_TXT payload."""
    packet_payload_hex = decoded.get("packet_payload_hex")
    channel_hash_hex = extract_channel_hash(packet_payload_hex)
    channel_name = resolve_channel(channel_hash_hex)

    result: dict[str, Any] = {
        "channel_hash_hex": channel_hash_hex,
        "channel_name": channel_name,
        "grp_txt_plaintext_hex": None,
        "grp_txt_msg_text": None,
        "grp_txt_msg_timestamp": None,
        "grp_txt_msg_flags": None,
        "grp_txt_mac_ok": None,
        "grp_txt_error": None,
        "grp_txt_sender_name": None,
        "grp_txt_body": None,
    }

    if not channel_name:
        result["grp_txt_error"] = (
            "unknown_channel" if channel_hash_hex else "missing_channel_hash"
        )
        return result

    decrypted = decrypt_grp_txt(packet_payload_hex, channel_name)
    result.update({
        "grp_txt_plaintext_hex": decrypted["plaintext_hex"],
        "grp_txt_msg_text": decrypted["msg_text"],
        "grp_txt_msg_timestamp": decrypted["msg_timestamp"],
        "grp_txt_msg_flags": decrypted["msg_flags"],
        "grp_txt_mac_ok": decrypted["mac_ok"],
        "grp_txt_error": decrypted["error"],
        "grp_txt_sender_name": decrypted["sender_name"],
        "grp_txt_body": decrypted["body"],
    })
    return result


def decode_grp_data(decoded: dict[str, Any]) -> dict[str, Any]:
    """Decode GRP_DATA metadata placeholder."""
    return {}


def decode_advert(decoded: dict[str, Any]) -> dict[str, Any]:
    """Decode ADVERT metadata placeholder."""
    return {}


def decode_control(decoded: dict[str, Any]) -> dict[str, Any]:
    """Decode CONTROL metadata placeholder."""
    return {}


PAYLOAD_DECODERS = {
    "TEXT_MSG": decode_text_msg,
    "GRP_TXT": decode_grp_txt,
    "GRP_DATA": decode_grp_data,
    "ADVERT": decode_advert,
    "CONTROL": decode_control,
}


def decode_payload_metadata(decoded: dict[str, Any]) -> dict[str, Any]:
    """Run the payload-specific decoder and normalize mc_rx payload fields."""
    payload_metadata: dict[str, Any] = {
        "channel_hash_hex": None,
        "channel_name": None,
        "grp_txt_plaintext_hex": None,
        "grp_txt_msg_text": None,
        "grp_txt_msg_timestamp": None,
        "grp_txt_msg_flags": None,
        "grp_txt_mac_ok": None,
        "grp_txt_error": None,
        "grp_txt_sender_name": None,
        "grp_txt_body": None,
        "txt_msg_dest_hash": None,
        "txt_msg_src_hash": None,
    }

    decoder = PAYLOAD_DECODERS.get(decoded.get("payload_type_name"))
    if decoder is not None:
        payload_metadata.update(decoder(decoded))

    return payload_metadata


def extract_payload_route_type(payload_hex: Any) -> int | None:
    """Return the raw MeshCore route type value 0..3."""
    decoded = decode_packet(payload_hex)
    if decoded is None:
        return None
    return decoded["route_type"]


def extract_transport_codes(
    payload_hex: Any,
) -> tuple[str | None, str | None]:
    """Return transport codes for transport-routed packets."""
    decoded = decode_packet(payload_hex)
    if decoded is None:
        return None, None

    return decoded["transport1"], decoded["transport2"]


def extract_packet_payload_hex(
    payload_hex: Any,
    path_len: int | None = None,
    path_hash_size: int | None = None,
) -> str | None:
    """Return the packet payload after MeshCore routing metadata.

    ``path_len`` and ``path_hash_size`` remain accepted for compatibility with
    the existing Companion analyzer. When supplied, they are checked against
    the values encoded in the packet itself.
    """
    decoded = decode_packet(payload_hex)
    if decoded is None:
        return None

    if path_len is not None:
        try:
            if int(path_len) != decoded["path_len"]:
                return None
        except (TypeError, ValueError):
            return None

    if path_hash_size is not None:
        try:
            if int(path_hash_size) != decoded["path_hash_size"]:
                return None
        except (TypeError, ValueError):
            return None

    return decoded["packet_payload_hex"]


# LoRa preset used by the existing Companion analyzer:
# "EU/UK (Narrow), Switzerland"
LORA_SF = 8
LORA_BW_HZ = 62500
LORA_CR_DENOM = 8
LORA_PREAMBLE_SYMBOLS = 8
LORA_CRC_ENABLED = True
LORA_EXPLICIT_HEADER = True


def safe_int(value: Any) -> int | None:
    """Convert a value to int without raising."""
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_received_time_seconds(metadata: dict[str, Any] | None) -> int | None:
    """Extract the QuestDB timestamp in whole Unix seconds from PacketTap metadata."""
    if not metadata:
        return None

    recv_time = safe_int(metadata.get("recv_time"))
    if recv_time is not None:
        return recv_time

    received_unix_ns = safe_int(metadata.get("received_unix_ns"))
    if received_unix_ns is not None:
        return received_unix_ns // 1_000_000_000

    received_utc = metadata.get("received_utc")
    if received_utc:
        try:
            text = str(received_utc).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
        except (TypeError, ValueError, OverflowError):
            return None

    return None


def extract_nodes(
    path_nodes: list[str] | tuple[str, ...] | None,
) -> tuple[str | None, str | None, str | None, list[str]]:
    """Return sender, previous hop, repeater and normalized path nodes."""
    nodes = [str(node) for node in (path_nodes or []) if node is not None]
    sender_node = nodes[0] if len(nodes) >= 1 else None
    repeater = nodes[-1] if len(nodes) >= 1 else None
    prev_hop = nodes[-2] if len(nodes) >= 2 else None
    return sender_node, prev_hop, repeater, nodes


def extract_hop_count(path_len: Any) -> int | None:
    """Convert MeshCore path length to the existing dashboard hop count."""
    value = safe_int(path_len)
    if value is None:
        return None
    return max(0, value - 1)


def calc_lora_airtime_ms(
    payload_bytes: int,
    sf: int = LORA_SF,
    bw_hz: int = LORA_BW_HZ,
    cr_denom: int = LORA_CR_DENOM,
    preamble_symbols: int = LORA_PREAMBLE_SYMBOLS,
    crc_enabled: bool = LORA_CRC_ENABLED,
    explicit_header: bool = LORA_EXPLICIT_HEADER,
) -> float | None:
    """Calculate LoRa airtime using the same formula as mc_rx_analyzer.py."""
    import math

    try:
        if payload_bytes is None or payload_bytes < 0:
            return None

        ih = 0 if explicit_header else 1
        crc = 1 if crc_enabled else 0
        de = 1 if ((2 ** sf) / bw_hz) > 0.016 else 0

        cr_term = cr_denom - 4
        if cr_term < 1 or cr_term > 4:
            return None

        symbol_time = (2 ** sf) / bw_hz
        preamble_time = (preamble_symbols + 4.25) * symbol_time
        numerator = (8 * payload_bytes) - (4 * sf) + 28 + (16 * crc) - (20 * ih)
        denominator = 4 * (sf - (2 * de))
        payload_symbols = 8 + max(
            math.ceil(numerator / denominator) * (cr_term + 4),
            0,
        )
        return (preamble_time + payload_symbols * symbol_time) * 1000.0
    except Exception:
        return None


def decode_mc_rx_record(
    payload_hex: Any,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build the exact argument dictionary expected by ``write_mc_rx()``.

    The returned keys match the existing Companion QuestDB writer so the
    result can later be passed directly with ``await write_mc_rx(**record)``.
    Unknown fields intentionally remain ``None`` until their decoder stage is
    implemented.
    """
    decoded = decode_packet(payload_hex)
    if decoded is None:
        return None

    metadata = metadata or {}
    payload_metadata = decode_payload_metadata(decoded)

    sender_node, prev_hop, repeater_from_path, nodes = extract_nodes(
        decoded["path_nodes"]
    )

    repeater_hint = metadata.get("repeater")
    if repeater_hint is not None:
        repeater_text = str(repeater_hint).strip()
        repeater = repeater_text or repeater_from_path
    else:
        repeater = repeater_from_path

    recv_time = parse_received_time_seconds(metadata)

    # Companion receives pkt_hash directly from RX_LOG_DATA. PacketTap does
    # not expose it, therefore exact compatibility means leaving it None
    # unless a future PacketTap version supplies it in metadata.
    pkt_hash = safe_int(metadata.get("pkt_hash"))

    region_code = None
    region_name = None
    if decoded["payload_type_name"] in {"GRP_TXT", "GRP_DATA"}:
        region_code = decoded.get("transport1")
        region_name = resolve_region(
            region_code,
            decoded["payload_type_name"],
            decoded["packet_payload_hex"],
        )

    return {
        "recv_time": recv_time,
        "payload_type": decoded["payload_type_name"],
        "sender_node": sender_node,
        "prev_hop": prev_hop,
        "repeater": repeater,
        "hop_count": extract_hop_count(decoded["path_len"]),
        "region_code": region_code,
        "region_name": region_name,
        "channel_name": payload_metadata["channel_name"],
        "payload_route_type": decoded["route_type"],
        "pkt_hash": pkt_hash,
        "grp_txt_sender_name": payload_metadata["grp_txt_sender_name"],
        "grp_txt_body": payload_metadata["grp_txt_body"],
        "frame_bits": decoded["frame_bits"],
        "frame_bytes": decoded["frame_bytes"],
        "path_hash_size": decoded["path_hash_size"],
        "airtime_ms": calc_lora_airtime_ms(decoded["frame_bytes"]),
        "nodes": nodes,
        "payload_hex": decoded["payload_hex"],
        "packet_payload_hex": decoded["packet_payload_hex"],
        "packet_payload_sha256": decoded["packet_payload_sha256"],
        "txt_msg_dest_hash": payload_metadata["txt_msg_dest_hash"],
        "txt_msg_src_hash": payload_metadata["txt_msg_src_hash"],

        # PacketTap-specific receive metadata. Companion-originated records
        # keep these values as None.
        "capture_sequence": safe_int(metadata.get("sequence")),
        "rssi_dbm": safe_int(metadata.get("rssi_dbm")),
        "snr_db": (
            float(metadata["snr_db"])
            if metadata.get("snr_db") is not None
            else None
        ),
        "crc_ok": (
            bool(metadata["crc_ok"])
            if metadata.get("crc_ok") is not None
            else None
        ),
        "frame_length": safe_int(metadata.get("frame_length")),
        "received_unix_ns": safe_int(metadata.get("received_unix_ns")),
        "received_utc": (
            str(metadata["received_utc"]).strip()
            if metadata.get("received_utc")
            else None
        ),
        "receiver_time_ns": safe_int(
            metadata.get("receiver_time_ns")
            if metadata.get("receiver_time_ns") is not None
            else metadata.get("received_unix_ns")
        ),
        "receiver_id": (
            str(metadata["receiver_id"]).strip()
            if metadata.get("receiver_id")
            else None
        ),
        "receiver_name": (
            str(metadata["receiver_name"]).strip()
            if metadata.get("receiver_name")
            else None
        ),
        "receiver_type": (
            str(metadata["receiver_type"]).strip()
            if metadata.get("receiver_type")
            else None
        ),
        "receiver_ip": (
            str(metadata["receiver_ip"]).strip()
            if metadata.get("receiver_ip")
            else None
        ),
        "receiver_port": safe_int(metadata.get("receiver_port")),
        "receiver_version": (
            str(metadata["receiver_version"]).strip()
            if metadata.get("receiver_version") is not None
            else None
        ),
        "timestamp_ms": safe_int(metadata.get("timestamp_ms")),
        "packettap_version": safe_int(metadata.get("version")),
        "packettap_flags": safe_int(metadata.get("flags")),
    }