import asyncio
import csv
import hashlib
import hmac
import json
import os
import time
from collections import OrderedDict
from datetime import datetime, UTC

from Crypto.Cipher import AES
from meshcore import MeshCore, EventType
from questdb.ingress import Sender, TimestampNanos

HOST = "10.9.35.65"
PORT = 5000

CSV_FILE = "meshcore_log.csv"
WRITE_TO_CSV = False
DEDUP_CACHE_SIZE = 10000

WRITE_TO_DB = True
QUESTDB_HOST = "localhost"
QUESTDB_PORT = 9000
QUESTDB_TABLE = "meshcore_rx"

PUBLIC_CHANNELS_FILE = "public_channels.json"
UNKNOWN_CHANNELS_FILE = "unknown_channels.csv"
REGIONS_FILE = "regions.json"

DEFAULT_PUBLIC_CHANNEL_NAMES = [
    "#ping",
    "#alt-rover",
    "#bruchsal",
    "#dk0a",
    "#karlsruhe",
    "#test",
]

TARGET_CHANNEL = "#karlsruhe"
LOCAL_NODE = "48"
CLI_SESSION_CACHE_MAX_SIZE = 1000
CLI_SESSION_IDLE_SECONDS = 300
CLI_LOGIN_MIN_PACKETS = 2
CLI_LOGIN_MIN_PAYLOAD = 60
CLI_NEIGHBOR_MIN_PACKETS = 2
CLI_NEIGHBOR_MIN_LARGE_PAYLOAD = 70
CLI_NEIGHBOR_STRONG_MIN_PAYLOAD = 100
CLI_LOGIN_START_MAX_PAYLOAD = 30
GUEST_LOGIN_EPHEMERAL_MIN_LEN = 4

CONNECT_TIMEOUT_SECONDS = 15
IDLE_RECONNECT_SECONDS = 300
WATCHDOG_CHECK_SECONDS = 10
RECONNECT_DELAY_SECONDS = 3

SESSION_CACHE_MAX_SIZE = 5000
SESSION_IDLE_SECONDS = 900

PAYLOAD_TYPE_MAP = {
    "REQ": 0x00,
    "RESPONSE": 0x01,
    "TEXT_MSG": 0x02,
    "ACK": 0x03,
    "ADVERT": 0x04,
    "GRP_TXT": 0x05,
    "GRP_DATA": 0x06,
    "ANON_REQ": 0x07,
    "PATH": 0x08,
    "TRACE": 0x09,
    "MULTIPART": 0x0A,
    "CONTROL": 0x0B,
    "CUSTOM": 0x0F,
}

last_rx_monotonic = None
connection_generation = 0
seen_unknown_channels = set()
last_guest_login = None


def load_region_names():
    if os.path.exists(REGIONS_FILE):
        try:
            with open(REGIONS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, list):
                result = []
                for item in data:
                    if item is None:
                        continue
                    name = str(item).strip()
                    if name:
                        result.append(name)

                if result:
                    print(f"Geladene Regionen aus {REGIONS_FILE}: {len(result)}")
                    return result

        except Exception as exc:
            print(f"Fehler beim Laden von {REGIONS_FILE}: {exc}")

    print("Keine gültige regions.json gefunden, verwende leere Regionsliste.")
    return []


REGION_NAMES = load_region_names()


def calc_region_key(region_name: str) -> bytes:
    return hashlib.sha256(region_name.encode("utf-8")).digest()[:16]


def calc_transport_code_for_region(region_name: str, payload_type_byte: int, pkt_payload_bytes: bytes):
    try:
        region_key = calc_region_key(region_name)
        msg = bytes([payload_type_byte]) + pkt_payload_bytes
        digest = hmac.new(region_key, msg, hashlib.sha256).digest()
        code = int.from_bytes(digest[:2], byteorder="little", signed=False)

        if code in (0x0000, 0xFFFF):
            return None

        return code
    except Exception:
        return None


def extract_transport_codes(payload_hex):
    try:
        if not payload_hex:
            return None, None

        raw = bytes.fromhex(str(payload_hex).strip().lower())

        if len(raw) < 5:
            return None, None

        tc1_hex = raw[1:3][::-1].hex()
        tc2_hex = raw[3:5][::-1].hex()
        return tc1_hex, tc2_hex

    except Exception:
        return None, None


def resolve_region_name(payload_type, pkt_payload_hex, region_code_hex):
    try:
        if not payload_type or not pkt_payload_hex or not region_code_hex:
            return None

        payload_type_byte = PAYLOAD_TYPE_MAP.get(payload_type)
        if payload_type_byte is None:
            return None

        pkt_payload_bytes = bytes.fromhex(str(pkt_payload_hex).strip().lower())
        wanted_code = int(str(region_code_hex).strip().lower(), 16)

        for region_name in REGION_NAMES:
            calc_code = calc_transport_code_for_region(
                region_name=region_name,
                payload_type_byte=payload_type_byte,
                pkt_payload_bytes=pkt_payload_bytes,
            )
            if calc_code == wanted_code:
                return region_name

        return None

    except Exception:
        return None


def load_public_channel_names():
    if os.path.exists(PUBLIC_CHANNELS_FILE):
        try:
            with open(PUBLIC_CHANNELS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, list):
                result = []
                for item in data:
                    if item is None:
                        continue
                    name = str(item).strip()
                    if name:
                        result.append(name)

                if result:
                    print(f"Geladene öffentliche Channels aus {PUBLIC_CHANNELS_FILE}: {len(result)}")
                    return result

        except Exception as exc:
            print(f"Fehler beim Laden von {PUBLIC_CHANNELS_FILE}: {exc}")

    print("Keine gültige public_channels.json gefunden, verwende DEFAULT_PUBLIC_CHANNEL_NAMES.")
    return list(DEFAULT_PUBLIC_CHANNEL_NAMES)


def derive_public_channel_secret(channel_name):
    try:
        channel_name = str(channel_name).strip()
        if not channel_name:
            return None
        return hashlib.sha256(channel_name.encode("utf-8")).hexdigest()[:32]
    except Exception:
        return None


def derive_channel_hash_from_secret(secret_hex):
    try:
        raw = bytes.fromhex(secret_hex)
        return hashlib.sha256(raw).hexdigest()[:2]
    except Exception:
        return None


def build_public_channels_from_names(channel_names):
    mapping = {}
    derived_info = {}

    for channel_name in channel_names:
        secret_hex = derive_public_channel_secret(channel_name)
        if not secret_hex:
            continue

        channel_hash_hex = derive_channel_hash_from_secret(secret_hex)
        if not channel_hash_hex:
            continue

        if channel_hash_hex in mapping and mapping[channel_hash_hex] != channel_name:
            print(
                f"WARNUNG: Hash-Kollision {channel_hash_hex}: "
                f"{mapping[channel_hash_hex]} / {channel_name}"
            )

        mapping[channel_hash_hex] = channel_name
        derived_info[channel_name] = {
            "secret": secret_hex,
            "hash": channel_hash_hex,
        }

    return mapping, derived_info


PUBLIC_CHANNEL_NAMES = load_public_channel_names()
PUBLIC_CHANNELS, PUBLIC_CHANNEL_DERIVED = build_public_channels_from_names(PUBLIC_CHANNEL_NAMES)

if PUBLIC_CHANNEL_DERIVED:
    print("Abgeleitete öffentliche Channel-Daten:")
    for name in sorted(PUBLIC_CHANNEL_DERIVED):
        info = PUBLIC_CHANNEL_DERIVED[name]
        print(f"  {name}: secret={info['secret']} hash={info['hash']}")


def init_unknown_channels_csv():
    if os.path.exists(UNKNOWN_CHANNELS_FILE):
        return

    with open(UNKNOWN_CHANNELS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "first_seen_local",
            "channel_hash_hex",
        ])


def log_unknown_channel(first_seen_local, channel_hash_hex):
    if not channel_hash_hex:
        return

    with open(UNKNOWN_CHANNELS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            first_seen_local,
            channel_hash_hex,
        ])


class GuestSessionTracker:
    def __init__(self, max_size: int = 5000, idle_seconds: int = 900):
        self.max_size = max_size
        self.idle_seconds = idle_seconds
        self.sessions = OrderedDict()

    def _cleanup(self, now_ts: int | None = None):
        if now_ts is None:
            now_ts = int(time.time())

        stale_keys = []
        for key, state in self.sessions.items():
            last_seen = state.get("last_seen")
            if last_seen is not None and (now_ts - last_seen) > self.idle_seconds:
                stale_keys.append(key)

        for key in stale_keys:
            self.sessions.pop(key, None)

        while len(self.sessions) > self.max_size:
            self.sessions.popitem(last=False)

    def update_and_classify(
        self,
        session_key: str | None,
        recv_time: int | None,
        sender_node: str | None,
        direct_neighbor: str | None,
    ):
        if not session_key:
            return {
                "guest_req_type": None,
                "guest_session_packets": None,
                "guest_session_nodes": None,
                "guest_session_last_hops": None,
                "guest_session_duration_s": None,
            }

        now_ts = recv_time if recv_time is not None else int(time.time())
        self._cleanup(now_ts)

        state = self.sessions.get(session_key)
        if state is None:
            state = {
                "first_seen": now_ts,
                "last_seen": now_ts,
                "packet_count": 0,
                "sender_nodes": set(),
                "last_hops": set(),
            }
            self.sessions[session_key] = state
        else:
            self.sessions.move_to_end(session_key)
            state["last_seen"] = now_ts

        state["packet_count"] += 1
        if sender_node:
            state["sender_nodes"].add(sender_node)
        if direct_neighbor:
            state["last_hops"].add(direct_neighbor)

        packet_count = state["packet_count"]
        node_count = len(state["sender_nodes"])
        last_hop_count = len(state["last_hops"])
        duration_s = max(0, state["last_seen"] - state["first_seen"])

        guest_req_type = classify_guest_request_type(
            packet_count=packet_count,
            node_count=node_count,
            last_hop_count=last_hop_count,
            duration_s=duration_s,
        )

        return {
            "guest_req_type": guest_req_type,
            "guest_session_packets": packet_count,
            "guest_session_nodes": node_count,
            "guest_session_last_hops": last_hop_count,
            "guest_session_duration_s": duration_s,
        }


def classify_guest_request_type(packet_count: int, node_count: int, last_hop_count: int, duration_s: int):
    if node_count >= 3 or last_hop_count >= 3:
        return "guest_neighbor_discovery"
    if packet_count >= 8 and node_count <= 2:
        return "guest_repeater_neighbors"
    if packet_count <= 3 and node_count <= 2:
        return "guest_simple_query"
    return "guest_unknown"


guest_session_tracker = GuestSessionTracker(
    max_size=SESSION_CACHE_MAX_SIZE,
    idle_seconds=SESSION_IDLE_SECONDS,
)


def write_to_db(
    recv_time,
    recv_time_local,
    payload_type,
    route_type,
    payload_length,
    path_len,
    path_hash_size,
    sender_node,
    direct_neighbor,
    receiver_node,
    is_direct,
    is_duplicate,
    path,
    from_raw,
    from_ephemeral,
    payload_hex,
    pkt_payload_hex,
    pkt_hash,
    dedup_key,
    channel_hash_hex,
    channel_name,
    channel_label,
    channel_known,
    channel_match,
    region_code,
    region_name,
    msg_text,
    msg_ts,
    msg_ts_local,
    msg_flags,
    msg_mac_ok,
    msg_error,
    msg_sender_name,
    msg_body,
    req_family,
    req_session_key,
    req_sender_is_receiver,
    req_path_signature,
    req_endpoint_pair,
    req_hop_count,
    req_last_hop,
    req_origin_node,
    req_is_guest,
    req_session_kind,
    req_is_to_local,
    guest_target_repeater_hint,
    guest_client_hint,
    guest_req_type,
    guest_session_packets,
    guest_session_nodes,
    guest_session_last_hops,
    guest_session_duration_s,
    cli_session_key,
    cli_session_packets,
    cli_session_max_payload,
    cli_session_duration_s,
    login_start_candidate,
    guest_login_start_candidate,
    guest_login_follow_candidate,
    login_candidate,
    neighbor_list_candidate,
):
    if not WRITE_TO_DB or recv_time is None:
        return

    try:
        symbols = {
            "payload_type": payload_type,
            "route_type": route_type,
            "sender_node": sender_node,
            "direct_neighbor": direct_neighbor,
            "receiver_node": receiver_node,
            "from_raw": from_raw,
            "from_ephemeral": from_ephemeral,
            "dedup_key": dedup_key,
            "channel_hash_hex": channel_hash_hex,
            "channel_name": channel_name,
            "channel_label": channel_label,
            "region_code": region_code,
            "region_name": region_name,
            "msg_sender_name": msg_sender_name,
            "req_family": req_family,
            "req_session_key": req_session_key,
            "req_path_signature": req_path_signature,
            "req_endpoint_pair": req_endpoint_pair,
            "req_last_hop": req_last_hop,
            "req_origin_node": req_origin_node,
            "req_session_kind": req_session_kind,
            "guest_target_repeater_hint": guest_target_repeater_hint,
            "guest_client_hint": guest_client_hint,
            "guest_req_type": guest_req_type,
            "cli_session_key": cli_session_key,
        }
        symbols = {k: v for k, v in symbols.items() if v is not None}

        columns = {
            "recv_time": int(recv_time),
            "recv_time_local": recv_time_local,
            "payload_length": payload_length,
            "path_len": path_len,
            "path_hash_size": path_hash_size,
            "is_direct": is_direct,
            "is_duplicate": is_duplicate,
            "path": path,
            "payload_hex": payload_hex,
            "pkt_payload_hex": pkt_payload_hex,
            "pkt_hash": pkt_hash,
            "channel_known": channel_known,
            "channel_match": channel_match,
            "msg_text": msg_text,
            "msg_ts": msg_ts,
            "msg_ts_local": msg_ts_local,
            "msg_flags": msg_flags,
            "msg_mac_ok": msg_mac_ok,
            "msg_error": msg_error,
            "msg_body": msg_body,
            "req_sender_is_receiver": req_sender_is_receiver,
            "req_hop_count": req_hop_count,
            "req_is_guest": req_is_guest,
            "req_is_to_local": req_is_to_local,
            "guest_session_packets": guest_session_packets,
            "guest_session_nodes": guest_session_nodes,
            "guest_session_last_hops": guest_session_last_hops,
            "guest_session_duration_s": guest_session_duration_s,
            "cli_session_packets": cli_session_packets,
            "cli_session_max_payload": cli_session_max_payload,
            "cli_session_duration_s": cli_session_duration_s,
            "login_start_candidate": login_start_candidate,
            "guest_login_start_candidate": guest_login_start_candidate,
            "guest_login_follow_candidate": guest_login_follow_candidate,
            "login_candidate": login_candidate,
            "neighbor_list_candidate": neighbor_list_candidate,
        }
        columns = {k: v for k, v in columns.items() if v is not None}

        with Sender.from_conf(f"http::addr={QUESTDB_HOST}:{QUESTDB_PORT};") as sender:
            sender.row(
                QUESTDB_TABLE,
                symbols=symbols,
                columns=columns,
                at=TimestampNanos(int(recv_time) * 1_000_000_000),
            )
            sender.flush()

    except Exception as exc:
        print(f"QuestDB write error: {exc}")


def init_csv():
    if not WRITE_TO_CSV:
        return

    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "recv_time", "recv_time_local", "payload_type", "route_type",
                "payload_length", "path_len", "path_hash_size", "sender_node",
                "direct_neighbor", "receiver_node", "is_direct", "is_duplicate",
                "path", "from_raw", "from_ephemeral", "payload_hex", "pkt_payload_hex",
                "pkt_hash", "dedup_key", "channel_hash_hex", "channel_name",
                "channel_label", "channel_known", "channel_match", "region_code",
                "region_name", "msg_text", "msg_ts", "msg_ts_local", "msg_flags",
                "msg_mac_ok", "msg_error", "msg_sender_name", "msg_body",
                "req_family", "req_session_key", "req_sender_is_receiver",
                "req_path_signature", "req_endpoint_pair", "req_hop_count",
                "req_last_hop", "req_origin_node", "req_is_guest", "req_session_kind",
                "req_is_to_local", "guest_target_repeater_hint", "guest_client_hint",
                "guest_req_type", "guest_session_packets", "guest_session_nodes",
                "guest_session_last_hops", "guest_session_duration_s", "cli_session_key",
                "cli_session_packets", "cli_session_max_payload", "cli_session_duration_s",
                "login_start_candidate", "guest_login_start_candidate", "guest_login_follow_candidate",
                "login_candidate", "neighbor_list_candidate",
            ])


def write_csv(row):
    if not WRITE_TO_CSV:
        return
    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)


def fmt_ts(ts: int) -> str:
    try:
        return datetime.fromtimestamp(ts, UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def bool_to_int(value: bool) -> int:
    return 1 if value else 0


def safe_int(value):
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def decode_path(path_hex, hash_size):
    if not path_hex or not hash_size:
        return []
    step = hash_size * 2
    return [path_hex[i:i + step] for i in range(0, len(path_hex), step)]


def extract_nodes(path_hex, hash_size):
    nodes = decode_path(path_hex, hash_size)
    sender_node = nodes[0] if len(nodes) >= 1 else None
    receiver_node = nodes[-1] if len(nodes) >= 1 else None
    direct_neighbor = nodes[-2] if len(nodes) >= 2 else None
    return sender_node, direct_neighbor, receiver_node, nodes


def bytes_to_hex(data):
    if data is None:
        return None
    if isinstance(data, bytes):
        return data.hex()
    return str(data)


def extract_from_fields_by_type(p):
    payload_hex = p.get("payload")
    path_len = p.get("path_len")
    path_hash_size = p.get("path_hash_size", 1)
    payload_type = p.get("payload_typename")

    if not payload_hex or path_len is None:
        return None, None

    try:
        payload_hex = str(payload_hex).strip().lower()
        idx = 2
        idx += path_len * path_hash_size * 2

        if payload_type in {"REQ", "RESPONSE", "TEXT_MSG", "PATH"}:
            from_raw = payload_hex[idx + 2:idx + 4]
            return (from_raw or None), None

        if payload_type == "ANON_REQ":
            idx += 2
            from_ephemeral = payload_hex[idx:idx + 8]
            return None, (from_ephemeral or None)

        return None, None

    except Exception:
        return None, None


def extract_channel_hash(payload_type, payload_hex, path_len, path_hash_size):
    if payload_type not in {"GRP_TXT", "GRP_DATA"}:
        return None
    if not payload_hex or path_len is None or not path_hash_size:
        return None

    try:
        payload_hex = str(payload_hex).strip().lower()
        idx = 12
        idx += int(path_len) * int(path_hash_size) * 2
        if len(payload_hex) < idx + 2:
            return None
        return payload_hex[idx:idx + 2]
    except Exception:
        return None


def resolve_channel(channel_hash_hex):
    if not channel_hash_hex:
        return None, None, 0

    channel_hash_hex = channel_hash_hex.lower()
    channel_name = PUBLIC_CHANNELS.get(channel_hash_hex)
    channel_known = bool_to_int(channel_name is not None)
    channel_label = channel_name if channel_name else f"unknown:{channel_hash_hex}"
    return channel_name, channel_label, channel_known


def maybe_log_unknown_channel(recv_time_local, payload_type, sender_node, path, channel_hash_hex, channel_known):
    global seen_unknown_channels
    if not channel_hash_hex or channel_known == 1 or channel_hash_hex in seen_unknown_channels:
        return
    seen_unknown_channels.add(channel_hash_hex)
    log_unknown_channel(recv_time_local, channel_hash_hex)
    print(
        f"  [NEW UNKNOWN CHANNEL] "
        f"first_seen={recv_time_local} "
        f"type={payload_type} "
        f"sender={sender_node} "
        f"path={path} "
        f"hash={channel_hash_hex}"
    )


def split_group_text(msg_text):
    if not msg_text:
        return None, None
    text = str(msg_text).strip()
    if ": " in text:
        sender_name, body = text.split(": ", 1)
        return sender_name.strip() or None, body.strip() or None
    if ":" in text:
        sender_name, body = text.split(":", 1)
        return sender_name.strip() or None, body.strip() or None
    return None, text


def decrypt_grp_txt(payload_hex, path_len, path_hash_size, channel_name):
    try:
        if not payload_hex or path_len is None or not path_hash_size or not channel_name:
            return None

        secret_hex = derive_public_channel_secret(channel_name)
        if not secret_hex:
            return None

        key = bytes.fromhex(secret_hex)
        payload_hex = str(payload_hex).strip().lower()

        idx = 12
        idx += int(path_len) * int(path_hash_size) * 2

        grp_part_hex = payload_hex[idx:]
        if not grp_part_hex or len(grp_part_hex) < 6:
            return {"ok": False, "error": "grp_part_too_short"}

        grp_part = bytes.fromhex(grp_part_hex)
        rx_channel_hash = grp_part[0]
        rx_cipher_mac = grp_part[1:3]
        ciphertext = grp_part[3:]

        if not ciphertext:
            return {
                "ok": False,
                "error": "empty_ciphertext",
                "channel_hash_hex": f"{rx_channel_hash:02x}",
                "cipher_mac_hex": rx_cipher_mac.hex(),
            }

        if len(ciphertext) % 16 != 0:
            return {
                "ok": False,
                "error": "ciphertext_not_block_aligned",
                "channel_hash_hex": f"{rx_channel_hash:02x}",
                "cipher_mac_hex": rx_cipher_mac.hex(),
                "ciphertext_len": len(ciphertext),
                "ciphertext_hex": ciphertext.hex(),
            }

        calc_mac = hmac.new(key, ciphertext, hashlib.sha256).digest()[:2]
        mac_ok = (calc_mac == rx_cipher_mac)

        cipher = AES.new(key, AES.MODE_ECB)
        plaintext_padded = cipher.decrypt(ciphertext)
        plaintext = plaintext_padded.rstrip(b" ")

        if len(plaintext) < 5:
            return {
                "ok": False,
                "error": "plaintext_too_short",
                "channel_hash_hex": f"{rx_channel_hash:02x}",
                "cipher_mac_hex": rx_cipher_mac.hex(),
                "calc_mac_hex": calc_mac.hex(),
                "mac_ok": bool(mac_ok),
                "plaintext_hex": plaintext.hex(),
            }

        msg_ts = int.from_bytes(plaintext[0:4], byteorder="little", signed=False)
        msg_flags = plaintext[4]
        msg_bytes = plaintext[5:]
        msg_text = msg_bytes.decode("utf-8", errors="replace").strip()

        return {
            "ok": True,
            "channel_hash_hex": f"{rx_channel_hash:02x}",
            "cipher_mac_hex": rx_cipher_mac.hex(),
            "calc_mac_hex": calc_mac.hex(),
            "mac_ok": bool(mac_ok),
            "msg_timestamp": msg_ts,
            "msg_timestamp_local": fmt_ts(msg_ts),
            "msg_flags": msg_flags,
            "msg_text": msg_text,
            "plaintext_hex": plaintext.hex(),
        }

    except Exception as exc:
        return {"ok": False, "error": f"exception:{exc}"}


def classify_req_family(payload_type):
    if payload_type == "ANON_REQ":
        return "guest_request"
    if payload_type == "REQ":
        return "request"
    if payload_type == "RESPONSE":
        return "response"
    return None


def build_req_session_key(payload_type, from_raw, from_ephemeral):
    if payload_type == "ANON_REQ":
        return from_ephemeral
    if payload_type in {"REQ", "RESPONSE"}:
        return from_raw
    return None


def build_req_path_signature(path_len, path):
    if path_len is None and not path:
        return None
    return f"{path_len}:{path}"


def build_req_endpoint_pair(sender_node, receiver_node):
    if not sender_node or not receiver_node:
        return None
    return f"{sender_node}->{receiver_node}"


def build_req_session_kind(payload_type):
    if payload_type == "ANON_REQ":
        return "ephemeral"
    if payload_type in {"REQ", "RESPONSE"}:
        return "raw"
    return None


class CliSessionTracker:
    def __init__(self, max_size: int = 1000, idle_seconds: int = 30):
        self.max_size = max_size
        self.idle_seconds = idle_seconds
        self.sessions = OrderedDict()

    def _cleanup(self, now_ts: int | None = None):
        if now_ts is None:
            now_ts = int(time.time())

        stale_keys = []
        for key, state in self.sessions.items():
            last_seen = state.get("last_seen")
            if last_seen is not None and (now_ts - last_seen) > self.idle_seconds:
                stale_keys.append(key)

        for key in stale_keys:
            self.sessions.pop(key, None)

        while len(self.sessions) > self.max_size:
            self.sessions.popitem(last=False)

    def update(self, session_key: str | None, recv_time: int | None, payload_length: int | None):
        if not session_key:
            return {
                "packet_count": None,
                "max_payload_length": None,
                "duration_s": None,
            }

        now_ts = recv_time if recv_time is not None else int(time.time())
        self._cleanup(now_ts)

        state = self.sessions.get(session_key)
        if state is None:
            state = {
                "first_seen": now_ts,
                "last_seen": now_ts,
                "packet_count": 0,
                "max_payload_length": 0,
            }
            self.sessions[session_key] = state
        else:
            self.sessions.move_to_end(session_key)
            state["last_seen"] = now_ts

        state["packet_count"] += 1
        if payload_length is not None:
            state["max_payload_length"] = max(state["max_payload_length"], payload_length)

        return {
            "packet_count": state["packet_count"],
            "max_payload_length": state["max_payload_length"],
            "duration_s": max(0, state["last_seen"] - state["first_seen"]),
        }


def build_cli_session_key(
    payload_type,
    route_type,
    from_raw,
    sender_node,
    receiver_node,
    path_len,
    req_sender_is_receiver,
):
    if payload_type != "RESPONSE" or route_type != "DIRECT":
        return None
    if not from_raw or not sender_node:
        return None
    if path_len != 1:
        return None
    if req_sender_is_receiver != 1:
        return None
    return f"{from_raw}:{sender_node}:{route_type}"


def is_login_start_candidate(payload_type, from_raw, payload_length, path_len, req_session_key):
    return int(
        payload_type == "RESPONSE"
        and from_raw is not None
        and req_session_key == from_raw
        and payload_length is not None
        and payload_length <= CLI_LOGIN_START_MAX_PAYLOAD
        and path_len == 0
    )


def parse_guest_login_ephemeral(from_ephemeral):
    if not from_ephemeral:
        return None, None
    raw = str(from_ephemeral).strip().lower()
    if len(raw) < GUEST_LOGIN_EPHEMERAL_MIN_LEN:
        return None, None
    repeater_hint = raw[:2]
    client_hint = raw[2:4] if len(raw) >= 4 else None
    return repeater_hint or None, client_hint or None


def is_guest_login_start_candidate(payload_type, route_type, from_ephemeral, req_is_guest, path_len):
    if payload_type != "ANON_REQ":
        return 0
    if route_type != "DIRECT":
        return 0
    if req_is_guest != 1:
        return 0
    if from_ephemeral is None:
        return 0
    if path_len not in (0, None):
        return 0
    repeater_hint, client_hint = parse_guest_login_ephemeral(from_ephemeral)
    return int(repeater_hint is not None and client_hint is not None)


def is_guest_login_follow_candidate(
    payload_type,
    route_type,
    from_raw,
    payload_length,
    pkt_payload_hex,
    recent_guest_login,
):
    if payload_type != "RESPONSE":
        return 0
    if route_type != "FLOOD":
        return 0
    if not from_raw:
        return 0
    if payload_length is None or payload_length > 30:
        return 0
    if not pkt_payload_hex:
        return 0
    if not recent_guest_login:
        return 0

    expected_prefix = f"{recent_guest_login['client']}{recent_guest_login['repeater']}".lower()
    return int(str(pkt_payload_hex).strip().lower().startswith(expected_prefix))


def is_login_candidate(
    payload_type,
    route_type,
    from_raw,
    payload_length,
    path_len,
    req_sender_is_receiver,
    cli_session_packets,
    cli_session_max_payload,
    login_start_candidate,
    guest_login_start_candidate,
    guest_login_follow_candidate,
):
    if login_start_candidate:
        return 1

    if guest_login_start_candidate:
        return 1

    if guest_login_follow_candidate:
        return 1

    if payload_type != "RESPONSE":
        return 0
    if route_type != "DIRECT":
        return 0
    if not from_raw:
        return 0
    if path_len != 1:
        return 0
    if req_sender_is_receiver != 1:
        return 0

    enough_packets = cli_session_packets is not None and cli_session_packets >= CLI_LOGIN_MIN_PACKETS
    large_payload = (
        payload_length is not None and payload_length >= CLI_LOGIN_MIN_PAYLOAD
    ) or (
        cli_session_max_payload is not None and cli_session_max_payload >= CLI_LOGIN_MIN_PAYLOAD
    )
    return int(enough_packets or large_payload)


def is_neighbor_list_candidate(
    payload_type,
    route_type,
    from_raw,
    payload_length,
    path_len,
    req_sender_is_receiver,
    cli_session_packets,
    cli_session_max_payload,
):
    if payload_type != "RESPONSE":
        return 0
    if route_type != "DIRECT":
        return 0
    if not from_raw:
        return 0
    if path_len != 1:
        return 0
    if req_sender_is_receiver != 1:
        return 0

    if payload_length is not None and payload_length >= CLI_NEIGHBOR_STRONG_MIN_PAYLOAD:
        return 1

    enough_packets = cli_session_packets is not None and cli_session_packets >= CLI_NEIGHBOR_MIN_PACKETS
    large_payload = (
        payload_length is not None and payload_length >= CLI_NEIGHBOR_MIN_LARGE_PAYLOAD
    ) or (
        cli_session_max_payload is not None and cli_session_max_payload >= CLI_NEIGHBOR_MIN_LARGE_PAYLOAD
    )
    return int(enough_packets and large_payload)


cli_session_tracker = CliSessionTracker(
    max_size=CLI_SESSION_CACHE_MAX_SIZE,
    idle_seconds=CLI_SESSION_IDLE_SECONDS,
)


class DedupCache:
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._cache = OrderedDict()

    def seen(self, key: str) -> bool:
        if key in self._cache:
            self._cache.move_to_end(key)
            return True
        self._cache[key] = True
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)
        return False


dedup_cache = DedupCache(DEDUP_CACHE_SIZE)


def build_dedup_key(pkt_hash, path, payload_hex, pkt_payload_hex):
    src = {
        "pkt_hash": pkt_hash,
        "path": path,
        "payload_hex": payload_hex,
        "pkt_payload_hex": pkt_payload_hex,
    }
    raw = repr(src).encode("utf-8", errors="ignore")
    return hashlib.sha1(raw).hexdigest()


def mark_rx_activity():
    global last_rx_monotonic
    last_rx_monotonic = time.monotonic()


def seconds_since_last_rx():
    if last_rx_monotonic is None:
        return None
    return time.monotonic() - last_rx_monotonic


async def handle_rx_event(event):
    global connection_generation, last_guest_login

    mark_rx_activity()
    p = event.payload

    recv_time = safe_int(p.get("recv_time"))
    recv_time_local = fmt_ts(recv_time) if recv_time is not None else None

    payload_type = p.get("payload_typename")
    route_type = p.get("route_typename")
    payload_len = safe_int(p.get("payload_length"))

    path = p.get("path")
    hash_size = safe_int(p.get("path_hash_size")) or 1
    path_len = safe_int(p.get("path_len"))

    pkt_hash = safe_int(p.get("pkt_hash"))
    payload_hex = p.get("payload")
    pkt_payload_hex = bytes_to_hex(p.get("pkt_payload"))

    sender_node, direct_neighbor, receiver_node, nodes = extract_nodes(path, hash_size)
    from_raw, from_ephemeral = extract_from_fields_by_type(p)

    channel_hash_hex = extract_channel_hash(
        payload_type=payload_type,
        payload_hex=payload_hex,
        path_len=path_len,
        path_hash_size=hash_size,
    )
    channel_name, channel_label, channel_known = resolve_channel(channel_hash_hex)
    channel_match = bool_to_int(channel_name == TARGET_CHANNEL)

    transport_code_1, transport_code_2 = extract_transport_codes(payload_hex)
    region_code = transport_code_1
    region_name = resolve_region_name(
        payload_type=payload_type,
        pkt_payload_hex=pkt_payload_hex,
        region_code_hex=region_code,
    )

    maybe_log_unknown_channel(
        recv_time_local=recv_time_local,
        payload_type=payload_type,
        sender_node=sender_node,
        path=path,
        channel_hash_hex=channel_hash_hex,
        channel_known=channel_known,
    )

    msg_text = None
    msg_ts = None
    msg_ts_local = None
    msg_flags = None
    msg_mac_ok = None
    msg_error = None
    msg_sender_name = None
    msg_body = None

    req_family = classify_req_family(payload_type)
    req_session_key = build_req_session_key(payload_type, from_raw, from_ephemeral)
    req_sender_is_receiver = bool_to_int(
        sender_node is not None and
        receiver_node is not None and
        sender_node == receiver_node
    ) if req_family else None
    req_path_signature = build_req_path_signature(path_len, path) if req_family else None
    req_endpoint_pair = build_req_endpoint_pair(sender_node, receiver_node) if req_family else None
    req_hop_count = path_len if req_family else None
    req_last_hop = direct_neighbor if req_family else None
    req_origin_node = sender_node if req_family else None
    req_is_guest = bool_to_int(payload_type == "ANON_REQ") if req_family else None
    req_session_kind = build_req_session_kind(payload_type) if req_family else None
    req_is_to_local = bool_to_int(receiver_node == LOCAL_NODE) if req_family and receiver_node is not None else None
    guest_target_repeater_hint, guest_client_hint = parse_guest_login_ephemeral(from_ephemeral)

    guest_req_type = None
    guest_session_packets = None
    guest_session_nodes = None
    guest_session_last_hops = None
    guest_session_duration_s = None

    if payload_type == "ANON_REQ":
        guest_info = guest_session_tracker.update_and_classify(
            session_key=req_session_key,
            recv_time=recv_time,
            sender_node=sender_node,
            direct_neighbor=direct_neighbor,
        )
        guest_req_type = guest_info["guest_req_type"]
        guest_session_packets = guest_info["guest_session_packets"]
        guest_session_nodes = guest_info["guest_session_nodes"]
        guest_session_last_hops = guest_info["guest_session_last_hops"]
        guest_session_duration_s = guest_info["guest_session_duration_s"]

    cli_session_key = build_cli_session_key(
        payload_type=payload_type,
        route_type=route_type,
        from_raw=from_raw,
        sender_node=sender_node,
        receiver_node=receiver_node,
        path_len=path_len,
        req_sender_is_receiver=req_sender_is_receiver,
    )
    cli_session_packets = None
    cli_session_max_payload = None
    cli_session_duration_s = None

    if cli_session_key:
        cli_info = cli_session_tracker.update(
            session_key=cli_session_key,
            recv_time=recv_time,
            payload_length=payload_len,
        )
        cli_session_packets = cli_info["packet_count"]
        cli_session_max_payload = cli_info["max_payload_length"]
        cli_session_duration_s = cli_info["duration_s"]

    guest_login_start_candidate = is_guest_login_start_candidate(
        payload_type=payload_type,
        route_type=route_type,
        from_ephemeral=from_ephemeral,
        req_is_guest=req_is_guest,
        path_len=path_len,
    )

    if guest_login_start_candidate:
        last_guest_login = {
            "ts": recv_time,
            "repeater": guest_target_repeater_hint,
            "client": guest_client_hint,
        }

    recent_guest_login = None
    if last_guest_login and recv_time is not None:
        age = recv_time - last_guest_login["ts"]
        if 0 <= age <= 10:
            recent_guest_login = last_guest_login
        elif age > 10:
            last_guest_login = None

    login_start_candidate = is_login_start_candidate(
        payload_type=payload_type,
        from_raw=from_raw,
        payload_length=payload_len,
        path_len=path_len,
        req_session_key=req_session_key,
    )
    guest_login_follow_candidate = is_guest_login_follow_candidate(
        payload_type=payload_type,
        route_type=route_type,
        from_raw=from_raw,
        payload_length=payload_len,
        pkt_payload_hex=pkt_payload_hex,
        recent_guest_login=recent_guest_login,
    )

    login_candidate = is_login_candidate(
        payload_type=payload_type,
        route_type=route_type,
        from_raw=from_raw,
        payload_length=payload_len,
        path_len=path_len,
        req_sender_is_receiver=req_sender_is_receiver,
        cli_session_packets=cli_session_packets,
        cli_session_max_payload=cli_session_max_payload,
        login_start_candidate=login_start_candidate,
        guest_login_start_candidate=guest_login_start_candidate,
        guest_login_follow_candidate=guest_login_follow_candidate,
    )
    neighbor_list_candidate = is_neighbor_list_candidate(
        payload_type=payload_type,
        route_type=route_type,
        from_raw=from_raw,
        payload_length=payload_len,
        path_len=path_len,
        req_sender_is_receiver=req_sender_is_receiver,
        cli_session_packets=cli_session_packets,
        cli_session_max_payload=cli_session_max_payload,
    )

    if payload_type == "GRP_TXT" and channel_name:
        msg_info = decrypt_grp_txt(
            payload_hex=payload_hex,
            path_len=path_len,
            path_hash_size=hash_size,
            channel_name=channel_name,
        )
        if msg_info:
            msg_text = msg_info.get("msg_text")
            msg_ts = msg_info.get("msg_timestamp")
            msg_ts_local = msg_info.get("msg_timestamp_local")
            msg_flags = msg_info.get("msg_flags")
            msg_mac_ok = msg_info.get("mac_ok")
            msg_error = msg_info.get("error")
            if msg_text:
                msg_sender_name, msg_body = split_group_text(msg_text)
            print(f"  grp_txt_decode={msg_info}")

    is_direct = bool_to_int(
        sender_node is not None and
        direct_neighbor is not None and
        sender_node == direct_neighbor
    )

    dedup_key = build_dedup_key(
        pkt_hash=pkt_hash,
        path=path,
        payload_hex=payload_hex,
        pkt_payload_hex=pkt_payload_hex,
    )

    is_duplicate = bool_to_int(dedup_cache.seen(dedup_key))

    print(
        f"[{recv_time_local}] "
        f"gen={connection_generation} "
        f"type={payload_type} "
        f"route={route_type} "
        f"len={payload_len} "
        f"path_len={path_len} "
        f"hash_size={hash_size} "
        f"sender={sender_node} "
        f"direct_neighbor={direct_neighbor} "
        f"receiver={receiver_node} "
        f"is_direct={is_direct} "
        f"is_duplicate={is_duplicate} "
        f"from={from_raw} "
        f"from_ephemeral={from_ephemeral} "
        f"channel_hash={channel_hash_hex} "
        f"channel_name={channel_name} "
        f"channel_label={channel_label} "
        f"channel_known={channel_known} "
        f"channel_match={channel_match}"
    )

    if login_start_candidate:
        print(
            f"  *** LOGIN_START_CANDIDATE *** "
            f"cli_client={from_raw} req_session_key={req_session_key} "
            f"payload_len={payload_len} path_len={path_len}"
        )

    if guest_login_start_candidate:
        print(
            f"  *** GUEST_LOGIN_START_CANDIDATE *** "
            f"guest_session_key={req_session_key} from_ephemeral={from_ephemeral} "
            f"guest_target_repeater_hint={guest_target_repeater_hint} guest_client_hint={guest_client_hint} "
            f"payload_len={payload_len} path_len={path_len}"
        )

    if guest_login_follow_candidate:
        print(
            f"  *** GUEST_LOGIN_FOLLOW_CANDIDATE *** "
            f"cli_client={from_raw} "
            f"guest_repeater={recent_guest_login['repeater'] if recent_guest_login else None} "
            f"payload_len={payload_len}"
        )

    if login_candidate:
        print(
            f"  *** LOGIN_CANDIDATE *** "
            f"cli_client={from_raw} repeater={sender_node} "
            f"cli_session_key={cli_session_key} packets={cli_session_packets} "
            f"max_payload={cli_session_max_payload} duration_s={cli_session_duration_s}"
        )

    if neighbor_list_candidate:
        print(
            f"  *** NEIGHBOR_LIST_CANDIDATE *** "
            f"cli_client={from_raw} repeater={sender_node} "
            f"cli_session_key={cli_session_key} packets={cli_session_packets} "
            f"max_payload={cli_session_max_payload} duration_s={cli_session_duration_s}"
        )

    print(f"  path={path}")
    print(f"  nodes={nodes}")
    print(f"  payload={payload_hex}")
    print(f"  pkt_payload={pkt_payload_hex}")
    print(f"  pkt_hash={pkt_hash}")
    print(f"  dedup_key={dedup_key}")
    print(f"  transport_code_1={transport_code_1}")
    print(f"  transport_code_2={transport_code_2}")
    print(f"  region_code={region_code}")
    print(f"  region_name={region_name}")
    print(f"  msg_text={msg_text}")
    print(f"  msg_ts={msg_ts} ({msg_ts_local})")
    print(f"  msg_flags={msg_flags}")
    print(f"  msg_mac_ok={msg_mac_ok}")
    print(f"  msg_error={msg_error}")
    print(f"  msg_sender_name={msg_sender_name}")
    print(f"  msg_body={msg_body}")
    print(f"  req_family={req_family}")
    print(f"  req_session_key={req_session_key}")
    print(f"  req_sender_is_receiver={req_sender_is_receiver}")
    print(f"  req_path_signature={req_path_signature}")
    print(f"  req_endpoint_pair={req_endpoint_pair}")
    print(f"  req_hop_count={req_hop_count}")
    print(f"  req_last_hop={req_last_hop}")
    print(f"  req_origin_node={req_origin_node}")
    print(f"  req_is_guest={req_is_guest}")
    print(f"  req_session_kind={req_session_kind}")
    print(f"  req_is_to_local={req_is_to_local}")
    print(f"  guest_target_repeater_hint={guest_target_repeater_hint}")
    print(f"  guest_client_hint={guest_client_hint}")
    print(f"  guest_req_type={guest_req_type}")
    print(f"  guest_session_packets={guest_session_packets}")
    print(f"  guest_session_nodes={guest_session_nodes}")
    print(f"  guest_session_last_hops={guest_session_last_hops}")
    print(f"  guest_session_duration_s={guest_session_duration_s}")
    print(f"  cli_session_key={cli_session_key}")
    print(f"  cli_session_packets={cli_session_packets}")
    print(f"  cli_session_max_payload={cli_session_max_payload}")
    print(f"  cli_session_duration_s={cli_session_duration_s}")
    print(f"  login_start_candidate={login_start_candidate}")
    print(f"  guest_login_start_candidate={guest_login_start_candidate}")
    print(f"  guest_login_follow_candidate={guest_login_follow_candidate}")
    print(f"  login_candidate={login_candidate}")
    print(f"  neighbor_list_candidate={neighbor_list_candidate}")

    write_csv([
        recv_time, recv_time_local, payload_type, route_type, payload_len, path_len,
        hash_size, sender_node, direct_neighbor, receiver_node, is_direct, is_duplicate,
        path, from_raw, from_ephemeral, payload_hex, pkt_payload_hex, pkt_hash, dedup_key,
        channel_hash_hex, channel_name, channel_label, channel_known, channel_match,
        region_code, region_name, msg_text, msg_ts, msg_ts_local, msg_flags, msg_mac_ok,
        msg_error, msg_sender_name, msg_body, req_family, req_session_key,
        req_sender_is_receiver, req_path_signature, req_endpoint_pair, req_hop_count,
        req_last_hop, req_origin_node, req_is_guest, req_session_kind, req_is_to_local,
        guest_target_repeater_hint, guest_client_hint, guest_req_type, guest_session_packets,
        guest_session_nodes, guest_session_last_hops, guest_session_duration_s, cli_session_key,
        cli_session_packets, cli_session_max_payload, cli_session_duration_s,
        login_start_candidate, guest_login_start_candidate, guest_login_follow_candidate,
        login_candidate, neighbor_list_candidate,
    ])

    write_to_db(
        recv_time=recv_time,
        recv_time_local=recv_time_local,
        payload_type=payload_type,
        route_type=route_type,
        payload_length=payload_len,
        path_len=path_len,
        path_hash_size=hash_size,
        sender_node=sender_node,
        direct_neighbor=direct_neighbor,
        receiver_node=receiver_node,
        is_direct=is_direct,
        is_duplicate=is_duplicate,
        path=path,
        from_raw=from_raw,
        from_ephemeral=from_ephemeral,
        payload_hex=payload_hex,
        pkt_payload_hex=pkt_payload_hex,
        pkt_hash=pkt_hash,
        dedup_key=dedup_key,
        channel_hash_hex=channel_hash_hex,
        channel_name=channel_name,
        channel_label=channel_label,
        channel_known=channel_known,
        channel_match=channel_match,
        region_code=region_code,
        region_name=region_name,
        msg_text=msg_text,
        msg_ts=msg_ts,
        msg_ts_local=msg_ts_local,
        msg_flags=msg_flags,
        msg_mac_ok=msg_mac_ok,
        msg_error=msg_error,
        msg_sender_name=msg_sender_name,
        msg_body=msg_body,
        req_family=req_family,
        req_session_key=req_session_key,
        req_sender_is_receiver=req_sender_is_receiver,
        req_path_signature=req_path_signature,
        req_endpoint_pair=req_endpoint_pair,
        req_hop_count=req_hop_count,
        req_last_hop=req_last_hop,
        req_origin_node=req_origin_node,
        req_is_guest=req_is_guest,
        req_session_kind=req_session_kind,
        req_is_to_local=req_is_to_local,
        guest_target_repeater_hint=guest_target_repeater_hint,
        guest_client_hint=guest_client_hint,
        guest_req_type=guest_req_type,
        guest_session_packets=guest_session_packets,
        guest_session_nodes=guest_session_nodes,
        guest_session_last_hops=guest_session_last_hops,
        guest_session_duration_s=guest_session_duration_s,
        cli_session_key=cli_session_key,
        cli_session_packets=cli_session_packets,
        cli_session_max_payload=cli_session_max_payload,
        cli_session_duration_s=cli_session_duration_s,
        login_start_candidate=login_start_candidate,
        guest_login_start_candidate=guest_login_start_candidate,
        guest_login_follow_candidate=guest_login_follow_candidate,
        login_candidate=login_candidate,
        neighbor_list_candidate=neighbor_list_candidate,
    )


async def idle_watchdog(stop_event: asyncio.Event):
    while not stop_event.is_set():
        await asyncio.sleep(WATCHDOG_CHECK_SECONDS)
        idle = seconds_since_last_rx()
        if idle is None:
            continue
        if idle >= IDLE_RECONNECT_SECONDS:
            print(
                f"\n[WATCHDOG] Seit {idle:.1f}s keine RX_LOG_DATA Events mehr "
                f"-> Verbindung wird neu aufgebaut.\n"
            )
            stop_event.set()
            return


async def run_connection_loop():
    global last_rx_monotonic, connection_generation

    while True:
        mesh = None
        sub = None
        watchdog_task = None
        stop_event = asyncio.Event()

        try:
            connection_generation += 1
            current_gen = connection_generation

            print(f"Verbinde zu {HOST}:{PORT} ... (gen={current_gen})")
            mesh = await asyncio.wait_for(
                MeshCore.create_tcp(HOST, PORT),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
            print(f"Verbunden. RX_LOG_DATA abonniert. (gen={current_gen})\n")

            mark_rx_activity()
            sub = mesh.subscribe(EventType.RX_LOG_DATA, handle_rx_event)
            watchdog_task = asyncio.create_task(idle_watchdog(stop_event))

            while not stop_event.is_set():
                await asyncio.sleep(1)

        except asyncio.TimeoutError:
            print(f"Verbindungsaufbau nach {CONNECT_TIMEOUT_SECONDS}s abgebrochen.")
        except Exception as exc:
            print(f"Verbindungsfehler / Laufzeitfehler: {exc}")
        finally:
            if watchdog_task is not None:
                watchdog_task.cancel()
                try:
                    await watchdog_task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass

            if mesh is not None and sub is not None:
                try:
                    mesh.unsubscribe(sub)
                except Exception as exc:
                    print(f"Fehler beim Unsubscribe: {exc}")

            if mesh is not None:
                try:
                    await mesh.disconnect()
                except Exception as exc:
                    print(f"Fehler beim Disconnect: {exc}")

            last_rx_monotonic = None
            print(f"Verbindung geschlossen. Neuer Versuch in {RECONNECT_DELAY_SECONDS}s.\n")
            await asyncio.sleep(RECONNECT_DELAY_SECONDS)


async def main():
    init_csv()
    init_unknown_channels_csv()
    try:
        await run_connection_loop()
    except KeyboardInterrupt:
        print("\nAbbruch durch Benutzer.")


if __name__ == "__main__":
    asyncio.run(main())
