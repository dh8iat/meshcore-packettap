import asyncio
import hashlib
import hmac
import json
import math
import os
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from Crypto.Cipher import AES
from meshcore import EventType, MeshCore
from mc_db import QuestDBWriter, configure_writer
from mc_writer import (
    clear_contacts_snapshot,
    write_mc_advert,
    write_mc_companion_info,
    write_mc_contact,
    write_mc_neighbor_discovery,
    write_mc_repeater_neighbors,
    write_mc_rx,
)


# TCP-Ziel des lokalen/entfernten MeshCore-Nodes
HOST = "10.9.35.65"
PORT = 5000

# Globale Schalter für Datenbanknutzung und QuestDB-Verbindung
WRITE_TO_DB = True
QUESTDB_HOST = "localhost"
QUESTDB_PORT = 9000

# Tabellen in QuestDB
TABLE_RX = "mc_rx"
TABLE_ADVERT = "mc_advert"
TABLE_NEIGHBOR_DISCOVERY = "mc_neighbor_discovery"
TABLE_REPEATER_NEIGHBORS = "mc_repeater_neighbors"
TABLE_COMPANION_INFO = "mc_companion_info"
TABLE_CONTACTS = "mc_contacts"

# Konfigurationsdateien für bekannte öffentliche Channels und Regionen
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PUBLIC_CHANNELS_FILE = os.path.join(BASE_DIR, "public_channels.json")
PUBLIC_CHANNEL_KEYS_FILE = os.path.join(BASE_DIR, "public_channel_keys.json")
REGIONS_FILE = os.path.join(BASE_DIR, "regions.json")

# Konsolen- und Loggingoptionen
ENABLE_COLOR_OUTPUT = True
VERBOSE_LOGGING = False

# Verbindungs- und Watchdog-Parameter
CONNECT_TIMEOUT_SECONDS = 15
IDLE_RECONNECT_SECONDS = 300
WATCHDOG_CHECK_SECONDS = 10
RECONNECT_DELAY_SECONDS = 3
WATCHDOG_DO_PING_BEFORE_RECONNECT = True

# QuestDB Writer
DB_FLUSH_INTERVAL_SECONDS = 2.0
DB_FLUSH_ROW_THRESHOLD = 200
DB_QUEUE_MAXSIZE = 10000
DB_ERROR_LOG_INTERVAL_SECONDS = 15

# LoRa preset: "EU/UK (Narrow), Switzerland"
LORA_SF = 8
LORA_BW_HZ = 62500
LORA_CR_DENOM = 8          # 4/8
LORA_PREAMBLE_SYMBOLS = 8
LORA_CRC_ENABLED = True
LORA_EXPLICIT_HEADER = True

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

# ANSI-Farbcodes und Steuerzeichen dürfen nicht in QuestDB-Line-Protocol-Felder gelangen.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Merker für die letzte empfangene RX-Aktivität
last_rx_monotonic = None

# Fortlaufende Nummer der aktuellen TCP-Verbindung
connection_generation = 0

# Globaler DB-Writer
db_writer = None

# Letzter bekannter Companion-Stand
last_known_companion_info = {
    "model": None,
    "firmware": None,
    "build": None,
    "noise_floor": None,
    "node_name": None,
    "public_key": None,
}




def update_last_known_companion_info(
    model=None,
    firmware=None,
    build=None,
    noise_floor=None,
    node_name=None,
    public_key=None,
):
    global last_known_companion_info

    if model is not None:
        last_known_companion_info["model"] = model
    if firmware is not None:
        last_known_companion_info["firmware"] = firmware
    if build is not None:
        last_known_companion_info["build"] = build
    if noise_floor is not None:
        last_known_companion_info["noise_floor"] = noise_floor
    if node_name is not None:
        last_known_companion_info["node_name"] = node_name
    if public_key is not None:
        last_known_companion_info["public_key"] = public_key


def enable_windows_vt_mode():
    if not ENABLE_COLOR_OUTPUT:
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle == 0 or handle == -1:
            return

        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return

        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def color_text(text, color=None):
    if not ENABLE_COLOR_OUTPUT or color is None:
        return str(text)

    colors = {
        "red": "\033[31m",
        "orange": "\033[33m",
        "cyan": "\033[36m",
        "white": "\033[37m",
        "dim": "\033[90m",
        "reset": "\033[0m",
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def log_verbose(msg):
    if VERBOSE_LOGGING:
        print(msg)


def format_region_for_log(payload_type, region_name):
    if payload_type != "GRP_TXT":
        return region_name
    return color_text(region_name, "orange") if region_name else color_text("None", "red")


def format_channel_for_log(payload_type, channel_name):
    if payload_type != "GRP_TXT":
        return channel_name
    return color_text(channel_name, "orange") if channel_name else color_text("None", "red")


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

    print("Keine gültige public_channels.json gefunden, verwende keine abgeleiteten #-Channels.")
    return []


def load_public_channel_key_entries():
    if os.path.exists(PUBLIC_CHANNEL_KEYS_FILE):
        try:
            with open(PUBLIC_CHANNEL_KEYS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            result = []
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue

                    name = str(item.get("name", "")).strip()
                    key_hex = str(item.get("key_hex", "")).strip().lower()

                    if not name or not key_hex:
                        continue

                    if len(key_hex) != 32:
                        print(f"Ungültige key_hex Länge für {name}: {key_hex}")
                        continue

                    try:
                        bytes.fromhex(key_hex)
                    except ValueError:
                        print(f"Ungültige key_hex für {name}: {key_hex}")
                        continue

                    result.append({
                        "name": name,
                        "key_hex": key_hex,
                    })

            if result:
                print(f"Geladene feste Public-Channel-Keys aus {PUBLIC_CHANNEL_KEYS_FILE}: {len(result)}")
            else:
                print(f"Keine gültigen Einträge in {PUBLIC_CHANNEL_KEYS_FILE} gefunden.")

            return result

        except Exception as exc:
            print(f"Fehler beim Laden von {PUBLIC_CHANNEL_KEYS_FILE}: {exc}")

    print("Keine public_channel_keys.json gefunden, verwende keine festen Channel-Keys.")
    return []


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


def build_public_channels(channel_names, key_entries):
    mapping = {}

    def add_channel(name, secret_hex):
        channel_hash_hex = derive_channel_hash_from_secret(secret_hex)
        if not channel_hash_hex:
            return

        if channel_hash_hex in mapping and mapping[channel_hash_hex]["name"] != name:
            print(
                f"WARNUNG: Hash-Kollision {channel_hash_hex}: "
                f"{mapping[channel_hash_hex]['name']} / {name}"
            )

        mapping[channel_hash_hex] = {
            "name": name,
            "secret_hex": secret_hex,
        }

    for channel_name in channel_names:
        secret_hex = derive_public_channel_secret(channel_name)
        if secret_hex:
            add_channel(channel_name, secret_hex)

    for entry in key_entries:
        add_channel(entry["name"], entry["key_hex"])

    return mapping


REGION_NAMES = load_region_names()
PUBLIC_CHANNEL_NAMES = load_public_channel_names()
PUBLIC_CHANNEL_KEY_ENTRIES = load_public_channel_key_entries()
PUBLIC_CHANNELS = build_public_channels(PUBLIC_CHANNEL_NAMES, PUBLIC_CHANNEL_KEY_ENTRIES)


def fmt_ts(ts: int) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def safe_int(value):
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def bytes_to_hex(data):
    if data is None:
        return None
    if isinstance(data, bytes):
        return data.hex()
    return str(data)


def safe_float(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def clean_db_text(value, max_len=500):
    """
    Bereinigt Texte für QuestDB Line Protocol.

    Entfernt:
    - ANSI-Farbcodes
    - Steuerzeichen
    - Zeilenumbrüche und Tabs
    - leere Strings

    Gibt None zurück, wenn nach der Bereinigung nichts Sinnvolles übrig bleibt.
    """
    if value is None:
        return None

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")

    text = str(value)
    text = ANSI_RE.sub("", text)

    text = "".join(
        ch for ch in text
        if ch.isprintable() and ch not in "\r\n\t"
    )

    text = text.strip()
    if not text:
        return None

    return text[:max_len]


def looks_like_human_text(value, min_ratio=0.85):
    """
    Plausibilitätsprüfung für entschlüsselte GRP_TXT-Inhalte.

    Falsch entschlüsselte Payloads erzeugen häufig ungültige UTF-8-Sequenzen,
    die bei tolerantem Decoding als Unicode-Ersatzzeichen (�) erscheinen.
    Diese Werte dürfen nicht als gültiger Chattext in QuestDB landen.
    """
    if not value:
        return False

    text = str(value)
    if not text:
        return False

    # Unicode replacement character: klares Zeichen für fehlerhaftes Decoding.
    if "�" in text or "�" in text:
        return False

    # Keine Steuerzeichen oder Binärreste erlauben.
    if any(not ch.isprintable() for ch in text):
        return False

    printable = sum(1 for ch in text if ch.isprintable())
    return printable / max(len(text), 1) >= min_ratio


def decode_path(path_hex, hash_size):
    if not path_hex or not hash_size:
        return []
    step = hash_size * 2
    return [path_hex[i:i + step] for i in range(0, len(path_hex), step)]


def extract_nodes(path_hex, hash_size):
    nodes = decode_path(path_hex, hash_size)
    sender_node = nodes[0] if len(nodes) >= 1 else None
    repeater = nodes[-1] if len(nodes) >= 1 else None
    prev_hop = nodes[-2] if len(nodes) >= 2 else None
    return sender_node, prev_hop, repeater, nodes


def nodes_to_string(nodes):
    if not nodes:
        return None
    return ">".join(str(node) for node in nodes if node is not None)


def extract_channel_hash(payload_type, payload_hex, path_len, path_hash_size):
    if payload_type not in {"GRP_TXT", "GRP_DATA"}:
        return None
    if not payload_hex or path_len is None or not path_hash_size:
        return None

    try:
        raw = bytes.fromhex(str(payload_hex).strip().lower())

        if len(raw) < 2:
            return None

        header = raw[0]
        route_type = header & 0x03

        idx = 1

        # Transport Flood / Transport Direct enthalten 4 Byte Transport-Codes.
        # Normale Flood-/Direct-Pakete enthalten diese 4 Byte nicht.
        if route_type in (0x00, 0x03):
            if len(raw) < idx + 4:
                return None
            idx += 4

        # Path-Length-/Path-Header-Byte überspringen.
        if len(raw) < idx + 1:
            return None
        idx += 1

        path_bytes = int(path_len) * int(path_hash_size)
        if len(raw) < idx + path_bytes + 1:
            return None

        idx += path_bytes

        # Bei GRP_TXT/GRP_DATA folgt hier der 1-Byte-Channel-Hash.
        return raw[idx:idx + 1].hex()

    except Exception:
        return None


def resolve_channel(channel_hash_hex):
    if not channel_hash_hex:
        return None
    info = PUBLIC_CHANNELS.get(str(channel_hash_hex).strip().lower())
    return info["name"] if info else None


def get_channel_secret_hex(channel_name):
    if not channel_name:
        return None

    for info in PUBLIC_CHANNELS.values():
        if info["name"] == channel_name:
            return info["secret_hex"]

    return None


def calc_region_key(region_name: str) -> bytes | None:
    try:
        name = str(region_name).strip()
        if not name:
            return None
        return hashlib.sha256(name.encode("utf-8")).digest()[:16]
    except Exception:
        return None


def calc_transport_code_for_region(region_name: str, payload_type_byte: int, pkt_payload_bytes: bytes):
    try:
        region_key = calc_region_key(region_name)
        if region_key is None:
            return None

        msg = bytes([payload_type_byte]) + pkt_payload_bytes
        digest = hmac.new(region_key, msg, hashlib.sha256).digest()
        code = int.from_bytes(digest[:2], byteorder="little", signed=False)

        if code == 0x0000:
            code = 0x0001
        elif code == 0xFFFF:
            code = 0xFFFE

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


def extract_payload_route_type(payload_hex):
    """
    Extrahiert den Route-Type aus dem Payload-Header.

    Die unteren 2 Bits des ersten Payload-Bytes enthalten den Routing-Typ:
    0 = Transport Flood
    1 = Flood
    2 = Direct
    3 = Transport Direct

    Die genaue Interpretation kann je nach MeshCore-Version variieren;
    gespeichert wird deshalb bewusst der Rohwert 0..3.
    """
    if not payload_hex:
        return None

    try:
        raw = bytes.fromhex(str(payload_hex).strip().lower())
        if len(raw) < 1:
            return None
        return raw[0] & 0x03
    except Exception:
        return None


def extract_packet_payload_hex(payload_hex, path_len, path_hash_size):
    if not payload_hex:
        return None

    try:
        payload_hex = str(payload_hex).strip().lower()
        raw = bytes.fromhex(payload_hex)

        if len(raw) < 2:
            return None

        header = raw[0]
        route_type = header & 0x03

        idx = 1
        if route_type in (0x00, 0x03):
            if len(raw) < idx + 4:
                return None
            idx += 4

        if len(raw) < idx + 1:
            return None
        idx += 1

        if path_len is None or path_hash_size is None:
            return None

        path_bytes = int(path_len) * int(path_hash_size)
        if len(raw) < idx + path_bytes:
            return None

        idx += path_bytes
        pkt_payload = raw[idx:]

        if not pkt_payload:
            return None

        return pkt_payload.hex()
    except Exception:
        return None


def short_sha256_hex(value):
    if not value:
        return None
    try:
        return hashlib.sha256(str(value).strip().lower().encode("utf-8")).hexdigest()[:16]
    except Exception:
        return None


def extract_txt_msg_hashes(packet_payload_hex, path_hash_size=1):
    """
    Extrahiert Ziel- und Absender-Hash aus TEXT_MSG.

    MeshCore TXT_MSG Packet-Payload:
    [dest_hash][src_hash][MAC + encrypted data]

    Die Hash-Länge entspricht path_hash_size:
    1, 2 oder 3 Byte.
    """
    if not packet_payload_hex:
        return None, None

    try:
        raw = bytes.fromhex(str(packet_payload_hex).strip().lower())
        size = safe_int(path_hash_size) or 1

        if size not in (1, 2, 3):
            size = 1

        if len(raw) < 2 * size:
            return None, None

        dest_hash = raw[0:size].hex()
        src_hash = raw[size:2 * size].hex()

        return dest_hash or None, src_hash or None
    except Exception:
        return None, None


def decrypt_grp_txt(packet_payload_hex, channel_name):
    if not packet_payload_hex or not channel_name:
        return None, None, None, None

    try:
        secret_hex = get_channel_secret_hex(channel_name)
        if not secret_hex:
            return None, None, None, None

        key = bytes.fromhex(secret_hex)
        grp_part = bytes.fromhex(str(packet_payload_hex).strip().lower())

        if len(grp_part) < 6:
            return None, None, None, None

        ciphertext = grp_part[3:]
        if not ciphertext or len(ciphertext) % 16 != 0:
            return None, None, None, None

        cipher = AES.new(key, AES.MODE_ECB)
        plaintext_padded = cipher.decrypt(ciphertext)
        plaintext_stripped = plaintext_padded.rstrip(b"\x00 ")

        plaintext_hex = plaintext_stripped.hex()

        msg_text = None
        sender_name = None
        body = None

        if len(plaintext_stripped) >= 5:
            msg_bytes = plaintext_stripped[5:].rstrip(b"\x00 ")
            msg_text = msg_bytes.decode("utf-8", errors="strict")
            sender_name, body = split_grp_txt_sender_and_body(msg_text)

        return plaintext_hex, msg_text, sender_name, body
    except Exception:
        return None, None, None, None


def split_grp_txt_sender_and_body(msg_text):
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


def resolve_region(region_code, payload_type, payload_hex):
    if not region_code or not payload_hex or not payload_type:
        return None

    payload_type_byte = PAYLOAD_TYPE_MAP.get(payload_type)
    if payload_type_byte is None:
        return None

    try:
        payload_bytes = bytes.fromhex(payload_hex)
        wanted_code = int(region_code, 16)
    except Exception:
        return None

    for region_name in REGION_NAMES:
        if calc_transport_code_for_region(region_name, payload_type_byte, payload_bytes) == wanted_code:
            return region_name

    return None


def resolve_repeater(event_payload, repeater_from_path):
    repeater_hint = event_payload.get("repeater")
    if repeater_hint is not None:
        repeater_hint = str(repeater_hint).strip()
        return repeater_hint or None

    if repeater_from_path:
        repeater_from_path = str(repeater_from_path).strip()
        return repeater_from_path or None

    return None


def extract_hop_count(path_len):
    if path_len is None:
        return None
    try:
        return max(0, int(path_len) - 1)
    except Exception:
        return None


def extract_advert_text(payload_type, event_payload):
    if payload_type != "ADVERT":
        return None

    for key in ("msg_text", "text", "advert_text", "advert", "message"):
        value = event_payload.get(key)
        if value:
            return str(value)

    pkt_payload = event_payload.get("pkt_payload")
    payload = event_payload.get("payload")

    if pkt_payload is not None:
        return bytes_to_hex(pkt_payload)

    if payload is not None:
        return str(payload)

    return None


def is_neighbor_discovery_payload(payload_type, event_payload):
    if payload_type == "NEIGHBOR_DISCOVERY":
        return True

    subtype = event_payload.get("subtype") or event_payload.get("control_type")
    return bool(subtype and str(subtype).upper() == "NEIGHBOR_DISCOVERY")


def is_repeater_neighbors_payload(payload_type, event_payload):
    if payload_type == "REPEATER_NEIGHBORS":
        return True

    subtype = event_payload.get("subtype") or event_payload.get("control_type")
    return bool(subtype and str(subtype).upper() == "REPEATER_NEIGHBORS")


def calc_lora_airtime_ms(
    payload_bytes: int,
    sf: int = LORA_SF,
    bw_hz: int = LORA_BW_HZ,
    cr_denom: int = LORA_CR_DENOM,
    preamble_symbols: int = LORA_PREAMBLE_SYMBOLS,
    crc_enabled: bool = LORA_CRC_ENABLED,
    explicit_header: bool = LORA_EXPLICIT_HEADER,
) -> float | None:
    try:
        if payload_bytes is None or payload_bytes < 0:
            return None

        ih = 0 if explicit_header else 1
        crc = 1 if crc_enabled else 0

        de = 1 if ((2 ** sf) / bw_hz) > 0.016 else 0

        cr_term = cr_denom - 4
        if cr_term < 1 or cr_term > 4:
            return None

        t_sym = (2 ** sf) / bw_hz
        t_preamble = (preamble_symbols + 4.25) * t_sym

        numerator = (8 * payload_bytes) - (4 * sf) + 28 + (16 * crc) - (20 * ih)
        denominator = 4 * (sf - (2 * de))

        payload_symb_nb = 8 + max(
            math.ceil(numerator / denominator) * (cr_term + 4),
            0
        )

        t_payload = payload_symb_nb * t_sym
        t_packet = t_preamble + t_payload

        return t_packet * 1000.0

    except Exception:
        return None






















def mark_rx_activity():
    global last_rx_monotonic
    last_rx_monotonic = time.monotonic()


def seconds_since_last_rx():
    if last_rx_monotonic is None:
        return None
    return time.monotonic() - last_rx_monotonic


def log_packet_summary(
    recv_time_local,
    payload_type,
    sender_node,
    prev_hop,
    repeater,
    hop_count,
    region_name,
    channel_name,
    grp_txt_sender_name,
    grp_txt_body,
):
    region_display = format_region_for_log(payload_type, region_name)

    log_line = (
        f"[{recv_time_local}] "
        f"gen={connection_generation} "
        f"type={payload_type} "
        f"sender={sender_node} "
        f"prev_hop={prev_hop} "
        f"repeater={repeater} "
        f"hops={hop_count} "
        f"region={region_display}"
    )

    if payload_type == "GRP_TXT":
        channel_display = format_channel_for_log(payload_type, channel_name)
        log_line += f" channel={channel_display}"

    print(log_line)

    if payload_type == "GRP_TXT":
        sender_disp = color_text(grp_txt_sender_name or "None", "cyan" if grp_txt_sender_name else "red")
        body_disp = color_text(grp_txt_body or "None", "white" if grp_txt_body else "red")
        print(f"  ├─ sender: {sender_disp}")
        print(f"  └─ msg   : {body_disp}")


def log_packet_details(
    path,
    nodes,
    pkt_hash,
    region_code,
    transport_code_2,
    payload_hex,
    packet_payload_hex,
    frame_bits,
    frame_bytes,
    path_hash_size,
    airtime_ms,
    grp_txt_plaintext_hex,
    grp_txt_msg_text,
    grp_txt_sender_name,
    grp_txt_body,
    advert_text,
):
    print(f"  path={path}")
    print(f"  nodes={nodes}")
    print(f"  pkt_hash={pkt_hash}")
    print(f"  region_code={region_code}")
    print(f"  transport_code_2={transport_code_2}")
    print(f"  payload_hex={payload_hex}")
    print(f"  packet_payload_hex={packet_payload_hex}")
    print(f"  frame_bytes={frame_bytes}")
    print(f"  frame_bits={frame_bits}")
    print(f"  path_hash_size={path_hash_size}")
    print(f"  airtime_ms={airtime_ms}")
    print(f"  grp_txt_plaintext_hex={grp_txt_plaintext_hex}")
    print(f"  grp_txt_msg_text={grp_txt_msg_text}")
    print(f"  grp_txt_sender_name={grp_txt_sender_name}")
    print(f"  grp_txt_body={grp_txt_body}")
    if advert_text is not None:
        print(f"  advert_text={advert_text}")


def log_contacts_payload(contacts_payload):
    print("\n--- Kontaktliste des TCP-Nodes ---")

    if contacts_payload is None:
        print("Keine Kontaktdaten erhalten.")
        return

    print(f"Payload-Typ: {type(contacts_payload).__name__}")

    if isinstance(contacts_payload, dict):
        print(f"Anzahl Kontakte: {len(contacts_payload)}")
        for key, value in contacts_payload.items():
            print(f"- {key}: {value}")
        return

    if isinstance(contacts_payload, list):
        print(f"Anzahl Kontakte: {len(contacts_payload)}")
        for idx, item in enumerate(contacts_payload, start=1):
            print(f"- [{idx}] {item}")
        return

    print(f"Inhalt: {contacts_payload}")


def count_contacts_payload(contacts_payload):
    if isinstance(contacts_payload, dict):
        return len(contacts_payload)

    if isinstance(contacts_payload, list):
        return len(contacts_payload)

    return 0


async def write_contacts_payload_to_db(contacts_payload, recv_time):
    if not isinstance(contacts_payload, dict):
        return

    await clear_contacts_snapshot()

    for key, value in contacts_payload.items():
        if not isinstance(value, dict):
            continue

        public_key = value.get("public_key") or key
        adv_name = value.get("adv_name")
        contact_type = safe_int(value.get("type"))
        flags = safe_int(value.get("flags"))
        out_path_hash_mode = safe_int(value.get("out_path_hash_mode"))
        out_path_len = safe_int(value.get("out_path_len"))
        out_path = value.get("out_path")
        last_advert = safe_int(value.get("last_advert"))
        lastmod = safe_int(value.get("lastmod"))
        adv_lat = safe_float(value.get("adv_lat"))
        adv_lon = safe_float(value.get("adv_lon"))

        if public_key is not None:
            public_key = str(public_key).strip() or None
        if adv_name is not None:
            adv_name = str(adv_name).strip() or None
        if out_path is not None:
            out_path = str(out_path).strip() or None

        await write_mc_contact(
            recv_time=recv_time,
            public_key=public_key,
            adv_name=adv_name,
            contact_type=contact_type,
            flags=flags,
            out_path_hash_mode=out_path_hash_mode,
            out_path_len=out_path_len,
            out_path=out_path,
            last_advert=last_advert,
            adv_lat=adv_lat,
            adv_lon=adv_lon,
            lastmod=lastmod,
        )


async def call_mesh_command(mesh, command_name, *args, **kwargs):
    try:
        cmd = getattr(mesh.commands, command_name, None)
        if cmd is None:
            print(f"[CMD] {command_name}: nicht verfügbar")
            return None

        result = await cmd(*args, **kwargs)
        log_verbose(f"[CMD] {command_name}: {result}")
        return result

    except Exception as exc:
        print(f"[CMD] {command_name} Fehler: {type(exc).__name__}: {exc}")
        return None


async def query_local_companion(mesh):
    log_verbose("\n--- Lokale Companion-Abfrage ---")

    device_info_event = await call_mesh_command(mesh, "send_device_query")
    stats_radio_event = await call_mesh_command(mesh, "get_stats_radio")
    appstart_event = await call_mesh_command(mesh, "send_appstart")
    contacts_event = await call_mesh_command(mesh, "get_contacts")

    recv_time = int(time.time())

    device_info_payload = device_info_event.payload if device_info_event is not None else {}
    stats_radio_payload = stats_radio_event.payload if stats_radio_event is not None else {}
    appstart_payload = appstart_event.payload if appstart_event is not None else {}
    contacts_payload = contacts_event.payload if contacts_event is not None else None

    log_verbose(f"[CMD] send_appstart payload: {appstart_payload}")
    log_verbose(f"[CMD] get_contacts payload: {contacts_payload}")

    model = str(device_info_payload.get("model")).strip() if device_info_payload.get("model") is not None else None
    firmware = str(device_info_payload.get("ver")).strip() if device_info_payload.get("ver") is not None else None
    build = str(device_info_payload.get("fw_build")).strip() if device_info_payload.get("fw_build") is not None else None
    noise_floor = safe_int(stats_radio_payload.get("noise_floor"))

    node_name = appstart_payload.get("name")
    public_key = appstart_payload.get("public_key")

    node_name = str(node_name).strip() if node_name else None
    public_key = str(public_key).strip() if public_key else None

    update_last_known_companion_info(
        model=model,
        firmware=firmware,
        build=build,
        noise_floor=noise_floor,
        node_name=node_name,
        public_key=public_key,
    )

    await write_mc_companion_info(
        recv_time=recv_time,
        model=model,
        firmware=firmware,
        build=build,
        noise_floor=noise_floor,
        node_name=node_name,
        public_key=public_key,
        tcp_connected=1,
    )
    log_verbose("[DB] Companion-Info geschrieben.")

    if contacts_event is None:
        print("[CONTACTS] Keine Kontaktliste erhalten.")
    else:
        try:
            contact_count = count_contacts_payload(contacts_payload)
            print(f"[CONTACTS] {contact_count} Kontakte eingelesen.")

            if VERBOSE_LOGGING:
                log_contacts_payload(contacts_payload)

            await write_contacts_payload_to_db(contacts_payload, recv_time)

            if db_writer is not None:
                await db_writer.request_flush()

            log_verbose("[DB] Kontakte geschrieben.")
        except Exception as exc:
            print(f"[CONTACTS] Fehler beim Verarbeiten der Kontaktliste: {exc}")


async def handle_rx_event(event):
    global connection_generation

    mark_rx_activity()
    p = event.payload

    recv_time = safe_int(p.get("recv_time"))
    recv_time_local = fmt_ts(recv_time)

    payload_type = p.get("payload_typename")
    path = p.get("path")
    hash_size = safe_int(p.get("path_hash_size")) or 1
    path_len = safe_int(p.get("path_len"))
    pkt_hash = safe_int(p.get("pkt_hash"))
    payload_hex = p.get("payload")

    sender_node, prev_hop, repeater_from_path, nodes = extract_nodes(path, hash_size)
    repeater = resolve_repeater(p, repeater_from_path)
    hop_count = extract_hop_count(path_len)

    frame_bits = None
    frame_bytes = None
    airtime_ms = None
    payload_route_type = None

    if payload_hex:
        try:
            payload_hex = str(payload_hex).strip()
            payload_route_type = extract_payload_route_type(payload_hex)
            frame_bytes = len(payload_hex) // 2
            frame_bits = frame_bytes * 8
            airtime_ms = calc_lora_airtime_ms(payload_bytes=frame_bytes)
        except Exception:
            frame_bits = None
            frame_bytes = None
            airtime_ms = None

    channel_hash_hex = extract_channel_hash(
        payload_type=payload_type,
        payload_hex=payload_hex,
        path_len=path_len,
        path_hash_size=hash_size,
    )
    channel_name = resolve_channel(channel_hash_hex)

    packet_payload_hex = extract_packet_payload_hex(
        payload_hex=payload_hex,
        path_len=path_len,
        path_hash_size=hash_size,
    )

    packet_payload_sha256 = short_sha256_hex(packet_payload_hex)

    txt_msg_dest_hash = None
    txt_msg_src_hash = None

    if payload_type == "TEXT_MSG":
        txt_msg_dest_hash, txt_msg_src_hash = extract_txt_msg_hashes(
            packet_payload_hex=packet_payload_hex,
            path_hash_size=hash_size,
        )

    transport_code_1 = None
    transport_code_2 = None
    region_code = None
    region_name = None
    grp_txt_plaintext_hex = None
    grp_txt_msg_text = None
    grp_txt_sender_name = None
    grp_txt_body = None

    if payload_type == "GRP_TXT" and channel_name:
        (
            grp_txt_plaintext_hex,
            grp_txt_msg_text,
            grp_txt_sender_name,
            grp_txt_body,
        ) = decrypt_grp_txt(
            packet_payload_hex=packet_payload_hex,
            channel_name=channel_name,
        )

        # Falsch entschlüsselte GRP_TXT-Payloads erzeugen oft Binär-/Steuerzeichen.
        # Solche Werte werden nicht geloggt und nicht in QuestDB geschrieben.
        if grp_txt_sender_name:
            grp_txt_sender_name = clean_db_text(grp_txt_sender_name, max_len=200)
            if not looks_like_human_text(grp_txt_sender_name):
                grp_txt_sender_name = None

        if grp_txt_body:
            grp_txt_body = clean_db_text(grp_txt_body, max_len=2000)
            if not looks_like_human_text(grp_txt_body):
                grp_txt_body = None

        if grp_txt_msg_text:
            grp_txt_msg_text = clean_db_text(grp_txt_msg_text, max_len=2000)
            if not looks_like_human_text(grp_txt_msg_text):
                grp_txt_msg_text = None

    if payload_type in {"GRP_TXT", "GRP_DATA"}:
        transport_code_1, transport_code_2 = extract_transport_codes(payload_hex)
        region_code = transport_code_1
        region_name = resolve_region(region_code, payload_type, packet_payload_hex)

    advert_text = extract_advert_text(payload_type, p)

    log_packet_summary(
        recv_time_local=recv_time_local,
        payload_type=payload_type,
        sender_node=sender_node,
        prev_hop=prev_hop,
        repeater=repeater,
        hop_count=hop_count,
        region_name=region_name,
        channel_name=channel_name,
        grp_txt_sender_name=grp_txt_sender_name,
        grp_txt_body=grp_txt_body,
    )

    if VERBOSE_LOGGING:
        log_packet_details(
            path=path,
            nodes=nodes,
            pkt_hash=pkt_hash,
            region_code=region_code,
            transport_code_2=transport_code_2,
            payload_hex=payload_hex,
            packet_payload_hex=packet_payload_hex,
            frame_bits=frame_bits,
            frame_bytes=frame_bytes,
            path_hash_size=hash_size,
            airtime_ms=airtime_ms,
            grp_txt_plaintext_hex=grp_txt_plaintext_hex,
            grp_txt_msg_text=grp_txt_msg_text,
            grp_txt_sender_name=grp_txt_sender_name,
            grp_txt_body=grp_txt_body,
            advert_text=advert_text,
        )

    await write_mc_rx(
        recv_time=recv_time,
        payload_type=payload_type,
        sender_node=sender_node,
        prev_hop=prev_hop,
        repeater=repeater,
        hop_count=hop_count,
        region_code=region_code,
        region_name=region_name,
        channel_name=channel_name,
        payload_route_type=payload_route_type,
        pkt_hash=pkt_hash,
        grp_txt_sender_name=grp_txt_sender_name,
        grp_txt_body=grp_txt_body,
        frame_bits=frame_bits,
        frame_bytes=frame_bytes,
        path_hash_size=hash_size,
        airtime_ms=airtime_ms,
        nodes=nodes,
        payload_hex=payload_hex,
        packet_payload_hex=packet_payload_hex,
        packet_payload_sha256=packet_payload_sha256,
        txt_msg_dest_hash=txt_msg_dest_hash,
        txt_msg_src_hash=txt_msg_src_hash,
    )

    if advert_text is not None:
        await write_mc_advert(
            recv_time=recv_time,
            repeater=repeater,
            sender_node=sender_node,
            prev_hop=prev_hop,
            channel_name=channel_name,
            region_name=region_name,
            pkt_hash=pkt_hash,
            advert_text=advert_text,
        )

    if is_neighbor_discovery_payload(payload_type, p):
        await write_mc_neighbor_discovery(
            recv_time=recv_time,
            repeater=repeater,
            sender_node=sender_node,
            prev_hop=prev_hop,
            channel_name=channel_name,
            region_name=region_name,
            pkt_hash=pkt_hash,
        )

    if is_repeater_neighbors_payload(payload_type, p):
        await write_mc_repeater_neighbors(
            recv_time=recv_time,
            repeater=repeater,
            sender_node=sender_node,
            prev_hop=prev_hop,
            channel_name=channel_name,
            region_name=region_name,
            pkt_hash=pkt_hash,
        )


async def idle_watchdog(mesh, stop_event: asyncio.Event):
    while not stop_event.is_set():
        await asyncio.sleep(WATCHDOG_CHECK_SECONDS)
        idle = seconds_since_last_rx()
        if idle is None:
            continue

        if idle >= IDLE_RECONNECT_SECONDS:
            print(
                f"\n[WATCHDOG] Seit {idle:.1f}s keine RX_LOG_DATA Events mehr "
                f"-> Reconnect wird erzwungen.\n"
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

            await query_local_companion(mesh)

            mark_rx_activity()
            sub = mesh.subscribe(EventType.RX_LOG_DATA, handle_rx_event)
            watchdog_task = asyncio.create_task(idle_watchdog(mesh, stop_event))

            while not stop_event.is_set():
                await asyncio.sleep(1)

        except asyncio.TimeoutError:
            print(f"Verbindungsaufbau nach {CONNECT_TIMEOUT_SECONDS}s abgebrochen.")
        except Exception as exc:
            print(f"Verbindungsfehler / Laufzeitfehler: {exc}")
        finally:
            if mesh is not None:
                try:
                    await write_mc_companion_info(
                        recv_time=int(time.time()),
                        model=last_known_companion_info["model"],
                        firmware=last_known_companion_info["firmware"],
                        build=last_known_companion_info["build"],
                        noise_floor=last_known_companion_info["noise_floor"],
                        node_name=last_known_companion_info["node_name"],
                        public_key=last_known_companion_info["public_key"],
                        tcp_connected=0,
                    )
                    if db_writer is not None:
                        await db_writer.request_flush()
                    log_verbose("[DB] TCP-Disconnect-Status geschrieben.")
                except Exception as exc:
                    log_verbose(f"[DB] Fehler beim Schreiben des Disconnect-Status: {exc}")

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
    global db_writer

    enable_windows_vt_mode()

    db_task = None
    try:
        if WRITE_TO_DB:
            db_writer = QuestDBWriter(
                QUESTDB_HOST,
                QUESTDB_PORT,
                enabled=WRITE_TO_DB,
                flush_interval=DB_FLUSH_INTERVAL_SECONDS,
                flush_row_threshold=DB_FLUSH_ROW_THRESHOLD,
                queue_maxsize=DB_QUEUE_MAXSIZE,
            )
            configure_writer(db_writer)
            db_task = asyncio.create_task(db_writer.run())

        await run_connection_loop()
    except KeyboardInterrupt:
        print("\nAbbruch durch Benutzer.")
    finally:
        if db_writer is not None:
            await db_writer.stop()

        if db_task is not None:
            try:
                await asyncio.wait_for(db_task, timeout=10)
            except asyncio.TimeoutError:
                db_task.cancel()
                try:
                    await db_task
                except asyncio.CancelledError:
                    pass

        configure_writer(None)


if __name__ == "__main__":
    asyncio.run(main())