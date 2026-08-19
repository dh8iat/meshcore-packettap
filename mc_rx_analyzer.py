#!/usr/bin/env python3
"""
MeshCore Companion RX Analyzer - PacketTap-compatible collector

Produktionskandidat für einen MeshCore Companion über TCP.

- RX_LOG_DATA -> gemeinsamer meshcore_decoder
- mc_rx inklusive RSSI/SNR und Receiver-Identität
- mc_contacts ausschließlich aus passiv empfangenen ADVERTs
- mc_contact_observations für ADVERT und DISCOVER_RESP
- mc_companion_info aus Geräte-/Radio-Abfragen
- automatischer Reconnect und RX-Watchdog
"""

import asyncio
import signal
import time
from datetime import datetime, timezone

from meshcore import EventType, MeshCore
from mc_db import QuestDBWriter, configure_writer
from mc_writer import (
    write_decoded_packet,
    write_mc_advert,
    write_mc_companion_info,
    write_mc_contact,
    write_mc_contact_observation,
    write_mc_neighbor_discovery,
    write_mc_repeater_neighbors,
)
from meshcore_decoder import decode_mc_rx_record


# TCP-Ziel des lokalen/entfernten MeshCore-Nodes
HOST = "10.9.35.65"
PORT = 5000

# Globale Schalter für Datenbanknutzung und QuestDB-Verbindung
WRITE_TO_DB = True
QUESTDB_HOST = "localhost"
QUESTDB_PORT = 9000


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


# Merker für die letzte empfangene RX-Aktivität
last_rx_monotonic = None

# Fortlaufende Nummer der aktuellen TCP-Verbindung
connection_generation = 0

# Globaler DB-Writer
db_writer = None

# Letzter bekannter Companion-Stand
seen_contact_public_keys: set[str] = set()

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


async def write_passive_advert_to_contacts(decoded):
    """Write one compact mc_contacts row per observed ADVERT public key/run."""
    if decoded.get("payload_type") != "ADVERT":
        return

    public_key = str(decoded.get("advert_public_key") or "").strip()
    if not public_key or public_key in seen_contact_public_keys:
        return

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
        last_advert=decoded.get("advert_timestamp"),
        adv_lat=decoded.get("advert_lat"),
        adv_lon=decoded.get("advert_lon"),
        lastmod=decoded.get("advert_timestamp"),
        node_role=decoded.get("advert_node_role"),
        source_type="advert",
    )


async def write_passive_contact_observation(decoded):
    """Write historical ADVERT and DISCOVER_RESP observations."""
    payload_type = decoded.get("payload_type")

    if payload_type == "ADVERT":
        public_key = decoded.get("advert_public_key")
        if not public_key:
            return

        await write_mc_contact_observation(
            recv_time=decoded.get("recv_time"),
            public_key=public_key,
            receiver_id=decoded.get("receiver_id"),
            receiver_name=decoded.get("receiver_name"),
            node_role=decoded.get("advert_node_role"),
            hop_count=decoded.get("advert_hop_count"),
            rssi_dbm=decoded.get("rssi_dbm"),
            snr_db=decoded.get("snr_db"),
            region_name=decoded.get("region_name"),
            packet_payload_sha256=decoded.get("packet_payload_sha256"),
            source_type="advert",
        )
        return

    if (
        payload_type == "CONTROL"
        and decoded.get("control_subtype_name") == "DISCOVER_RESP"
    ):
        public_key = decoded.get("control_public_key")
        if not public_key:
            return

        await write_mc_contact_observation(
            recv_time=decoded.get("recv_time"),
            public_key=public_key,
            receiver_id=decoded.get("receiver_id"),
            receiver_name=decoded.get("receiver_name"),
            node_role=decoded.get("control_node_role"),
            hop_count=decoded.get("control_hop_count"),
            rssi_dbm=decoded.get("rssi_dbm"),
            snr_db=decoded.get("snr_db"),
            region_name=decoded.get("region_name"),
            packet_payload_sha256=decoded.get("packet_payload_sha256"),
            source_type="discover_resp",
            discover_snr=decoded.get("control_discover_snr"),
            discover_tag=decoded.get("control_discover_tag"),
            public_key_bytes=decoded.get("control_public_key_bytes"),
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

    recv_time = int(time.time())

    device_info_payload = device_info_event.payload if device_info_event is not None else {}
    stats_radio_payload = stats_radio_event.payload if stats_radio_event is not None else {}
    appstart_payload = appstart_event.payload if appstart_event is not None else {}

    log_verbose(f"[CMD] send_appstart payload: {appstart_payload}")

    model = str(device_info_payload.get("model")).strip() if device_info_payload.get("model") is not None else None
    firmware = str(device_info_payload.get("ver")).strip() if device_info_payload.get("ver") is not None else None
    build = str(device_info_payload.get("fw_build")).strip() if device_info_payload.get("fw_build") is not None else None
    noise_floor = safe_int(stats_radio_payload.get("noise_floor"))

    node_name = appstart_payload.get("name")
    public_key = appstart_payload.get("public_key")

    node_name = str(node_name).strip() if node_name else None
    public_key = str(public_key).strip() if public_key else None
    adv_lat = appstart_payload.get("adv_lat")
    adv_lon = appstart_payload.get("adv_lon")

    # Der eigene Beobachtungsstandort wird einmal pro Prozesslauf als
    # Kontakt-Snapshot eingetragen. Die Herkunft "self" unterscheidet diesen
    # Eintrag bewusst von passiv empfangenen ADVERTs.
    if public_key and public_key not in seen_contact_public_keys:
        seen_contact_public_keys.add(public_key)
        await write_mc_contact(
            recv_time=recv_time,
            public_key=public_key,
            adv_name=node_name,
            contact_type=None,
            flags=None,
            out_path_hash_mode=None,
            out_path_len=None,
            out_path=None,
            last_advert=None,
            adv_lat=adv_lat,
            adv_lon=adv_lon,
            lastmod=None,
            node_role="companion",
            source_type="self",
        )

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
        node_role="companion",
    )
    log_verbose("[DB] Companion-Info geschrieben.")

async def handle_rx_event(event):
    global connection_generation

    mark_rx_activity()
    p = event.payload

    payload_hex = p.get("payload")
    if not payload_hex:
        return

    # Companion RX_LOG_DATA metadata that is not encoded in the raw
    # MeshCore packet itself. Receiver metadata is deliberately added
    # in Companion-v2 step 2.
    metadata = {
        "recv_time": p.get("recv_time"),
        "pkt_hash": p.get("pkt_hash"),
        "repeater": p.get("repeater"),
        "rssi_dbm": p.get("rssi"),
        "snr_db": p.get("snr"),

        # Companion-v2 step 2: identify the observation receiver in every
        # mc_rx row using the information queried from the TCP Companion.
        "receiver_id": last_known_companion_info["public_key"],
        "receiver_name": last_known_companion_info["node_name"],
        "receiver_type": last_known_companion_info["model"],
        "receiver_ip": HOST,
        "receiver_port": PORT,
        "receiver_version": last_known_companion_info["firmware"],
    }

    decoded = decode_mc_rx_record(
        payload_hex=payload_hex,
        metadata=metadata,
    )

    if decoded is None:
        recv_time = safe_int(p.get("recv_time"))
        print(
            f"[{fmt_ts(recv_time)}] "
            f"gen={connection_generation} "
            "WARNUNG: MeshCore-Paket konnte nicht dekodiert werden."
        )
        return

    recv_time = decoded.get("recv_time")
    recv_time_local = fmt_ts(recv_time)

    payload_type = decoded.get("payload_type")
    sender_node = decoded.get("sender_node")
    prev_hop = decoded.get("prev_hop")
    repeater = decoded.get("repeater")
    hop_count = decoded.get("hop_count")
    region_name = decoded.get("region_name")
    channel_name = decoded.get("channel_name")
    grp_txt_sender_name = decoded.get("grp_txt_sender_name")
    grp_txt_body = decoded.get("grp_txt_body")

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
        print(f"  path={p.get('path')}")
        print(f"  nodes={decoded.get('nodes')}")
        print(f"  pkt_hash={decoded.get('pkt_hash')}")
        print(f"  region_code={decoded.get('region_code')}")
        print(f"  transport_code_2={decoded.get('transport2')}")
        print(f"  payload_hex={decoded.get('payload_hex')}")
        print(f"  packet_payload_hex={decoded.get('packet_payload_hex')}")
        print(f"  frame_bytes={decoded.get('frame_bytes')}")
        print(f"  frame_bits={decoded.get('frame_bits')}")
        print(f"  path_hash_size={decoded.get('path_hash_size')}")
        print(f"  airtime_ms={decoded.get('airtime_ms')}")

        if payload_type == "ADVERT":
            print(f"  advert_name={decoded.get('advert_name')}")
            print(f"  advert_role={decoded.get('advert_node_role')}")
            print(f"  advert_public_key={decoded.get('advert_public_key')}")

        if (
            payload_type == "CONTROL"
            and decoded.get("control_subtype_name") == "DISCOVER_RESP"
        ):
            print(f"  discover_role={decoded.get('control_node_role')}")
            print(f"  discover_snr={decoded.get('control_discover_snr')}")
            print(f"  discover_public_key={decoded.get('control_public_key')}")

    # Gemeinsamer QuestDB-Schreibpfad für dekodierte MeshCore-Pakete.
    await write_decoded_packet(decoded)

    # Passive Kontaktbasis und historische Funkbeobachtungen.
    await write_passive_advert_to_contacts(decoded)
    await write_passive_contact_observation(decoded)

    # Bestehende Spezialtabellen für Legacy-Auswertungen weiterführen.
    advert_text = extract_advert_text(payload_type, p)

    if advert_text is not None:
        await write_mc_advert(
            recv_time=recv_time,
            repeater=repeater,
            sender_node=sender_node,
            prev_hop=prev_hop,
            channel_name=channel_name,
            region_name=region_name,
            pkt_hash=decoded.get("pkt_hash"),
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
            pkt_hash=decoded.get("pkt_hash"),
        )

    if is_repeater_neighbors_payload(payload_type, p):
        await write_mc_repeater_neighbors(
            recv_time=recv_time,
            repeater=repeater,
            sender_node=sender_node,
            prev_hop=prev_hop,
            channel_name=channel_name,
            region_name=region_name,
            pkt_hash=decoded.get("pkt_hash"),
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


async def run_connection_loop(shutdown_event: asyncio.Event):
    global last_rx_monotonic, connection_generation

    while not shutdown_event.is_set():
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
            watchdog_task = asyncio.create_task(
                idle_watchdog(mesh, stop_event)
            )

            while not stop_event.is_set() and not shutdown_event.is_set():
                await asyncio.sleep(1)

        except asyncio.TimeoutError:
            if not shutdown_event.is_set():
                print(
                    f"Verbindungsaufbau nach "
                    f"{CONNECT_TIMEOUT_SECONDS}s abgebrochen."
                )
        except asyncio.CancelledError:
            shutdown_event.set()
            raise
        except Exception as exc:
            if not shutdown_event.is_set():
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
                        node_role="companion",
                    )
                    if db_writer is not None:
                        await db_writer.request_flush()
                    log_verbose(
                        "[DB] TCP-Disconnect-Status geschrieben."
                    )
                except Exception as exc:
                    log_verbose(
                        "[DB] Fehler beim Schreiben des "
                        f"Disconnect-Status: {exc}"
                    )

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

        if shutdown_event.is_set():
            print("Verbindung geschlossen. Programm wird beendet.\n")
            break

        print(
            f"Verbindung geschlossen. Neuer Versuch in "
            f"{RECONNECT_DELAY_SECONDS}s.\n"
        )

        try:
            await asyncio.wait_for(
                shutdown_event.wait(),
                timeout=RECONNECT_DELAY_SECONDS,
            )
        except asyncio.TimeoutError:
            pass


async def main():
    global db_writer

    enable_windows_vt_mode()

    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def request_shutdown():
        if not shutdown_event.is_set():
            print("\nShutdown angefordert.")
            shutdown_event.set()

    # Unter Linux/systemd werden SIGINT (Ctrl+C) und SIGTERM sauber in
    # denselben geordneten Shutdown-Pfad überführt.
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_shutdown)
        except (NotImplementedError, RuntimeError):
            # Fallback für Plattformen ohne asyncio-Signalhandler.
            pass

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

        await run_connection_loop(shutdown_event)

    except KeyboardInterrupt:
        request_shutdown()

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

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.remove_signal_handler(sig)
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
