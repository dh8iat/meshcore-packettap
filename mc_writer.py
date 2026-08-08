#!/usr/bin/env python3
"""MeshCore table mapping built on the generic mc_db backend."""

from __future__ import annotations

from typing import Any

from mc_db import execute_sql_async, get_writer, write_row


TABLE_RX = "mc_rx"
TABLE_ADVERT = "mc_advert"
TABLE_NEIGHBOR_DISCOVERY = "mc_neighbor_discovery"
TABLE_REPEATER_NEIGHBORS = "mc_repeater_neighbors"
TABLE_COMPANION_INFO = "mc_companion_info"
TABLE_CONTACTS = "mc_contacts"

MC_RX_OPTIONAL_FIELDS = {
    "capture_sequence",
    "rssi_dbm",
    "snr_db",
    "crc_ok",
    "frame_length",
    "received_unix_ns",
    "received_utc",
    "receiver_time_ns",
    "receiver_id",
    "receiver_name",
    "receiver_type",
    "receiver_ip",
    "receiver_port",
    "receiver_version",
    "timestamp_ms",
    "packettap_version",
    "packettap_flags",
}


MC_RX_REQUIRED_FIELDS = {
    "recv_time",
    "payload_type",
    "sender_node",
    "prev_hop",
    "repeater",
    "hop_count",
    "region_code",
    "region_name",
    "channel_name",
    "payload_route_type",
    "pkt_hash",
    "grp_txt_sender_name",
    "grp_txt_body",
    "frame_bits",
    "frame_bytes",
    "path_hash_size",
    "airtime_ms",
    "nodes",
    "payload_hex",
    "packet_payload_hex",
    "packet_payload_sha256",
    "txt_msg_dest_hash",
    "txt_msg_src_hash",
}


def nodes_to_string(nodes: Any) -> str | None:
    if not nodes:
        return None
    value = ">".join(str(node) for node in nodes if node is not None)
    return value or None


async def clear_contacts_snapshot() -> None:
    writer = get_writer()
    if writer is None:
        return
    await execute_sql_async(
        f"TRUNCATE TABLE {TABLE_CONTACTS}",
        host=writer.host,
        port=writer.port,
        enabled=writer.enabled,
    )


async def write_mc_rx(
    recv_time,
    payload_type,
    sender_node,
    prev_hop,
    repeater,
    hop_count,
    region_code,
    region_name,
    channel_name,
    payload_route_type,
    pkt_hash,
    grp_txt_sender_name,
    grp_txt_body,
    frame_bits,
    frame_bytes,
    path_hash_size,
    airtime_ms,
    nodes,
    payload_hex,
    packet_payload_hex,
    packet_payload_sha256,
    txt_msg_dest_hash,
    txt_msg_src_hash,
    capture_sequence=None,
    rssi_dbm=None,
    snr_db=None,
    crc_ok=None,
    frame_length=None,
    received_unix_ns=None,
    received_utc=None,
    receiver_time_ns=None,
    receiver_id=None,
    receiver_name=None,
    receiver_type=None,
    receiver_ip=None,
    receiver_port=None,
    receiver_version=None,
    timestamp_ms=None,
    packettap_version=None,
    packettap_flags=None,
) -> None:
    await write_row(
        TABLE_RX,
        recv_time,
        symbols={
            "repeater": repeater,
            "prev_hop": prev_hop,
            "sender_node": sender_node,
            "payload_type": payload_type,
            "payload_route_type": payload_route_type,
            "region_code": region_code,
            "region": region_name,
            "channel": channel_name,
            "packet_id": str(pkt_hash) if pkt_hash is not None else None,
            "grp_txt_sender_name": grp_txt_sender_name,
            "packet_payload_sha256": packet_payload_sha256,
            "txt_msg_dest_hash": txt_msg_dest_hash,
            "txt_msg_src_hash": txt_msg_src_hash,
            "receiver_id": receiver_id,
            "receiver_name": receiver_name,
            "receiver_type": receiver_type,
            "receiver_ip": receiver_ip,
            "receiver_version": receiver_version,
        },
        columns={
            "hop_count": hop_count,
            "grp_txt_body": grp_txt_body,
            "frame_bits": frame_bits,
            "frame_bytes": frame_bytes,
            "path_hash_size": path_hash_size,
            "airtime_ms": airtime_ms,
            "nodes": nodes_to_string(nodes),
            "payload_hex": payload_hex,
            "packet_payload_hex": packet_payload_hex,
            "capture_sequence": capture_sequence,
            "rssi_dbm": rssi_dbm,
            "snr_db": snr_db,
            "crc_ok": crc_ok,
            "frame_length": frame_length,
            "received_unix_ns": received_unix_ns,
            "received_utc": received_utc,
            "receiver_time_ns": receiver_time_ns,
            "receiver_port": receiver_port,
            "timestamp_ms": timestamp_ms,
            "packettap_version": packettap_version,
            "packettap_flags": packettap_flags,
        },
    )


async def write_decoded_packet(decoded: dict[str, Any]) -> None:
    """Write a decode_mc_rx_record() result without exposing field plumbing."""
    missing = MC_RX_REQUIRED_FIELDS.difference(decoded)
    if missing:
        raise ValueError(
            "Decoded mc_rx record is missing fields: "
            + ", ".join(sorted(missing))
        )

    values = {
        field: decoded[field]
        for field in MC_RX_REQUIRED_FIELDS
    }
    values.update({
        field: decoded.get(field)
        for field in MC_RX_OPTIONAL_FIELDS
    })

    await write_mc_rx(**values)


async def write_mc_advert(
    recv_time,
    repeater,
    sender_node,
    prev_hop,
    channel_name,
    region_name,
    pkt_hash,
    advert_text,
) -> None:
    await write_row(
        TABLE_ADVERT,
        recv_time,
        symbols={
            "repeater": repeater,
            "sender_node": sender_node,
            "prev_hop": prev_hop,
            "channel": channel_name,
            "region": region_name,
            "packet_id": str(pkt_hash) if pkt_hash is not None else None,
        },
        columns={"advert_text": advert_text},
    )


async def write_mc_neighbor_discovery(
    recv_time,
    repeater,
    sender_node,
    prev_hop,
    channel_name,
    region_name,
    pkt_hash,
) -> None:
    await write_row(
        TABLE_NEIGHBOR_DISCOVERY,
        recv_time,
        symbols={
            "repeater": repeater,
            "sender_node": sender_node,
            "prev_hop": prev_hop,
            "channel": channel_name,
            "region": region_name,
            "packet_id": str(pkt_hash) if pkt_hash is not None else None,
        },
        columns={},
    )


async def write_mc_repeater_neighbors(
    recv_time,
    repeater,
    sender_node,
    prev_hop,
    channel_name,
    region_name,
    pkt_hash,
) -> None:
    await write_row(
        TABLE_REPEATER_NEIGHBORS,
        recv_time,
        symbols={
            "repeater": repeater,
            "sender_node": sender_node,
            "prev_hop": prev_hop,
            "channel": channel_name,
            "region": region_name,
            "packet_id": str(pkt_hash) if pkt_hash is not None else None,
        },
        columns={},
    )


async def write_mc_companion_info(
    recv_time,
    model,
    firmware,
    build,
    noise_floor,
    node_name,
    public_key,
    tcp_connected,
    node_role=None,
) -> None:
    await write_row(
        TABLE_COMPANION_INFO,
        recv_time,
        symbols={
            "model": model,
            "firmware": firmware,
            "build": build,
            "node_name": node_name,
            "public_key": public_key,
            "node_role": node_role,
        },
        columns={
            "noise_floor": noise_floor,
            "tcp_connected": tcp_connected,
        },
    )


async def write_mc_contact(
    recv_time,
    public_key,
    adv_name,
    contact_type,
    flags,
    out_path_hash_mode,
    out_path_len,
    out_path,
    last_advert,
    adv_lat,
    adv_lon,
    lastmod,
) -> None:
    await write_row(
        TABLE_CONTACTS,
        recv_time,
        symbols={
            "public_key": public_key,
            "adv_name": adv_name,
            "contact_type": (
                str(contact_type) if contact_type is not None else None
            ),
            "out_path": out_path,
        },
        columns={
            "flags": flags,
            "out_path_hash_mode": out_path_hash_mode,
            "out_path_len": out_path_len,
            "last_advert": last_advert,
            "adv_lat": adv_lat,
            "adv_lon": adv_lon,
            "lastmod": lastmod,
        },
    )
