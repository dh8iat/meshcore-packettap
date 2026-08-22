#!/usr/bin/env python3
"""
MeshCore PacketTap - Observed Mesh Report v0.41
==============================================

Standortbezogener Mesh-Report auf Basis des bestehenden meshcore-packettap
Datenmodells.

v0.41:
- Netzlastbewertung nach KiekR-Schreibweise in Paketen pro Minute:
    0-5   Pakete/min -> Ruhig
    6-20  Pakete/min -> Aktiv
    >=21  Pakete/min -> Ausgelastet
- Bewertung und Statistik werden minutengenau berechnet.
- Der Zeitverlauf wird für lange Zeiträume automatisch verdichtet, ohne die
  Klassifikation der Einzelminuten zu verändern.
- API-kompatibel zu report_server.py für die dort verwendeten Mesh-Funktionen.
"""

from __future__ import annotations

import argparse
import html
import json
import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import repeater_report as rr

APP_VERSION = "0.41"

QUIET_MAX_PACKETS_PER_MINUTE = 5
ACTIVE_MAX_PACKETS_PER_MINUTE = 20


@dataclass
class LoadMetrics:
    total_packets: int
    period_minutes: float
    period_hours: float
    avg_packets_per_minute: float
    max_packets_per_minute: int
    minutes_quiet: int
    minutes_active: int
    minutes_saturated: int

    # Kompatibilitätswerte für älteren aufrufenden Code.
    @property
    def avg_packets_per_hour(self) -> float:
        return self.avg_packets_per_minute * 60.0

    @property
    def max_packets_per_hour(self) -> int:
        return self.max_packets_per_minute * 60

    @property
    def hours_good(self) -> int:
        return round(self.minutes_quiet / 60)

    @property
    def hours_loaded(self) -> int:
        return round(self.minutes_active / 60)

    @property
    def hours_overloaded(self) -> int:
        return round(self.minutes_saturated / 60)


@dataclass
class RoutingMetrics:
    scoped: int
    unscoped: int
    direct: int
    other: int

    @property
    def classified(self) -> int:
        return self.scoped + self.unscoped + self.direct

    def percent(self, value: int) -> float:
        return 100.0 * value / self.classified if self.classified else 0.0


@dataclass
class UnscopedRepeater:
    public_key: str
    name: str
    packets: int
    max_position: int


@dataclass
class RepeaterActivity:
    public_key: str
    name: str
    packets: int
    percent: float
    max_position: int | None


@dataclass
class DirectNeighbor:
    path_id: str
    public_key: str
    name: str
    packets: int
    percent: float


@dataclass(frozen=True)
class GeoRepeater:
    public_key: str
    name: str
    lat: float
    lon: float


@dataclass
class MeshExtent:
    repeater_count: int
    geo_repeater_count: int
    north: GeoRepeater | None
    south: GeoRepeater | None
    east: GeoRepeater | None
    west: GeoRepeater | None
    north_south_km: float | None
    east_west_km: float | None
    max_pair_km: float | None
    max_pair_names: tuple[str, str] | None


def esc(value: Any) -> str:
    return html.escape(str(value))


def fmt_int(value: int | None) -> str:
    if value is None:
        return "–"
    return f"{value:,}".replace(",", ".")


def fmt_num(value: float, decimals: int = 1) -> str:
    return f"{value:.{decimals}f}".replace(".", ",")


def fmt_pct(value: float) -> str:
    return fmt_num(value, 1) + " %"


def parse_ts(value: Any) -> datetime | None:
    raw = rr.text_value(value)
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def minute_floor(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)


def format_period_de(value: str) -> str:
    dt = parse_ts(value)
    return dt.strftime("%d.%m.%Y") if dt else value


def short_receiver_key(value: str) -> str:
    value = str(value)
    return value if len(value) <= 18 else f"{value[:8]}…{value[-8:]}"


def load_assessment(avg_per_minute: float) -> tuple[str, str]:
    if avg_per_minute <= QUIET_MAX_PACKETS_PER_MINUTE:
        return "positive", "Ruhig"
    if avg_per_minute <= ACTIVE_MAX_PACKETS_PER_MINUTE:
        return "warning", "Aktiv"
    return "critical", "Ausgelastet"


def minute_load_class(packets_per_minute: float) -> tuple[str, str]:
    return load_assessment(packets_per_minute)


def to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0088
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2
    )
    return 2 * radius_km * math.asin(math.sqrt(a))


def load_mesh_rx(
    db: rr.QuestDB,
    period_from: str,
    period_to: str,
    receiver_id: str | None,
    receiver_name: str | None,
) -> list[dict[str, Any]]:
    available = db.table_columns("mc_rx")
    required = {
        "ts", "repeater", "payload_route_type", "hop_count",
        "path_hash_size", "nodes", "receiver_id", "receiver_name",
    }
    missing = required - available
    if missing:
        raise RuntimeError("mc_rx fehlen Spalten: " + ", ".join(sorted(missing)))

    optional = [
        col for col in (
            "airtime_ms", "region", "region_name", "sender_node", "payload_type"
        )
        if col in available
    ]
    where = [rr.time_filter("ts", period_from, period_to)]
    rf = rr.receiver_filter(receiver_id, receiver_name)
    if rf:
        where.append(rf)

    cols = [
        "ts", "repeater", "payload_route_type", "hop_count",
        "path_hash_size", "nodes", "receiver_id", "receiver_name", *optional,
    ]
    sql = f"""
        SELECT {', '.join(cols)}
        FROM mc_rx
        WHERE {' AND '.join(where)}
        ORDER BY ts
    """
    return db.rows(sql)


def load_geo_contacts(db: rr.QuestDB) -> dict[str, GeoRepeater]:
    available = db.table_columns("mc_contacts")
    required = {"ts", "public_key", "adv_lat", "adv_lon"}
    if required - available:
        return {}

    cols = ["ts", "public_key"]
    if "adv_name" in available:
        cols.append("adv_name")
    cols.extend(["adv_lat", "adv_lon"])

    rows = db.rows(f"""
        SELECT {', '.join(cols)}
        FROM mc_contacts
        WHERE public_key IS NOT NULL
        ORDER BY ts
    """)

    latest: dict[str, GeoRepeater] = {}
    for row in rows:
        key = rr.norm(row.get("public_key"))
        if not rr.is_full_public_key(key):
            continue
        lat = to_float(row.get("adv_lat"))
        lon = to_float(row.get("adv_lon"))
        if lat is None or lon is None:
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        if abs(lat) < 1e-6 and abs(lon) < 1e-6:
            continue
        latest[key] = GeoRepeater(
            public_key=key,
            name=rr.text_value(row.get("adv_name")) or "–",
            lat=lat,
            lon=lon,
        )
    return latest


def observer_geo_from_contacts(
    geo_contacts: dict[str, GeoRepeater],
    observer_id: str,
) -> GeoRepeater | None:
    key = rr.norm(observer_id)
    if not rr.is_full_public_key(key):
        return None
    return geo_contacts.get(key)


def filter_geo_by_observer_distance(
    geo_items: list[GeoRepeater],
    observer_geo: GeoRepeater | None,
    max_distance_km: float | None,
) -> tuple[list[GeoRepeater], list[GeoRepeater]]:
    if observer_geo is None or max_distance_km is None:
        return list(geo_items), []
    try:
        limit = float(max_distance_km)
    except (TypeError, ValueError):
        return list(geo_items), []
    if limit <= 0:
        return list(geo_items), []

    accepted = []
    rejected = []
    for item in geo_items:
        if item.public_key == observer_geo.public_key:
            accepted.append(item)
            continue
        distance = haversine_km(
            observer_geo.lat, observer_geo.lon, item.lat, item.lon
        )
        (accepted if distance <= limit else rejected).append(item)
    return accepted, rejected


def load_geo_repeaters(db: rr.QuestDB) -> list[GeoRepeater]:
    available = db.table_columns("mc_contacts")
    required = {"ts", "public_key", "node_role", "adv_lat", "adv_lon"}
    if required - available:
        return []

    rows = db.rows("""
        SELECT ts, public_key, adv_name, node_role, adv_lat, adv_lon
        FROM mc_contacts
        WHERE public_key IS NOT NULL
        ORDER BY ts
    """)

    latest_rows: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = rr.norm(row.get("public_key"))
        if rr.is_full_public_key(key):
            latest_rows[key] = row

    result = []
    for key, row in latest_rows.items():
        if rr.norm(row.get("node_role")) != "repeater":
            continue
        lat = to_float(row.get("adv_lat"))
        lon = to_float(row.get("adv_lon"))
        if lat is None or lon is None:
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        if abs(lat) < 1e-6 and abs(lon) < 1e-6:
            continue
        result.append(
            GeoRepeater(
                key,
                rr.text_value(row.get("adv_name")) or "–",
                lat,
                lon,
            )
        )
    return result


def determine_observer(
    rows: list[dict[str, Any]],
    receiver_id: str | None,
    receiver_name: str | None,
) -> tuple[str, str]:
    if receiver_name:
        name = receiver_name
    else:
        names = sorted({
            rr.text_value(r.get("receiver_name"))
            for r in rows if rr.text_value(r.get("receiver_name"))
        })
        name = ", ".join(names) if names else "(unbekannt)"

    if receiver_id:
        rid = receiver_id
    else:
        ids = sorted({
            rr.text_value(r.get("receiver_id"))
            for r in rows if rr.text_value(r.get("receiver_id"))
        })
        rid = ", ".join(ids) if ids else "(unbekannt)"
    return name, rid


def analyze_load(
    rows: list[dict[str, Any]],
    period_from: str,
    period_to: str,
) -> tuple[LoadMetrics, list[tuple[datetime, int]]]:
    start = parse_ts(period_from)
    end = parse_ts(period_to)
    if start is None or end is None or end < start:
        raise RuntimeError("Ungültiger Beobachtungszeitraum.")

    buckets: Counter[datetime] = Counter()
    for row in rows:
        dt = parse_ts(row.get("ts"))
        if dt is not None:
            buckets[minute_floor(dt)] += 1

    values: list[tuple[datetime, int]] = []
    cursor = minute_floor(start)
    last = minute_floor(end)
    while cursor <= last:
        values.append((cursor, buckets.get(cursor, 0)))
        cursor += timedelta(minutes=1)

    period_minutes = max((end - start).total_seconds() / 60.0, 1 / 60.0)
    avg = len(rows) / period_minutes
    peak = max((count for _, count in values), default=0)

    metrics = LoadMetrics(
        total_packets=len(rows),
        period_minutes=period_minutes,
        period_hours=period_minutes / 60.0,
        avg_packets_per_minute=avg,
        max_packets_per_minute=peak,
        minutes_quiet=sum(
            1 for _, c in values
            if c <= QUIET_MAX_PACKETS_PER_MINUTE
        ),
        minutes_active=sum(
            1 for _, c in values
            if QUIET_MAX_PACKETS_PER_MINUTE < c <= ACTIVE_MAX_PACKETS_PER_MINUTE
        ),
        minutes_saturated=sum(
            1 for _, c in values
            if c > ACTIVE_MAX_PACKETS_PER_MINUTE
        ),
    )
    return metrics, values


def analyze_routing(rows: list[dict[str, Any]]) -> RoutingMetrics:
    scoped = unscoped = direct = other = 0
    for row in rows:
        rt = rr.route_type(row)
        if rt in rr.SCOPED_ROUTE_TYPES:
            scoped += 1
        elif rt in rr.UNSCOPED_ROUTE_TYPES:
            unscoped += 1
        elif rt in rr.DIRECT_ROUTE_TYPES:
            direct += 1
        else:
            other += 1
    return RoutingMetrics(scoped, unscoped, direct, other)


def analyze_repeater_activity(
    rows: list[dict[str, Any]],
    resolver: rr.ContactResolver,
) -> list[RepeaterActivity]:
    counts: Counter[str] = Counter()
    max_pos: dict[str, int] = {}

    for row in rows:
        size = rr.to_int(row.get("path_hash_size"))
        seen: set[str] = set()
        for pos, node in enumerate(rr.parse_nodes(row.get("nodes"))):
            matches = resolver.resolve_path_id(node, size)
            if len(matches) != 1:
                continue
            key = matches[0].public_key
            seen.add(key)
            max_pos[key] = max(pos, max_pos.get(key, pos))
        for key in seen:
            counts[key] += 1

    denom = len(rows) or 1
    result = []
    for key, count in counts.items():
        contact = resolver.exact(key)
        result.append(
            RepeaterActivity(
                key,
                contact.adv_name if contact and contact.adv_name else "–",
                count,
                100.0 * count / denom,
                max_pos.get(key),
            )
        )
    return sorted(
        result,
        key=lambda x: (-x.packets, x.name.lower(), x.public_key),
    )


def analyze_unscoped_far(
    rows: list[dict[str, Any]],
    resolver: rr.ContactResolver,
) -> tuple[int, int, list[UnscopedRepeater], Counter[int]]:
    packets_far = 0
    max_position = 0
    position_counts: Counter[int] = Counter()
    packet_counts: Counter[str] = Counter()
    names: dict[str, str] = {}
    max_by_key: dict[str, int] = {}

    for row in rows:
        if rr.route_type(row) not in rr.UNSCOPED_ROUTE_TYPES:
            continue
        size = rr.to_int(row.get("path_hash_size"))
        seen: set[str] = set()
        found = False
        for pos, node in enumerate(rr.parse_nodes(row.get("nodes"))):
            if pos <= 3:
                continue
            matches = resolver.resolve_path_id(node, size)
            if len(matches) != 1:
                continue
            found = True
            contact = matches[0]
            key = contact.public_key
            names[key] = contact.adv_name or "–"
            seen.add(key)
            max_by_key[key] = max(pos, max_by_key.get(key, pos))
            position_counts[pos] += 1
            max_position = max(max_position, pos)
        if found:
            packets_far += 1
        for key in seen:
            packet_counts[key] += 1

    repeaters = [
        UnscopedRepeater(key, names.get(key, "–"), count, max_by_key[key])
        for key, count in packet_counts.items()
    ]
    repeaters.sort(key=lambda x: (-x.packets, -x.max_position, x.name.lower()))
    return packets_far, max_position, repeaters, position_counts


def analyze_direct_neighbors(
    rows: list[dict[str, Any]],
    resolver: rr.ContactResolver,
) -> list[DirectNeighbor]:
    counts: Counter[str] = Counter()
    for row in rows:
        value = rr.norm(row.get("repeater"))
        if value:
            counts[value] += 1

    denom = sum(counts.values()) or 1
    result = []
    for path_id, count in counts.items():
        public_key = path_id
        name = "–"
        if all(ch in "0123456789abcdef" for ch in path_id) and len(path_id) % 2 == 0:
            matches = resolver.resolve_path_id(path_id, len(path_id) // 2)
            if len(matches) == 1:
                public_key = matches[0].public_key
                name = matches[0].adv_name or "–"
        result.append(
            DirectNeighbor(
                path_id, public_key, name, count, 100.0 * count / denom
            )
        )
    return sorted(result, key=lambda x: (-x.packets, x.name.lower(), x.path_id))


def analyze_extent(
    repeaters: list[RepeaterActivity],
    geo_repeaters: list[GeoRepeater],
) -> tuple[MeshExtent, list[GeoRepeater]]:
    observed_keys = {item.public_key for item in repeaters}
    observed_geo = [g for g in geo_repeaters if g.public_key in observed_keys]

    if not observed_geo:
        return MeshExtent(
            len(repeaters), 0, None, None, None, None,
            None, None, None, None,
        ), []

    north = max(observed_geo, key=lambda g: g.lat)
    south = min(observed_geo, key=lambda g: g.lat)
    east = max(observed_geo, key=lambda g: g.lon)
    west = min(observed_geo, key=lambda g: g.lon)

    ns = haversine_km(south.lat, south.lon, north.lat, north.lon)
    ew = haversine_km(west.lat, west.lon, east.lat, east.lon)

    max_pair_km = 0.0
    max_pair_names = None
    for i, first in enumerate(observed_geo):
        for second in observed_geo[i + 1:]:
            distance = haversine_km(
                first.lat, first.lon, second.lat, second.lon
            )
            if distance > max_pair_km:
                max_pair_km = distance
                max_pair_names = (first.name, second.name)

    return MeshExtent(
        len(repeaters),
        len(observed_geo),
        north,
        south,
        east,
        west,
        ns,
        ew,
        max_pair_km if max_pair_names else None,
        max_pair_names,
    ), observed_geo


def _compact_load_values(
    values: list[tuple[datetime, int]],
    max_bars: int = 240,
) -> tuple[list[tuple[datetime, float]], int]:
    """
    Verdichte lange Minutenreihen für die Anzeige.
    Jeder Balken zeigt den Mittelwert Pakete/min im jeweiligen Zeitblock.
    """
    if not values:
        return [], 1
    group_size = max(1, math.ceil(len(values) / max_bars))
    compact = []
    for start in range(0, len(values), group_size):
        part = values[start:start + group_size]
        avg = sum(count for _, count in part) / len(part)
        compact.append((part[0][0], avg))
    return compact, group_size


def render_load_bar(
    values: list[tuple[datetime, int]],
    max_bars: int = 240,
) -> str:
    if not values:
        return "<p class='muted'>Keine Zeitreihendaten.</p>"

    compact, group_size = _compact_load_values(values, max_bars=max_bars)
    peak = max((value for _, value in compact), default=1.0) or 1.0
    bars = []
    for dt, value in compact:
        height = max(2, round(110 * value / peak))
        cls, label = minute_load_class(value)
        css = {
            "positive": "quiet",
            "warning": "active",
            "critical": "saturated",
        }[cls]
        bars.append(
            f"<div class='bar {css}' style='height:{height}px' "
            f"title='{esc(dt.strftime('%d.%m. %H:%M'))}: "
            f"{fmt_num(value, 1)} Pakete/min · {label}'></div>"
        )

    if group_size == 1:
        unit = "jede Säule = 1 Minute"
    else:
        unit = f"jede Säule = Ø aus {group_size} Minuten"

    return (
        f"<div class='bar-chart'>{''.join(bars)}</div>"
        f"<div class='chart-legend'><span>{esc(unit)}</span>"
        f"<span>Peak Einzelminute: "
        f"{fmt_int(max((count for _, count in values), default=0))} Pakete/min"
        f"</span></div>"
    )


def render_mesh_map(
    repeaters: list[GeoRepeater],
    observer_id: str,
    extent: MeshExtent,
    observer_geo: GeoRepeater | None = None,
) -> str:
    if not repeaters and observer_geo is None:
        return (
            "<div class='map-empty'>Keine Positionsdaten für die im "
            "Beobachtungszeitraum erkannten Repeater oder den "
            "Beobachtungsstandort verfügbar.</div>"
        )

    observer_key = rr.norm(observer_id)
    marker_data = []
    observer_present = False

    for item in repeaters:
        is_observer = observer_key == item.public_key
        observer_present = observer_present or is_observer
        marker_data.append({
            "key": item.public_key,
            "name": item.name,
            "lat": item.lat,
            "lon": item.lon,
            "observer": is_observer,
        })

    if observer_geo is not None and not observer_present:
        marker_data.append({
            "key": observer_geo.public_key,
            "name": observer_geo.name,
            "lat": observer_geo.lat,
            "lon": observer_geo.lon,
            "observer": True,
        })

    payload = json.dumps(marker_data, ensure_ascii=False).replace("</", "<\\/")
    return f"""
    <div id="mesh-report-map" class="leaflet-map"></div>
    <script>
    (function() {{
      const points = {payload};
      const element = document.getElementById("mesh-report-map");
      if (!element || typeof L === "undefined") return;
      const map = L.map("mesh-report-map", {{
        zoomControl:true,
        fadeAnimation:false,
        zoomAnimation:false
      }});
      L.tileLayer(
        "https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png",
        {{maxZoom:19, attribution:"&copy; OpenStreetMap contributors"}}
      ).addTo(map);
      const bounds = [];
      points.forEach(function(p) {{
        const point = [p.lat, p.lon];
        bounds.push(point);
        L.circleMarker(point, {{
          radius:p.observer ? 7 : 5,
          weight:p.observer ? 3 : 2,
          color:p.observer ? "#111" : "#555",
          fillColor:p.observer ? "#fff" : "#777",
          fillOpacity:.85
        }}).addTo(map).bindTooltip(
          "<strong>" + String(p.name || "–") + "</strong>"
          + (p.observer ? "<br>Beobachtungsstandort" : "")
        );
      }});
      if (bounds.length === 1) map.setView(bounds[0], 10);
      else if (bounds.length) map.fitBounds(bounds, {{padding:[24,24],maxZoom:11}});
    }})();
    </script>
    """


def render_html(
    observer_name: str,
    observer_id: str,
    period_from: str,
    period_to: str,
    load: LoadMetrics,
    minute_values: list[tuple[datetime, int]],
    routing: RoutingMetrics,
    repeaters: list[RepeaterActivity],
    unscoped_far_packets: int,
    unscoped_max_position: int,
    unscoped_repeaters: list[UnscopedRepeater],
    position_counts: Counter[int],
    direct_neighbors: list[DirectNeighbor],
    extent: MeshExtent,
    observed_geo: list[GeoRepeater],
    observer_geo: GeoRepeater | None = None,
    site_name: str | None = None,
) -> str:
    observer_display_name = rr.text_value(site_name) or observer_name
    receiver_detail = (
        f"Receiver: {observer_name} · Public Key: {short_receiver_key(observer_id)}"
        if rr.text_value(site_name)
        and rr.norm(site_name) != rr.norm(observer_name)
        else f"Public Key: {short_receiver_key(observer_id)}"
    )

    load_kind, load_label = load_assessment(load.avg_packets_per_minute)
    total_minutes = max(
        1,
        load.minutes_quiet + load.minutes_active + load.minutes_saturated,
    )
    saturated_pct = 100.0 * load.minutes_saturated / total_minutes

    repeater_rows = "".join(
        "<tr>"
        f"<td class='num'>{idx}</td><td><strong>{esc(r.name)}</strong></td>"
        f"<td class='num'>{fmt_int(r.packets)}</td>"
        f"<td class='num'>{fmt_pct(r.percent)}</td>"
        f"<td class='num'>{'–' if r.max_position is None else r.max_position}</td>"
        f"<td class='mono'>{esc(rr.short_key(r.public_key))}</td></tr>"
        for idx, r in enumerate(repeaters[:30], start=1)
    )

    direct_rows = "".join(
        "<tr>"
        f"<td><strong>{esc(r.name)}</strong></td>"
        f"<td class='num'>{fmt_int(r.packets)}</td>"
        f"<td class='num'>{fmt_pct(r.percent)}</td>"
        f"<td class='mono'>{esc(rr.short_key(r.public_key))}</td></tr>"
        for r in direct_neighbors[:20]
    )

    far_pct = (
        100.0 * unscoped_far_packets / routing.unscoped
        if routing.unscoped else 0.0
    )

    return f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/map/leaflet/leaflet.css">
<script src="/map/leaflet/leaflet.js"></script>
<title>Beobachtetes Mesh – {esc(observer_name)}</title>
<style>
:root {{--fg:#171717;--muted:#666;--line:#d9d9d9;--soft:#f5f5f5;--ok:#246b3c;--warn:#9a6200;--critical:#a32622}}
* {{box-sizing:border-box}}
body {{font-family:Arial,Helvetica,sans-serif;color:var(--fg);max-width:1100px;margin:30px auto;padding:0 28px 56px;line-height:1.45}}
.report-brand {{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.09em;font-weight:700}}
.report-type {{margin:5px 0 3px;font-size:2.05rem}}
.report-context-grid,.kpi-grid,.extent-grid,.routing-grid {{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}}
.report-context-grid {{grid-template-columns:1fr 1fr;margin-top:17px}}
.card,.report-context-card {{border:1px solid var(--line);border-radius:9px;padding:14px;background:#fafafa}}
.label,.report-context-label,.subvalue,.muted,.section-intro {{color:var(--muted)}}
.value {{font-size:1.55rem;font-weight:700}}
h2 {{margin-top:34px;border-bottom:1px solid var(--line);padding-bottom:7px}}
table {{width:100%;border-collapse:collapse}}
th,td {{padding:8px 7px;border-bottom:1px solid var(--line);text-align:left}}
th {{background:var(--soft)}}
.num {{text-align:right;white-space:nowrap}}
.mono {{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}}
.assessment {{margin-top:14px;border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:#fafafa}}
.assessment.positive strong {{color:var(--ok)}}
.assessment.warning strong {{color:var(--warn)}}
.assessment.critical strong {{color:var(--critical)}}
.bar-chart {{height:120px;display:flex;gap:2px;align-items:flex-end;border-bottom:1px solid var(--line);padding-top:8px;overflow:hidden}}
.bar {{flex:1 1 0;min-width:2px;background:#8b8b8b;border-radius:2px 2px 0 0}}
.bar.quiet {{background:#7b9b82}}
.bar.active {{background:#b28a35}}
.bar.saturated {{background:#a94a45}}
.chart-legend {{display:flex;justify-content:space-between;color:var(--muted);font-size:.8rem;margin-top:5px}}
.leaflet-map {{width:100%;height:500px;border:1px solid var(--line);border-radius:8px;background:#ececec}}
.footer {{margin-top:36px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:.8rem}}
@media(max-width:800px) {{.kpi-grid,.extent-grid,.routing-grid,.report-context-grid {{grid-template-columns:1fr 1fr}}}}
@media(max-width:520px) {{body {{padding:0 16px 40px}} .kpi-grid,.extent-grid,.routing-grid,.report-context-grid {{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<header>
<div class="report-brand">MESHCORE PACKETTAP</div>
<h1 class="report-type">Mesh-Report</h1>
<div class="report-context-grid">
  <div class="report-context-card">
    <div class="report-context-label">Beobachtungsstandort</div>
    <strong>{esc(observer_display_name)}</strong>
    <div class="subvalue">{esc(receiver_detail)}</div>
  </div>
  <div class="report-context-card">
    <div class="report-context-label">Beobachtungszeitraum</div>
    <strong>{format_period_de(period_from)} – {format_period_de(period_to)}</strong>
    <div class="subvalue">{fmt_num(load.period_hours,1)} h ausgewertet</div>
  </div>
</div>
</header>

<section>
<h2>Ausdehnung des beobachteten Mesh</h2>
<div class="extent-grid">
  <div class="card"><div class="label">Repeater</div><div class="value">{fmt_int(extent.repeater_count)}</div><div class="subvalue">{fmt_int(extent.geo_repeater_count)} mit Koordinaten</div></div>
  <div class="card"><div class="label">Nord–Süd</div><div class="value">{fmt_num(extent.north_south_km,1) + ' km' if extent.north_south_km is not None else '–'}</div></div>
  <div class="card"><div class="label">Ost–West</div><div class="value">{fmt_num(extent.east_west_km,1) + ' km' if extent.east_west_km is not None else '–'}</div></div>
  <div class="card"><div class="label">Größte Distanz</div><div class="value">{fmt_num(extent.max_pair_km,1) + ' km' if extent.max_pair_km is not None else '–'}</div></div>
</div>
<h3>Karte des beobachteten Mesh</h3>
{render_mesh_map(observed_geo, observer_id, extent, observer_geo)}
</section>

<section>
<h2>Netzlast am Beobachtungsstandort</h2>
<p class="section-intro">
  Bewertung nach Paketen pro Minute: 0–5 = Ruhig, 6–20 = Aktiv,
  ab 21 Paketen/min = Ausgelastet.
</p>
<div class="kpi-grid">
  <div class="card"><div class="label">Ø Pakete/min</div><div class="value">{fmt_num(load.avg_packets_per_minute,1)}</div><div class="subvalue">{fmt_num(load.period_hours,1)} h Beobachtungszeit</div></div>
  <div class="card"><div class="label">Peak Pakete/min</div><div class="value">{fmt_int(load.max_packets_per_minute)}</div><div class="subvalue">höchste Einzelminute</div></div>
  <div class="card"><div class="label">Ausgelastete Minuten</div><div class="value">{fmt_int(load.minutes_saturated)}</div><div class="subvalue">{fmt_pct(saturated_pct)} der Minuten</div></div>
  <div class="card"><div class="label">Bewertung Ø-Last</div><div class="value">{esc(load_label)}</div><div class="subvalue">KiekR-Schwellen</div></div>
</div>
<div class="assessment {load_kind}">
  <strong>{esc(load_label)}:</strong>
  Durchschnittlich {fmt_num(load.avg_packets_per_minute,1)} Pakete/min.
  Im Zeitraum: {fmt_int(load.minutes_quiet)} ruhige,
  {fmt_int(load.minutes_active)} aktive und
  {fmt_int(load.minutes_saturated)} ausgelastete Minuten.
</div>
<h3>Netzlast im Zeitverlauf</h3>
{render_load_bar(minute_values)}
</section>

<section>
<h2>Routing-Verhalten</h2>
<div class="routing-grid">
  <div class="card"><div class="label">Scoped</div><div class="value">{fmt_pct(routing.percent(routing.scoped))}</div><div>{fmt_int(routing.scoped)} Pakete</div></div>
  <div class="card"><div class="label">Unscoped</div><div class="value">{fmt_pct(routing.percent(routing.unscoped))}</div><div>{fmt_int(routing.unscoped)} Pakete</div></div>
  <div class="card"><div class="label">Direct</div><div class="value">{fmt_pct(routing.percent(routing.direct))}</div><div>{fmt_int(routing.direct)} Pakete</div></div>
  <div class="card"><div class="label">Sonstige</div><div class="value">{fmt_int(routing.other)}</div></div>
</div>
</section>

<section>
<h2>Weitreichender Unscoped-Verkehr</h2>
<div class="kpi-grid">
  <div class="card"><div class="label">Unscoped gesamt</div><div class="value">{fmt_int(routing.unscoped)}</div></div>
  <div class="card"><div class="label">mit Repeater &gt; Pos. 3</div><div class="value">{fmt_int(unscoped_far_packets)}</div><div class="subvalue">{fmt_pct(far_pct)}</div></div>
  <div class="card"><div class="label">Max. Path-Position</div><div class="value">{fmt_int(unscoped_max_position) if unscoped_repeaters else '–'}</div></div>
  <div class="card"><div class="label">Repeater &gt; Pos. 3</div><div class="value">{fmt_int(len(unscoped_repeaters))}</div></div>
</div>
</section>

<section>
<h2>Repeater im beobachteten Mesh</h2>
<table><thead><tr><th class="num">Rang</th><th>Repeater</th><th class="num">Pakete</th><th class="num">Anteil</th><th class="num">max. Pos.</th><th>Public Key</th></tr></thead>
<tbody>{repeater_rows or '<tr><td colspan="6">Keine Daten.</td></tr>'}</tbody></table>
</section>

<section>
<h2>Direkte Nachbarschaft des Receivers</h2>
<table><thead><tr><th>Repeater</th><th class="num">Pakete</th><th class="num">Anteil</th><th>Public Key / Path-ID</th></tr></thead>
<tbody>{direct_rows or '<tr><td colspan="4">Keine Daten.</td></tr>'}</tbody></table>
</section>

<section>
<h2>Methodik der Auswertung</h2>
<p class="section-intro">
  Die Netzlast wird minutengenau aus den am Beobachtungsstandort empfangenen
  Paketen gebildet. Die Schwellen 0–5 / 6–20 / ≥21 Pakete pro Minute folgen
  der gewünschten KiekR-Schreibweise und sind eine betriebliche Einordnung,
  keine MeshCore-Protokollgrenze.
</p>
</section>

<footer class="footer">MeshCore PacketTap · Mesh-Report v{APP_VERSION}</footer>
</body></html>"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MeshCore PacketTap Observed Mesh Report v0.41"
    )
    p.add_argument("--questdb-host", default=rr.DEFAULT_QUESTDB_HOST)
    p.add_argument("--questdb-port", type=int, default=rr.DEFAULT_QUESTDB_PORT)
    p.add_argument("--from", dest="period_from", type=rr.validate_iso_time, required=True)
    p.add_argument("--to", dest="period_to", type=rr.validate_iso_time, required=True)
    p.add_argument("--receiver-id", default=None)
    p.add_argument("--receiver-name", default=None)
    p.add_argument("--max-geo-distance-km", type=float, default=500.0)
    p.add_argument("--output", default="mesh_report.html")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    db = rr.QuestDB(args.questdb_host, args.questdb_port)

    rows = load_mesh_rx(
        db,
        args.period_from,
        args.period_to,
        args.receiver_id,
        args.receiver_name,
    )
    contacts = rr.load_contacts(db)
    resolver = rr.ContactResolver(contacts)

    observer_name, observer_id = determine_observer(
        rows, args.receiver_id, args.receiver_name
    )
    load, minute_values = analyze_load(
        rows, args.period_from, args.period_to
    )
    routing = analyze_routing(rows)
    repeaters = analyze_repeater_activity(rows, resolver)

    geo_repeaters = load_geo_repeaters(db)
    geo_contacts = load_geo_contacts(db)
    observer_geo = observer_geo_from_contacts(geo_contacts, observer_id)
    geo_repeaters, _ = filter_geo_by_observer_distance(
        geo_repeaters,
        observer_geo,
        args.max_geo_distance_km,
    )
    extent, observed_geo = analyze_extent(repeaters, geo_repeaters)

    far_packets, max_pos, far_repeaters, pos_counts = analyze_unscoped_far(
        rows, resolver
    )
    direct_neighbors = analyze_direct_neighbors(rows, resolver)

    output = render_html(
        observer_name,
        observer_id,
        args.period_from,
        args.period_to,
        load,
        minute_values,
        routing,
        repeaters,
        far_packets,
        max_pos,
        far_repeaters,
        pos_counts,
        direct_neighbors,
        extent,
        observed_geo,
        observer_geo,
    )

    Path(args.output).write_text(output, encoding="utf-8")
    print(f"[MESH] Report geschrieben: {Path(args.output).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
