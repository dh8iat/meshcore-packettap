#!/usr/bin/env python3
"""
MeshCore PacketTap - Observed Mesh Report v0.40
==============================================

Standortbezogener Mesh-Report auf Basis des bestehenden meshcore-packettap
Datenmodells. Der Report beschreibt ausschließlich das Mesh, das am
angegebenen PacketTap-Receiver im gewählten Zeitraum beobachtet wurde.

Abhängigkeiten:
    - Python-Standardbibliothek
    - repeater_report.py im selben Verzeichnis
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

APP_VERSION = "0.40"


@dataclass
class LoadMetrics:
    total_packets: int
    period_hours: float
    avg_packets_per_hour: float
    max_packets_per_hour: int
    hours_good: int
    hours_loaded: int
    hours_overloaded: int


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


def hour_floor(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def format_period_de(value: str) -> str:
    dt = parse_ts(value)
    return dt.strftime("%d.%m.%Y") if dt else value


def load_assessment(avg_per_hour: float) -> tuple[str, str]:
    if avg_per_hour < 1000:
        return "positive", "Gut nutzbar"
    if avg_per_hour <= 1500:
        return "warning", "Belastet"
    return "critical", "Überlastet"


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


def short_receiver_key(value: str) -> str:
    value = str(value)
    return value if len(value) <= 18 else f"{value[:8]}…{value[-8:]}"


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
        col for col in ("airtime_ms", "region", "region_name", "sender_node", "payload_type")
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
    """Load the latest valid coordinates for all contacts, regardless of role."""
    available = db.table_columns("mc_contacts")
    required = {"ts", "public_key", "adv_lat", "adv_lon"}
    missing = required - available
    if missing:
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
    """Resolve the observation site by its configured/detected public key."""
    key = rr.norm(observer_id)
    if not rr.is_full_public_key(key):
        return None
    return geo_contacts.get(key)


def filter_geo_by_observer_distance(
    geo_items: list[GeoRepeater],
    observer_geo: GeoRepeater | None,
    max_distance_km: float | None,
) -> tuple[list[GeoRepeater], list[GeoRepeater]]:
    """Filter implausible map positions without modifying QuestDB raw data."""
    if observer_geo is None or max_distance_km is None:
        return list(geo_items), []

    try:
        limit = float(max_distance_km)
    except (TypeError, ValueError):
        return list(geo_items), []

    if limit <= 0:
        return list(geo_items), []

    accepted: list[GeoRepeater] = []
    rejected: list[GeoRepeater] = []

    for item in geo_items:
        if item.public_key == observer_geo.public_key:
            accepted.append(item)
            continue

        distance = haversine_km(
            observer_geo.lat,
            observer_geo.lon,
            item.lat,
            item.lon,
        )
        (accepted if distance <= limit else rejected).append(item)

    return accepted, rejected


def load_geo_repeaters(db: rr.QuestDB) -> list[GeoRepeater]:
    """Load latest coordinates only for contacts whose current role is repeater."""
    available = db.table_columns("mc_contacts")
    required = {"ts", "public_key", "node_role", "adv_lat", "adv_lon"}
    missing = required - available
    if missing:
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

    result: list[GeoRepeater] = []
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
                public_key=key,
                name=rr.text_value(row.get("adv_name")) or "–",
                lat=lat,
                lon=lon,
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
        names = sorted({rr.text_value(r.get("receiver_name")) for r in rows if rr.text_value(r.get("receiver_name"))})
        name = ", ".join(names) if names else "(unbekannt)"

    if receiver_id:
        rid = receiver_id
    else:
        ids = sorted({rr.text_value(r.get("receiver_id")) for r in rows if rr.text_value(r.get("receiver_id"))})
        rid = ", ".join(ids) if ids else "(unbekannt)"
    return name, rid


def analyze_extent(
    repeaters: list[RepeaterActivity],
    geo_repeaters: list[GeoRepeater],
) -> tuple[MeshExtent, list[GeoRepeater]]:
    observed_keys = {item.public_key for item in repeaters}
    observed_geo = [g for g in geo_repeaters if g.public_key in observed_keys]

    if not observed_geo:
        return MeshExtent(
            repeater_count=len(repeaters),
            geo_repeater_count=0,
            north=None, south=None, east=None, west=None,
            north_south_km=None, east_west_km=None,
            max_pair_km=None, max_pair_names=None,
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
            distance = haversine_km(first.lat, first.lon, second.lat, second.lon)
            if distance > max_pair_km:
                max_pair_km = distance
                max_pair_names = (first.name, second.name)

    return MeshExtent(
        repeater_count=len(repeaters),
        geo_repeater_count=len(observed_geo),
        north=north, south=south, east=east, west=west,
        north_south_km=ns, east_west_km=ew,
        max_pair_km=max_pair_km if max_pair_names else None,
        max_pair_names=max_pair_names,
    ), observed_geo


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
        if dt:
            buckets[hour_floor(dt)] += 1

    values: list[tuple[datetime, int]] = []
    cursor = hour_floor(start)
    last = hour_floor(end)
    while cursor <= last:
        values.append((cursor, buckets.get(cursor, 0)))
        cursor += timedelta(hours=1)

    hours = max((end - start).total_seconds() / 3600.0, 1 / 3600.0)
    avg = len(rows) / hours
    peak = max((count for _, count in values), default=0)
    return (
        LoadMetrics(
            total_packets=len(rows),
            period_hours=hours,
            avg_packets_per_hour=avg,
            max_packets_per_hour=peak,
            hours_good=sum(1 for _, c in values if c < 1000),
            hours_loaded=sum(1 for _, c in values if 1000 <= c <= 1500),
            hours_overloaded=sum(1 for _, c in values if c > 1500),
        ),
        values,
    )


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
    return sorted(result, key=lambda x: (-x.packets, x.name.lower(), x.public_key))


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
        result.append(DirectNeighbor(path_id, public_key, name, count, 100.0 * count / denom))
    return sorted(result, key=lambda x: (-x.packets, x.name.lower(), x.path_id))


def render_load_bar(values: list[tuple[datetime, int]]) -> str:
    if not values:
        return "<p class='muted'>Keine Zeitreihendaten.</p>"
    peak = max((count for _, count in values), default=1) or 1
    bars = []
    for dt, count in values:
        height = max(2, round(110 * count / peak))
        cls = "overloaded" if count > 1500 else "loaded" if count >= 1000 else "good"
        bars.append(
            f"<div class='bar {cls}' style='height:{height}px' "
            f"title='{esc(dt.strftime('%d.%m. %H:%M'))}: {count} Pakete'></div>"
        )
    return (
        f"<div class='bar-chart'>{''.join(bars)}</div>"
        f"<div class='chart-legend'><span>jede Säule = 1 Stunde</span>"
        f"<span>Peak: {fmt_int(peak)} Pakete/h</span></div>"
    )


def render_mesh_map(
    repeaters: list[GeoRepeater],
    observer_id: str,
    extent: MeshExtent,
    observer_geo: GeoRepeater | None = None,
) -> str:
    """Render a Leaflet map with an online OpenStreetMap background."""
    if not repeaters and observer_geo is None:
        return (
            "<div class='map-empty'>Keine Positionsdaten für die im "
            "Beobachtungszeitraum erkannten Repeater oder den "
            "Beobachtungsstandort verfügbar.</div>"
        )

    observer_key = rr.norm(observer_id)
    marker_data = []
    observer_already_present = False

    for item in repeaters:
        is_observer = observer_key == item.public_key
        observer_already_present = observer_already_present or is_observer
        marker_data.append(
            {
                "key": item.public_key,
                "name": item.name,
                "lat": item.lat,
                "lon": item.lon,
                "observer": is_observer,
                "repeater": True,
            }
        )

    if observer_geo is not None and not observer_already_present:
        marker_data.append(
            {
                "key": observer_geo.public_key,
                "name": observer_geo.name,
                "lat": observer_geo.lat,
                "lon": observer_geo.lon,
                "observer": True,
                "repeater": False,
            }
        )

    max_pair = None
    if extent.max_pair_names:
        wanted = set(extent.max_pair_names)
        pair_points = [
            item for item in repeaters
            if item.name in wanted
        ]
        if len(pair_points) >= 2:
            first = pair_points[0]
            second = pair_points[1]
            max_pair = {
                "a": [first.lat, first.lon],
                "b": [second.lat, second.lon],
                "label": (
                    f"{first.name} ↔ {second.name}: "
                    f"{extent.max_pair_km:.1f} km"
                    if extent.max_pair_km is not None
                    else f"{first.name} ↔ {second.name}"
                ),
            }

    payload = json.dumps(
        {
            "markers": marker_data,
            "max_pair": max_pair,
        },
        ensure_ascii=False,
    ).replace("</", "<\\/")

    return f"""
    <div class="offline-map-shell">
      <div class="map-search">
        <label for="mesh-map-search">Repeater suchen</label>
        <div class="map-search-row">
          <input id="mesh-map-search" type="search"
                 placeholder="Repeater suchen – Name oder Public Key"
                 autocomplete="off">
          <button id="mesh-map-search-reset" type="button"
                  class="map-search-reset">Zurücksetzen</button>
        </div>
        <div id="mesh-map-suggestions" class="map-search-suggestions"></div>
        <div id="mesh-map-search-status" class="map-search-status"></div>
      </div>
      <div id="mesh-map" class="leaflet-map"></div>
      <div class="map-note">
        Kartenhintergrund: OpenStreetMap. Die Reportdaten und Repeater-Markierungen
        stammen weiterhin lokal aus PacketTap/QuestDB. Für den Kartenhintergrund
        ist beim Öffnen des Reports eine Internetverbindung erforderlich.
      </div>
    </div>
    <script>
    (function() {{
      const data = {payload};
      const mapElement = document.getElementById("mesh-map");

      if (typeof L === "undefined") {{
        mapElement.innerHTML =
          "<div class='map-error'>Leaflet wurde nicht geladen. " +
          "Prüfe <code>map/leaflet/</code> und den Report Server.</div>";
        return;
      }}

      const map = L.map("mesh-map", {{
        zoomControl: true,
        attributionControl: true,
        preferCanvas: true,
        fadeAnimation: false,
        zoomAnimation: false
      }});

      L.tileLayer("https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png", {{
        minZoom: 3,
        maxZoom: 19,
        noWrap: false,
        attribution: "&copy; OpenStreetMap contributors"
      }}).addTo(map);

      const bounds = [];
      const searchableMarkers = [];
      let highlightedMarker = null;

      data.markers.forEach(function(item) {{
        const latlng = [item.lat, item.lon];
        bounds.push(latlng);

        const normalStyle = {{
          radius: item.observer ? 7 : 4,
          weight: item.observer ? 3 : 1,
          opacity: 1,
          fillOpacity: item.observer ? 0.95 : 0.72,
          color: item.observer ? "#111" : "#555",
          fillColor: item.observer ? "#fff" : "#555"
        }};

        const marker = L.circleMarker(latlng, normalStyle).addTo(map);
        marker.bindTooltip(
          "<strong>" + escapeHtml(item.name) + "</strong><br>" +
          item.lat.toFixed(5) + ", " + item.lon.toFixed(5) +
          (item.observer ? "<br>Beobachtungsstandort" : ""),
          {{sticky: true}}
        );

        if (item.repeater) {{
          searchableMarkers.push({{
            item: item,
            marker: marker,
            normalStyle: normalStyle
          }});
        }}
      }});

      function clearHighlight() {{
        if (highlightedMarker) {{
          highlightedMarker.marker.setStyle(highlightedMarker.normalStyle);
          highlightedMarker.marker.setRadius(
            highlightedMarker.item.observer ? 7 : 4
          );
          highlightedMarker = null;
        }}
      }}

      function highlight(entry) {{
        clearHighlight();
        highlightedMarker = entry;
        entry.marker.setStyle({{
          color: "#b00020",
          fillColor: "#ffcf33",
          weight: 4,
          opacity: 1,
          fillOpacity: 1
        }});
        entry.marker.setRadius(10);
        map.setView(
          [entry.item.lat, entry.item.lon],
          Math.max(map.getZoom(), 11),
          {{animate: true}}
        );
        entry.marker.openTooltip();
      }}

      const searchInput = document.getElementById("mesh-map-search");
      const searchReset = document.getElementById("mesh-map-search-reset");
      const searchStatus = document.getElementById("mesh-map-search-status");
      const suggestions = document.getElementById("mesh-map-suggestions");
      let suggestionEntries = [];
      let activeSuggestion = -1;

      function matchingEntries(query) {{
        const q = query.trim().toLowerCase();
        if (q.length < 2) {{
          return [];
        }}
        return searchableMarkers
          .filter(function(entry) {{
            return entry.item.name.toLowerCase().includes(q) ||
                   entry.item.key.toLowerCase().includes(q);
          }})
          .sort(function(a, b) {{
            const an = a.item.name.toLowerCase();
            const bn = b.item.name.toLowerCase();
            const aStarts = an.startsWith(q) ? 0 : 1;
            const bStarts = bn.startsWith(q) ? 0 : 1;
            if (aStarts !== bStarts) return aStarts - bStarts;
            return an.localeCompare(bn);
          }});
      }}

      function clearSuggestions() {{
        suggestions.innerHTML = "";
        suggestionEntries = [];
        activeSuggestion = -1;
        suggestions.classList.remove("visible");
      }}

      function selectSuggestion(index) {{
        if (index < 0 || index >= suggestionEntries.length) return;
        const entry = suggestionEntries[index];
        searchInput.value = entry.item.name;
        highlight(entry);
        searchStatus.textContent = "Gefunden: " + entry.item.name;
        clearSuggestions();
      }}

      function renderSuggestions() {{
        const query = searchInput.value.trim();

        if (query.length < 2) {{
          clearSuggestions();
          searchStatus.textContent = "";
          return;
        }}

        const matches = matchingEntries(query);
        suggestionEntries = matches.slice(0, 10);
        activeSuggestion = -1;

        if (suggestionEntries.length === 0) {{
          suggestions.innerHTML =
            "<div class='map-search-suggestion empty'>Keine Treffer</div>";
          suggestions.classList.add("visible");
          searchStatus.textContent = "";
          return;
        }}

        suggestions.innerHTML = "";
        suggestionEntries.forEach(function(entry, index) {{
          const row = document.createElement("button");
          row.type = "button";
          row.className = "map-search-suggestion";
          row.innerHTML =
            "<span class='suggestion-main'>" +
              "<span class='suggestion-name'>" +
              escapeHtml(entry.item.name) +
              "</span>" +
              "<span class='suggestion-key'>" +
              escapeHtml(shortKey(entry.item.key)) +
              "</span>" +
            "</span>";
          row.addEventListener("mousedown", function(event) {{
            event.preventDefault();
            selectSuggestion(index);
          }});
          suggestions.appendChild(row);
        }});

        suggestions.classList.add("visible");
        searchStatus.textContent =
          matches.length > 10
            ? "10 von " + matches.length + " Treffern angezeigt"
            : matches.length + (matches.length === 1 ? " Treffer" : " Treffer");
      }}

      function updateActiveSuggestion() {{
        const rows = suggestions.querySelectorAll(".map-search-suggestion:not(.empty)");
        rows.forEach(function(row, index) {{
          row.classList.toggle("active", index === activeSuggestion);
        }});
      }}

      function runSearch() {{
        const query = searchInput.value.trim();
        if (query.length < 2) {{
          searchStatus.textContent =
            "Bitte mindestens zwei Zeichen eingeben.";
          clearSuggestions();
          return;
        }}

        const matches = matchingEntries(query);
        if (matches.length === 0) {{
          clearHighlight();
          searchStatus.textContent = "Kein passender Repeater gefunden.";
          clearSuggestions();
          return;
        }}

        searchInput.value = matches[0].item.name;
        highlight(matches[0]);
        searchStatus.textContent =
          matches.length === 1
            ? "Gefunden: " + matches[0].item.name
            : "Gefunden: " + matches[0].item.name +
              " · " + matches.length + " Treffer insgesamt";
        clearSuggestions();
      }}

      function shortKey(key) {{
        if (!key || key.length <= 18) return key || "";
        return key.slice(0, 8) + "…" + key.slice(-8);
      }}

      searchInput.addEventListener("input", renderSuggestions);

      searchInput.addEventListener("keydown", function(event) {{
        if (event.key === "ArrowDown" && suggestionEntries.length) {{
          event.preventDefault();
          activeSuggestion =
            Math.min(activeSuggestion + 1, suggestionEntries.length - 1);
          updateActiveSuggestion();
          return;
        }}

        if (event.key === "ArrowUp" && suggestionEntries.length) {{
          event.preventDefault();
          activeSuggestion = Math.max(activeSuggestion - 1, 0);
          updateActiveSuggestion();
          return;
        }}

        if (event.key === "Escape") {{
          clearSuggestions();
          return;
        }}

        if (event.key === "Enter") {{
          event.preventDefault();
          if (activeSuggestion >= 0) {{
            selectSuggestion(activeSuggestion);
          }} else {{
            runSearch();
          }}
        }}
      }});

      searchInput.addEventListener("blur", function() {{
        window.setTimeout(clearSuggestions, 120);
      }});

      searchReset.addEventListener("click", function() {{
        searchInput.value = "";
        searchStatus.textContent = "";
        clearSuggestions();
        clearHighlight();
        if (bounds.length === 1) {{
          map.setView(bounds[0], 10);
        }} else if (bounds.length > 1) {{
          map.fitBounds(bounds, {{padding: [24, 24], maxZoom: 11}});
        }}
      }});

      if (bounds.length === 1) {{
        map.setView(bounds[0], 10);
      }} else {{
        map.fitBounds(bounds, {{padding: [24, 24], maxZoom: 11}});
      }}

      function escapeHtml(value) {{
        return String(value)
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;")
          .replaceAll("'", "&#039;");
      }}
    }})();
    </script>
    """


def render_html(
    observer_name: str,
    observer_id: str,
    period_from: str,
    period_to: str,
    load: LoadMetrics,
    hour_values: list[tuple[datetime, int]],
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

    load_kind, load_label = load_assessment(load.avg_packets_per_hour)
    total_hours = max(1, load.hours_good + load.hours_loaded + load.hours_overloaded)
    overloaded_pct = 100.0 * load.hours_overloaded / total_hours
    far_pct = 100.0 * unscoped_far_packets / routing.unscoped if routing.unscoped else 0.0

    repeater_rows = "".join(
        "<tr>"
        f"<td class='num'>{idx}</td><td><strong>{esc(r.name)}</strong></td>"
        f"<td class='num'>{fmt_int(r.packets)}</td><td class='num'>{fmt_pct(r.percent)}</td>"
        f"<td class='num'>{'–' if r.max_position is None else r.max_position}</td>"
        f"<td class='mono key'>{esc(rr.short_key(r.public_key))}</td></tr>"
        for idx, r in enumerate(repeaters[:30], start=1)
    )

    direct_rows = "".join(
        "<tr>"
        f"<td><strong>{esc(r.name)}</strong></td><td class='num'>{fmt_int(r.packets)}</td>"
        f"<td class='num'>{fmt_pct(r.percent)}</td><td class='mono key'>{esc(rr.short_key(r.public_key))}</td>"
        "</tr>"
        for r in direct_neighbors[:20]
    )

    far_rows = "".join(
        "<tr>"
        f"<td><strong>{esc(r.name)}</strong></td><td class='num'>{fmt_int(r.packets)}</td>"
        f"<td class='num'>{r.max_position}</td><td class='mono key'>{esc(rr.short_key(r.public_key))}</td>"
        "</tr>"
        for r in unscoped_repeaters
    )

    position_rows = "".join(
        f"<tr><td class='num'>{pos}</td><td class='num'>{fmt_int(count)}</td></tr>"
        for pos, count in sorted(position_counts.items())
    )

    def geo_name(item: GeoRepeater | None) -> str:
        return item.name if item else "–"

    def geo_coord(item: GeoRepeater | None) -> str:
        return f"{item.lat:.4f}, {item.lon:.4f}" if item else ""

    other_note = ""
    if routing.other:
        other_note = (
            f"<p class='small muted'>Hinweis: {fmt_int(routing.other)} Pakete mit sonstigem oder nicht eindeutig "
            "klassifizierbarem Routing-Typ sind nicht in der 100-%-Verteilung enthalten.</p>"
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
:root {{--fg:#171717;--muted:#666;--line:#d9d9d9;--soft:#f5f5f5;--soft2:#fafafa;--ok:#246b3c;--warn:#9a6200;--critical:#a32622;}}
* {{box-sizing:border-box}} body {{font-family:Arial,Helvetica,sans-serif;color:var(--fg);max-width:1100px;margin:30px auto;padding:0 28px 56px;line-height:1.45}}
.report-brand {{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.09em;font-weight:700}}
.report-type {{margin:5px 0 3px;font-size:2.05rem;line-height:1.15}}
.report-object {{font-size:1.2rem;font-weight:700;margin-top:7px}}
.report-context-grid {{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:17px}}
.report-context-card {{border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:var(--soft2)}}
.report-context-label {{color:var(--muted);font-size:.78rem;margin-bottom:4px}}
.report-context-value {{font-weight:700}}
.report-context-sub {{margin-top:3px;color:var(--muted);font-size:.8rem}}
.subtitle,.muted {{color:var(--muted)}}
hr {{border:0;border-top:2px solid var(--fg);margin:20px 0 24px}} h2 {{margin-top:34px;margin-bottom:10px;padding-bottom:7px;border-bottom:1px solid var(--line);font-size:1.35rem}} h3 {{margin:22px 0 7px;font-size:1.05rem}}
.section-intro {{color:var(--muted);max-width:900px;margin-top:0}} .grid {{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}} .kpi-grid {{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}}
.card,.routing-card {{border:1px solid var(--line);border-radius:9px;padding:15px;background:var(--soft2)}} .label {{color:var(--muted);font-size:.84rem;margin-bottom:5px}} .value {{font-size:1.65rem;font-weight:700;line-height:1.1}} .subvalue {{color:var(--muted);font-size:.86rem;margin-top:5px}}
.routing-grid {{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:14px}} .assessment {{margin-top:14px;border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:var(--soft2)}} .assessment.positive strong {{color:var(--ok)}} .assessment.warning strong {{color:var(--warn)}} .assessment.critical strong {{color:var(--critical)}}
table {{width:100%;border-collapse:collapse;margin:10px 0 18px}} th,td {{border-bottom:1px solid var(--line);padding:8px 7px;text-align:left;vertical-align:top}} th {{background:var(--soft);font-size:.88rem}} .num {{text-align:right;white-space:nowrap}} .mono {{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}} .key {{color:var(--muted);font-size:.84rem;white-space:nowrap}} .small {{font-size:.84rem}}
.two-col {{display:grid;grid-template-columns:2fr 1fr;gap:22px}} .bar-chart {{height:120px;display:flex;gap:2px;align-items:flex-end;border-bottom:1px solid var(--line);padding-top:8px;overflow:hidden}} .bar {{flex:1 1 0;min-width:2px;background:#8b8b8b;border-radius:2px 2px 0 0}} .bar.loaded {{background:#b28a35}} .bar.overloaded {{background:#a94a45}} .chart-legend {{display:flex;justify-content:space-between;color:var(--muted);font-size:.8rem;margin-top:5px}}
.extent-grid {{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}}
.extreme-grid {{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:12px}}
.offline-map-shell {{border:1px solid var(--line);border-radius:9px;padding:12px;background:var(--soft2);margin-top:14px}}
.map-search {{
  margin-bottom:10px;
  position:relative;
}}
.map-search label {{
  display:block;
  font-size:.84rem;
  font-weight:700;
  margin-bottom:5px;
}}
.map-search-row {{
  display:flex;
  gap:8px;
  align-items:center;
}}
.map-search-row input {{
  flex:1 1 auto;
  min-width:0;
  border:1px solid #aaa;
  border-radius:6px;
  padding:9px 11px;
  font:inherit;
  background:#fff;
}}
.map-search-row input:focus {{
  outline:none;
  border-color:#666;
  box-shadow:0 0 0 2px rgba(0,0,0,.05);
}}
.map-search-row .map-search-reset {{
  border:1px solid #bbb;
  border-radius:6px;
  padding:9px 12px;
  background:#fff;
  color:var(--fg);
  font:inherit;
  font-weight:600;
  cursor:pointer;
}}
.map-search-row .map-search-reset:hover {{
  background:#f4f4f4;
}}
.map-search-suggestions {{
  display:none;
  position:absolute;
  left:0;
  right:112px;
  z-index:1000;
  margin-top:4px;
  border:1px solid #c9c9c9;
  border-radius:7px;
  background:#fff;
  overflow:hidden;
  box-shadow:0 8px 20px rgba(0,0,0,.10);
}}
.map-search-suggestions.visible {{display:block}}
.map-search-suggestion {{
  width:100%;
  display:block;
  border:0;
  border-bottom:1px solid #ececec;
  border-radius:0;
  padding:9px 11px;
  background:#fff;
  color:var(--fg);
  text-align:left;
  font:inherit;
  cursor:pointer;
}}
.map-search-suggestion:last-child {{border-bottom:0}}
.map-search-suggestion:hover,
.map-search-suggestion.active {{
  background:#f6f6f6;
}}
.map-search-suggestion.empty {{
  cursor:default;
  color:var(--muted);
}}
.suggestion-main {{
  display:block;
}}
.suggestion-name {{
  display:block;
  font-weight:700;
  line-height:1.25;
}}
.suggestion-key {{
  display:block;
  margin-top:2px;
  color:var(--muted);
  font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
  font-size:.76rem;
}}
.map-search-status {{
  min-height:1.2em;
  margin-top:5px;
  color:var(--muted);
  font-size:.8rem;
}}
.leaflet-map {{width:100%;height:520px;border-radius:7px;background:#ececec}}
.leaflet-map .leaflet-tile-pane,
.leaflet-map .leaflet-tile {{opacity:1 !important;filter:none !important}}
.map-note {{color:var(--muted);font-size:.8rem;margin-top:8px}}
.map-empty,.map-error {{border:1px solid var(--line);border-radius:9px;padding:16px;background:var(--soft2);color:var(--muted);margin-top:14px}}
.map-error {{display:flex;align-items:center;justify-content:center;min-height:180px;text-align:center}}
.footer {{margin-top:36px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:.8rem}}
@media(max-width:800px) {{.grid,.kpi-grid,.extent-grid,.extreme-grid {{grid-template-columns:1fr 1fr}} .routing-grid,.two-col,.report-context-grid {{grid-template-columns:1fr}} .map-search-suggestions {{right:0}} .map-search-row {{flex-wrap:wrap}} .map-search-row input {{flex-basis:100%}}}} @media(max-width:520px) {{body {{padding:0 16px 40px}} .grid,.kpi-grid,.extent-grid,.extreme-grid {{grid-template-columns:1fr}}}}
@page {{margin:10mm;}}
@media print {{
  body {{margin:0;max-width:none;padding:0;}}
  header {{break-after:avoid-page;}}
  h2,h3 {{break-after:avoid-page;}}
  .section-intro {{break-after:avoid-page;}}
  .card,.routing-card,.assessment,.offline-map-shell {{break-inside:avoid-page;}}
  .map-chapter {{break-before:page;}}
  .print-chapter {{break-before:page;}}
  table thead {{display:table-header-group;}}
  tr {{break-inside:avoid-page;}}
}}
</style>
</head>
<body>
<header>
<div class="report-brand">MESHCORE PACKETTAP</div>
<h1 class="report-type">Mesh-Report</h1>
<div class="report-object">Beobachtetes Mesh</div>
<div class="report-context-grid">
  <div class="report-context-card">
    <div class="report-context-label">Beobachtungsstandort</div>
    <div class="report-context-value">{esc(observer_display_name)}</div>
    <div class="report-context-sub">{esc(receiver_detail)}</div>
  </div>
  <div class="report-context-card">
    <div class="report-context-label">Beobachtungszeitraum</div>
    <div class="report-context-value">{format_period_de(period_from)} – {format_period_de(period_to)}</div>
    <div class="report-context-sub">{fmt_num(load.period_hours,1)} h ausgewertet</div>
  </div>
</div>
</header>
<hr>
<p class="section-intro">Dieser Report beschreibt ausschließlich das Mesh, das vom angegebenen Receiver im Beobachtungszeitraum empfangen werden konnte.</p>
<section><h2>Ausdehnung des beobachteten Mesh</h2>
<p class="section-intro">Die räumliche Ausdehnung wird aus den bekannten Koordinaten der Repeater berechnet, die im Beobachtungszeitraum eindeutig in Paketpfaden erkannt wurden. Repeater ohne bekannte Position fließen in die Repeater-Anzahl, aber nicht in die Entfernungsberechnung ein.</p>
<div class="extent-grid">
<div class="card"><div class="label">Repeater im beobachteten Mesh</div><div class="value">{fmt_int(extent.repeater_count)}</div><div class="subvalue">{fmt_int(extent.geo_repeater_count)} davon mit bekannten Koordinaten</div></div>
<div class="card"><div class="label">Nord–Süd-Ausdehnung</div><div class="value">{fmt_num(extent.north_south_km,1) + ' km' if extent.north_south_km is not None else '–'}</div><div class="subvalue">{esc(geo_name(extent.south))} ↔ {esc(geo_name(extent.north))}</div></div>
<div class="card"><div class="label">Ost–West-Ausdehnung</div><div class="value">{fmt_num(extent.east_west_km,1) + ' km' if extent.east_west_km is not None else '–'}</div><div class="subvalue">{esc(geo_name(extent.west))} ↔ {esc(geo_name(extent.east))}</div></div>
</div>
<div class="extreme-grid">
<div class="card"><div class="label">Größte Entfernung zweier bekannter Repeater</div><div class="value">{fmt_num(extent.max_pair_km,1) + ' km' if extent.max_pair_km is not None else '–'}</div><div class="subvalue">{esc(' ↔ '.join(extent.max_pair_names)) if extent.max_pair_names else 'keine ausreichenden Positionsdaten'}</div></div>
<div class="card"><div class="label">Geografische Randpunkte</div><div class="small">
N: <strong>{esc(geo_name(extent.north))}</strong> {esc(geo_coord(extent.north))}<br>
S: <strong>{esc(geo_name(extent.south))}</strong> {esc(geo_coord(extent.south))}<br>
W: <strong>{esc(geo_name(extent.west))}</strong> {esc(geo_coord(extent.west))}<br>
O: <strong>{esc(geo_name(extent.east))}</strong> {esc(geo_coord(extent.east))}
</div></div>
</div>
<h3 class="map-chapter">Karte des beobachteten Mesh</h3>{render_mesh_map(observed_geo, observer_id, extent, observer_geo)}
</section>
<section class="print-chapter"><h2>Netzlast am Beobachtungsstandort</h2><p class="section-intro">Die Bewertung basiert auf der Anzahl der am Receiver beobachteten Pakete pro Stunde. Unter 1.000 Paketen/h gilt das Netz erfahrungsgemäß als gut nutzbar, 1.000–1.500 Pakete/h als belastet und über 1.500 Pakete/h als überlastet.</p>
<div class="kpi-grid">
<div class="card"><div class="label">Ø Pakete pro Stunde</div><div class="value">{fmt_num(load.avg_packets_per_hour,0)}</div><div class="subvalue">{fmt_num(load.period_hours,1)} h Beobachtungszeit</div></div>
<div class="card"><div class="label">Max. Pakete pro Stunde</div><div class="value">{fmt_int(load.max_packets_per_hour)}</div><div class="subvalue">höchste beobachtete Stundenlast</div></div>
<div class="card"><div class="label">Überlastete Stunden</div><div class="value">{fmt_int(load.hours_overloaded)}</div><div class="subvalue">{fmt_pct(overloaded_pct)} der Stunden &gt; 1.500 Pakete/h</div></div>
<div class="card"><div class="label">Bewertung Ø-Last</div><div class="value">{esc(load_label)}</div><div class="subvalue">standortbezogene Erfahrungsbewertung</div></div>
</div>
<div class="assessment {load_kind}"><strong>{esc(load_label)}:</strong> Durchschnittlich {fmt_num(load.avg_packets_per_hour,0)} Pakete/h. Im Zeitraum gab es {fmt_int(load.hours_loaded)} belastete und {fmt_int(load.hours_overloaded)} überlastete Stunden.</div>
<h3>Stundenlast im Zeitverlauf</h3>{render_load_bar(hour_values)}</section>
<section class="print-chapter"><h2>Routing-Verhalten</h2><p class="section-intro">Scoped, Unscoped und Direct bilden gemeinsam 100 % der eindeutig klassifizierten Pakete am Beobachtungsstandort.</p><div class="routing-grid">
<div class="routing-card"><div class="label">Scoped</div><div class="value">{fmt_pct(routing.percent(routing.scoped))}</div><div>{fmt_int(routing.scoped)} Pakete</div><div class="subvalue">RT 0 + RT 3 · Routing mit Scope/Region</div></div>
<div class="routing-card"><div class="label">Unscoped</div><div class="value">{fmt_pct(routing.percent(routing.unscoped))}</div><div>{fmt_int(routing.unscoped)} Pakete</div><div class="subvalue">RT 1 · Flood-Routing ohne Region</div></div>
<div class="routing-card"><div class="label">Direct</div><div class="value">{fmt_pct(routing.percent(routing.direct))}</div><div>{fmt_int(routing.direct)} Pakete</div><div class="subvalue">RT 2 · direkte bzw. pfadbasierte Übertragung</div></div>
</div>{other_note}</section>
<section class="print-chapter"><h2>Weitreichender Unscoped-Verkehr</h2><p class="section-intro">Betrachtet werden ausschließlich Unscoped-Pakete (RT 1). Aufgelistet werden eindeutig erkennbare Repeater, die im beobachteten Paketpfad an einer zero-based Path-Position größer 3 vorkommen.</p>
<div class="kpi-grid"><div class="card"><div class="label">Unscoped-Pakete gesamt</div><div class="value">{fmt_int(routing.unscoped)}</div></div><div class="card"><div class="label">Unscoped mit Repeater &gt; Pos. 3</div><div class="value">{fmt_int(unscoped_far_packets)}</div><div class="subvalue">{fmt_pct(far_pct)} der Unscoped-Pakete</div></div><div class="card"><div class="label">Max. Unscoped Path-Position</div><div class="value">{fmt_int(unscoped_max_position) if unscoped_repeaters else '–'}</div><div class="subvalue">zero-based Position</div></div><div class="card"><div class="label">Repeater &gt; Pos. 3</div><div class="value">{fmt_int(len(unscoped_repeaters))}</div><div class="subvalue">eindeutig identifiziert</div></div></div>
<div class="two-col"><div><h3>Repeater bei Unscoped an Path-Position &gt; 3</h3><table><thead><tr><th>Repeater</th><th class="num">Pakete</th><th class="num">höchste Pos.</th><th>Public Key</th></tr></thead><tbody>{far_rows or '<tr><td colspan="4" class="muted">Keine eindeutigen Repeater an Path-Position &gt; 3 beobachtet.</td></tr>'}</tbody></table></div><div><h3>Verteilung der Path-Positionen</h3><table><thead><tr><th class="num">Position</th><th class="num">Vorkommen</th></tr></thead><tbody>{position_rows or '<tr><td colspan="2" class="muted">Keine Daten.</td></tr>'}</tbody></table></div></div></section>
<section class="print-chapter"><h2>Repeater im beobachteten Mesh</h2><p class="section-intro">Die Rangfolge basiert auf Paketen, in deren beobachtetem Pfad der Repeater eindeutig erkannt wurde. Ein Repeater wird pro Paket höchstens einmal gezählt.</p><table><thead><tr><th class="num">Rang</th><th>Repeater</th><th class="num">Pakete im Pfad</th><th class="num">Anteil</th><th class="num">max. Path-Pos.</th><th>Public Key</th></tr></thead><tbody>{repeater_rows}</tbody></table></section>
<section class="print-chapter"><h2>Direkte Nachbarschaft des Receivers</h2><p class="section-intro">Hier wird bewusst eine andere Perspektive verwendet: gezählt wird der Repeater im Feld <code>repeater</code>, also der letzte beobachtete Repeater unmittelbar vor dem PacketTap-Receiver.</p><table><thead><tr><th>Repeater</th><th class="num">Pakete</th><th class="num">Anteil</th><th>Public Key / Path-ID</th></tr></thead><tbody>{direct_rows}</tbody></table></section>
<section class="print-chapter"><h2>Methodik der Auswertung</h2><p class="section-intro">Die Ergebnisse beschreiben ausschließlich die Sicht des angegebenen Beobachtungsstandorts. Nicht empfangene Übertragungen können nicht in die Auswertung einfließen.</p><p class="small muted"><strong>Repeater-Zuordnung:</strong> Repeater in Paketpfaden werden nur dann gezählt, wenn die jeweilige Path-ID anhand der bekannten Public Keys und der verwendeten Path-Hash-Größe eindeutig auflösbar ist.</p><p class="small muted"><strong>Netzlast:</strong> Die Einordnung &lt;1000 / 1000–1500 / &gt;1500 Pakete pro Stunde ist eine betriebliche Erfahrungsbewertung für die Nutzbarkeit am Beobachtungsstandort und keine allgemeingültige MeshCore-Protokollgrenze.</p><p class="small muted"><strong>Unscoped &gt; Position 3:</strong> Die Position ist zero-based. Position 4 bezeichnet damit das fünfte Element des beobachteten Paketpfades.</p></section>
<footer class="footer">MeshCore PacketTap · Mesh-Report</footer>
</body></html>"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MeshCore PacketTap Observed Mesh Report v0.40")
    p.add_argument("--questdb-host", default=rr.DEFAULT_QUESTDB_HOST)
    p.add_argument("--questdb-port", type=int, default=rr.DEFAULT_QUESTDB_PORT)
    p.add_argument("--from", dest="period_from", type=rr.validate_iso_time, required=True)
    p.add_argument("--to", dest="period_to", type=rr.validate_iso_time, required=True)
    p.add_argument("--receiver-id", default=None)
    p.add_argument("--receiver-name", default=None)
    p.add_argument(
        "--max-geo-distance-km",
        type=float,
        default=500.0,
        help="Maximale plausible Advert-Entfernung zum Beobachtungsstandort; <=0 deaktiviert den Filter.",
    )
    p.add_argument("--output", default="mesh_report.html")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    db = rr.QuestDB(args.questdb_host, args.questdb_port)
    try:
        print(f"[MESH] Lade mc_rx {args.period_from} bis {args.period_to} von {args.questdb_host}:{args.questdb_port} ...")
        rows = load_mesh_rx(db, args.period_from, args.period_to, args.receiver_id, args.receiver_name)
        print(f"[MESH] {len(rows)} Pakete geladen.")

        print("[MESH] Lade mc_contacts ...")
        contacts = rr.load_contacts(db)
        resolver = rr.ContactResolver(contacts)
        print(f"[MESH] {len(contacts)} Kontakte, {len(resolver.repeaters)} Repeater.")

        observer_name, observer_id = determine_observer(rows, args.receiver_id, args.receiver_name)
        load, hour_values = analyze_load(rows, args.period_from, args.period_to)
        routing = analyze_routing(rows)
        repeaters = analyze_repeater_activity(rows, resolver)

        print("[MESH] Lade bekannte Repeater-Positionen ...")
        geo_repeaters = load_geo_repeaters(db)
        geo_contacts = load_geo_contacts(db)
        observer_geo = observer_geo_from_contacts(geo_contacts, observer_id)
        geo_repeaters, rejected_geo = filter_geo_by_observer_distance(
            geo_repeaters,
            observer_geo,
            args.max_geo_distance_km,
        )
        extent, observed_geo = analyze_extent(repeaters, geo_repeaters)
        print(
            f"[MESH] {extent.repeater_count} Repeater im beobachteten Mesh, "
            f"{extent.geo_repeater_count} mit bekannten Koordinaten."
        )

        far_packets, max_pos, far_repeaters, pos_counts = analyze_unscoped_far(rows, resolver)
        direct_neighbors = analyze_direct_neighbors(rows, resolver)

        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            render_html(
                observer_name, observer_id,
                args.period_from, args.period_to,
                load, hour_values, routing, repeaters,
                far_packets, max_pos, far_repeaters, pos_counts,
                direct_neighbors, extent, observed_geo, observer_geo,
            ),
            encoding="utf-8",
        )
        print(f"[MESH] HTML geschrieben: {output.resolve()}")
        return 0
    except KeyboardInterrupt:
        print("\n[MESH] Abgebrochen.")
        return 130
    except Exception as exc:
        print(f"[MESH][FEHLER] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
