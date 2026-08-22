#!/usr/bin/env python3
"""
node_directory.py v0.4.1

Lokale Node-Wissensbasis fuer MeshCore PacketTap.

v0.4:
- Multi-Source-Aufloesung aus CoreScope + offizieller MeshCore Map
- CoreScope bleibt gezielte Einzelabfrage je Path-ID
- MeshCore Map wird als kompletter JSON-Snapshot (?short=1) geladen
- Snapshot wird standardmaessig 6 Stunden lokal gecacht
- innerhalb eines Laufs wird der Map-Bestand nur einmal dekodiert/indexiert
- Standardstrategie "map_first":
    * MeshCore-Map-Snapshot zuerst lokal pruefen
    * CoreScope nur aufrufen, wenn die Map fuer die Path-ID keinen Treffer hat
    * dadurch bei grossen Batch-Laeufen deutlich weniger CoreScope-Requests
- optionale Strategie "merged":
    * CoreScope + MeshCore Map wie in v0.4 immer zusammenfuehren
- Kandidaten werden anhand des vollstaendigen Public Keys dedupliziert
- last_advert der MeshCore Map wird in node_directory.db gespeichert
- bestehende node_directory.db wird automatisch migriert
- keine QuestDB-Aenderungen

Standardpfade:
    state/node_directory.db
    state/meshcore_map_snapshot.json

Beispiele:
    python node_directory.py 1dea 827c bbca 1dea8f 6dc4 89e5 01e4
    python node_directory.py --refresh bbca
    python node_directory.py --show-cache
    python node_directory.py --refresh-map bbca
    python node_directory.py --map-status
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

APP_VERSION = "0.4.1"

DEFAULT_DB = Path("state/node_directory.db")

DEFAULT_BASE_URL = "https://analyzer.meshcorenetz.de"
DEFAULT_TIMEOUT = 15.0

DEFAULT_MAP_URL = "https://map.meshcore.dev/api/v1/nodes"
DEFAULT_MAP_SNAPSHOT_TTL = 6 * 3600
DEFAULT_MAP_TIMEOUT = 90.0

POSITIVE_TTL = 7 * 24 * 3600
NEGATIVE_TTL = 24 * 3600
ERROR_TTL = 60 * 60

USER_AGENT = f"MeshCore-PacketTap-NodeDirectory/{APP_VERSION}"

TYPE_NAMES = {
    1: "companion",
    2: "repeater",
    3: "room_server",
    4: "sensor",
    "1": "companion",
    "2": "repeater",
    "3": "room_server",
    "4": "sensor",
}


@dataclass
class Node:
    public_key: str
    name: str | None
    role: str | None
    lat: float | None
    lon: float | None
    source: str
    source_url: str | None
    updated_at: int
    last_advert: str | None = None


def norm_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()

    return "".join(
        c
        for c in str(value or "").strip().lower()
        if c in "0123456789abcdef"
    )


def valid_path_id(value: str) -> bool:
    return len(norm_hex(value)) in (2, 4, 6)


def pick(d: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if d.get(key) not in (None, ""):
            return d[key]
    return None


def to_float(value: Any) -> float | None:
    try:
        return None if value in (None, "") else float(value)
    except (TypeError, ValueError):
        return None


def public_key_of(node: dict[str, Any]) -> str | None:
    for key in (
        "public_key",
        "pubkey",
        "publicKey",
        "publickey",
        "pk",
        "key",
        "node_id",
        "nodeId",
    ):
        if key not in node:
            continue

        value = norm_hex(node[key])
        if len(value) == 64:
            return value

    return None


def extract_nodes(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [
            item
            for item in payload
            if isinstance(item, dict)
        ]

    if not isinstance(payload, dict):
        return []

    for key in (
        "nodes",
        "items",
        "results",
        "data",
        "entries",
    ):
        value = payload.get(key)

        if isinstance(value, list):
            return [
                item
                for item in value
                if isinstance(item, dict)
            ]

        if isinstance(value, dict):
            for subkey in (
                "nodes",
                "items",
                "results",
                "data",
            ):
                sub = value.get(subkey)
                if isinstance(sub, list):
                    return [
                        item
                        for item in sub
                        if isinstance(item, dict)
                    ]

    return [payload] if public_key_of(payload) else []


def candidate_sort_key(
    item: dict[str, Any] | sqlite3.Row | Node,
) -> tuple[str, str]:
    if isinstance(item, Node):
        name = item.name or ""
        public_key = item.public_key
    else:
        try:
            name = item["node_name"] or ""
        except Exception:
            name = ""
        try:
            public_key = item["public_key"] or ""
        except Exception:
            public_key = ""

    return (
        str(name).lower(),
        str(public_key).lower(),
    )


def source_parts(value: str | None) -> set[str]:
    if not value:
        return set()

    return {
        item.strip()
        for item in str(value).split("+")
        if item.strip()
    }


def combine_sources(*values: str | None) -> str:
    parts: set[str] = set()
    for value in values:
        parts.update(source_parts(value))

    preferred = [
        item
        for item in ("corescope", "meshcore_map", "manual")
        if item in parts
    ]
    other = sorted(
        item
        for item in parts
        if item not in preferred
    )

    return "+".join(preferred + other) or "directory"


def choose_text(
    primary: str | None,
    fallback: str | None,
) -> str | None:
    return primary if primary not in (None, "") else fallback


def choose_number(
    primary: float | None,
    fallback: float | None,
) -> float | None:
    return primary if primary is not None else fallback


def merge_node(
    existing: Node | None,
    incoming: Node,
) -> Node:
    if existing is None:
        return incoming

    # CoreScope values remain preferred when both sources supply the same
    # full public key. MeshCore Map enriches missing values and last_advert.
    existing_is_corescope = "corescope" in source_parts(existing.source)
    incoming_is_corescope = "corescope" in source_parts(incoming.source)

    if incoming_is_corescope and not existing_is_corescope:
        primary = incoming
        fallback = existing
    else:
        primary = existing
        fallback = incoming

    urls = []
    for value in (
        existing.source_url,
        incoming.source_url,
    ):
        if value and value not in urls:
            urls.append(value)

    return Node(
        public_key=existing.public_key,
        name=choose_text(primary.name, fallback.name),
        role=choose_text(primary.role, fallback.role),
        lat=choose_number(primary.lat, fallback.lat),
        lon=choose_number(primary.lon, fallback.lon),
        source=combine_sources(
            existing.source,
            incoming.source,
        ),
        source_url=" | ".join(urls) if urls else None,
        updated_at=max(
            existing.updated_at,
            incoming.updated_at,
        ),
        last_advert=choose_text(
            incoming.last_advert,
            existing.last_advert,
        ),
    )


class NodeDirectory:
    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        map_url: str = DEFAULT_MAP_URL,
        map_snapshot_path: str | Path | None = None,
        map_snapshot_ttl: int = DEFAULT_MAP_SNAPSHOT_TTL,
        map_timeout: float = DEFAULT_MAP_TIMEOUT,
        refresh_map: bool = False,
        lookup_strategy: str = "map_first",
    ):
        self.db_path = Path(db_path)
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)

        self.map_url = map_url.rstrip("/")
        self.map_snapshot_ttl = max(
            0,
            int(map_snapshot_ttl),
        )
        self.map_timeout = float(map_timeout)
        self.refresh_map = bool(refresh_map)

        lookup_strategy = str(lookup_strategy or "map_first").strip().lower()
        if lookup_strategy not in ("map_first", "merged"):
            raise ValueError(
                "lookup_strategy muss 'map_first' oder 'merged' sein."
            )
        self.lookup_strategy = lookup_strategy

        if map_snapshot_path is None:
            self.map_snapshot_path = (
                self.db_path.parent
                / "meshcore_map_snapshot.json"
            )
        else:
            self.map_snapshot_path = Path(
                map_snapshot_path
            )

        self._map_loaded = False
        self._map_nodes: dict[str, Node] = {}
        self._map_load_error = ""
        self._map_loaded_from = ""
        self._map_downloaded_at: int | None = None

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.map_snapshot_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.db = sqlite3.connect(self.db_path)
        self.db.row_factory = sqlite3.Row
        self._init_db()

    def close(self) -> None:
        self.db.close()

    def _init_db(self) -> None:
        self.db.executescript(
            """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS nodes(
                public_key TEXT PRIMARY KEY,
                node_name TEXT,
                node_role TEXT,
                lat REAL,
                lon REAL,
                source TEXT NOT NULL,
                source_url TEXT,
                last_updated INTEGER NOT NULL,
                manual_override INTEGER NOT NULL DEFAULT 0,
                last_advert TEXT
            );

            CREATE TABLE IF NOT EXISTS path_candidates(
                path_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY(path_id, public_key)
            );

            CREATE TABLE IF NOT EXISTS path_lookup_cache(
                path_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                candidate_count INTEGER NOT NULL,
                checked_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                source TEXT NOT NULL,
                error_text TEXT
            );

            CREATE TABLE IF NOT EXISTS directory_source_state(
                source TEXT PRIMARY KEY,
                last_success INTEGER,
                node_count INTEGER,
                byte_count INTEGER,
                source_url TEXT,
                error_text TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_path_candidates_path_id
                ON path_candidates(path_id);

            CREATE INDEX IF NOT EXISTS idx_nodes_source
                ON nodes(source);
            """
        )

        node_columns = {
            row["name"]
            for row in self.db.execute(
                "PRAGMA table_info(nodes)"
            )
        }

        if "last_advert" not in node_columns:
            self.db.execute(
                "ALTER TABLE nodes "
                "ADD COLUMN last_advert TEXT"
            )

        cache_columns = {
            row["name"]
            for row in self.db.execute(
                "PRAGMA table_info(path_lookup_cache)"
            )
        }

        if "error_text" not in cache_columns:
            self.db.execute(
                "ALTER TABLE path_lookup_cache "
                "ADD COLUMN error_text TEXT"
            )

        self.db.commit()

    def _http_json(
        self,
        url: str,
        timeout: float | None = None,
    ) -> tuple[Any, int]:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
        )

        with urllib.request.urlopen(
            request,
            timeout=(
                self.timeout
                if timeout is None
                else timeout
            ),
        ) as response:
            raw = response.read()
            charset = (
                response.headers.get_content_charset()
                or "utf-8"
            )
            return (
                json.loads(
                    raw.decode(
                        charset,
                        errors="replace",
                    )
                ),
                len(raw),
            )

    def _search_url(
        self,
        path_id: str,
    ) -> str:
        query = urllib.parse.urlencode(
            {"q": path_id}
        )

        return (
            f"{self.base_url}/api/nodes/search?"
            f"{query}"
        )

    def _corescope_search(
        self,
        path_id: str,
    ) -> list[Node]:
        url = self._search_url(path_id)

        try:
            payload, _ = self._http_json(url)
        except Exception as exc:
            raise RuntimeError(
                f"CoreScope-Abfrage fehlgeschlagen: {exc}"
            ) from exc

        matches: dict[str, Node] = {}

        for raw in extract_nodes(payload):
            public_key = public_key_of(raw)

            if not public_key:
                continue

            if not public_key.startswith(path_id):
                continue

            name = pick(
                raw,
                "name",
                "node_name",
                "nodeName",
                "adv_name",
                "display_name",
            )

            role = pick(
                raw,
                "role",
                "node_role",
                "nodeRole",
                "type",
            )

            lat = to_float(
                pick(
                    raw,
                    "lat",
                    "latitude",
                    "adv_lat",
                )
            )

            lon = to_float(
                pick(
                    raw,
                    "lon",
                    "lng",
                    "longitude",
                    "adv_lon",
                )
            )

            matches[public_key] = Node(
                public_key=public_key,
                name=(
                    str(name)
                    if name is not None
                    else None
                ),
                role=(
                    str(role)
                    if role is not None
                    else None
                ),
                lat=lat,
                lon=lon,
                source="corescope",
                source_url=url,
                updated_at=int(time.time()),
            )

        return sorted(
            matches.values(),
            key=candidate_sort_key,
        )

    def _map_snapshot_url(self) -> str:
        query = urllib.parse.urlencode(
            {"short": "1"}
        )
        return f"{self.map_url}?{query}"

    def _map_snapshot_is_fresh(self) -> bool:
        if not self.map_snapshot_path.exists():
            return False

        if self.map_snapshot_ttl <= 0:
            return False

        try:
            age = (
                time.time()
                - self.map_snapshot_path.stat().st_mtime
            )
        except OSError:
            return False

        return age <= self.map_snapshot_ttl

    def _write_snapshot_atomic(
        self,
        raw: bytes,
    ) -> None:
        self.map_snapshot_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd, tmp_name = tempfile.mkstemp(
            prefix=(
                self.map_snapshot_path.name
                + "."
            ),
            suffix=".tmp",
            dir=str(
                self.map_snapshot_path.parent
            ),
        )

        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(
                tmp_name,
                self.map_snapshot_path,
            )
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _download_map_snapshot(
        self,
    ) -> tuple[Any, int]:
        url = self._map_snapshot_url()

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
        )

        with urllib.request.urlopen(
            request,
            timeout=self.map_timeout,
        ) as response:
            raw = response.read()
            charset = (
                response.headers.get_content_charset()
                or "utf-8"
            )

        payload = json.loads(
            raw.decode(
                charset,
                errors="replace",
            )
        )

        self._write_snapshot_atomic(raw)

        now = int(time.time())

        self.db.execute(
            """
            INSERT INTO directory_source_state(
                source,
                last_success,
                node_count,
                byte_count,
                source_url,
                error_text
            )
            VALUES (?, ?, ?, ?, ?, '')
            ON CONFLICT(source)
            DO UPDATE SET
                last_success = excluded.last_success,
                node_count = excluded.node_count,
                byte_count = excluded.byte_count,
                source_url = excluded.source_url,
                error_text = ''
            """,
            (
                "meshcore_map",
                now,
                len(extract_nodes(payload)),
                len(raw),
                url,
            ),
        )
        self.db.commit()

        self._map_downloaded_at = now

        return payload, len(raw)

    def _read_map_snapshot(self) -> Any:
        return json.loads(
            self.map_snapshot_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        )

    def _load_map_index(self) -> None:
        if self._map_loaded:
            return

        self._map_loaded = True
        payload: Any | None = None

        try:
            should_download = (
                self.refresh_map
                or not self._map_snapshot_is_fresh()
            )

            if should_download:
                try:
                    payload, _ = (
                        self._download_map_snapshot()
                    )
                    self._map_loaded_from = "online"
                except Exception as exc:
                    # A stale snapshot is still more useful than no Map
                    # provider at all.
                    if self.map_snapshot_path.exists():
                        payload = self._read_map_snapshot()
                        self._map_loaded_from = (
                            "stale_snapshot"
                        )
                        self._map_load_error = (
                            "MeshCore-Map-Download "
                            f"fehlgeschlagen, alter Snapshot "
                            f"verwendet: {exc}"
                        )
                    else:
                        raise
            else:
                payload = self._read_map_snapshot()
                self._map_loaded_from = "snapshot"

            nodes: dict[str, Node] = {}
            source_url = self._map_snapshot_url()

            for raw in extract_nodes(payload):
                public_key = public_key_of(raw)

                if not public_key:
                    continue

                role_raw = pick(
                    raw,
                    "type",
                    "node_role",
                    "role",
                )
                role = (
                    TYPE_NAMES.get(
                        role_raw,
                        TYPE_NAMES.get(
                            str(role_raw),
                            str(role_raw)
                            if role_raw is not None
                            else None,
                        ),
                    )
                )

                node = Node(
                    public_key=public_key,
                    name=(
                        str(
                            pick(
                                raw,
                                "adv_name",
                                "name",
                                "node_name",
                            )
                        )
                        if pick(
                            raw,
                            "adv_name",
                            "name",
                            "node_name",
                        )
                        is not None
                        else None
                    ),
                    role=role,
                    lat=to_float(
                        pick(
                            raw,
                            "adv_lat",
                            "lat",
                            "latitude",
                        )
                    ),
                    lon=to_float(
                        pick(
                            raw,
                            "adv_lon",
                            "lon",
                            "lng",
                            "longitude",
                        )
                    ),
                    source="meshcore_map",
                    source_url=source_url,
                    updated_at=int(time.time()),
                    last_advert=(
                        str(
                            pick(
                                raw,
                                "last_advert",
                                "last_seen",
                            )
                        )
                        if pick(
                            raw,
                            "last_advert",
                            "last_seen",
                        )
                        is not None
                        else None
                    ),
                )

                nodes[public_key] = node

            self._map_nodes = nodes

            state = self.db.execute(
                """
                SELECT last_success
                FROM directory_source_state
                WHERE source = 'meshcore_map'
                """
            ).fetchone()

            if state is not None:
                self._map_downloaded_at = (
                    int(state["last_success"])
                    if state["last_success"] is not None
                    else None
                )

        except Exception as exc:
            self._map_nodes = {}
            self._map_load_error = (
                f"MeshCore-Map-Abfrage fehlgeschlagen: {exc}"
            )

            self.db.execute(
                """
                INSERT INTO directory_source_state(
                    source,
                    last_success,
                    node_count,
                    byte_count,
                    source_url,
                    error_text
                )
                VALUES (?, NULL, NULL, NULL, ?, ?)
                ON CONFLICT(source)
                DO UPDATE SET
                    source_url = excluded.source_url,
                    error_text = excluded.error_text
                """,
                (
                    "meshcore_map",
                    self._map_snapshot_url(),
                    self._map_load_error,
                ),
            )
            self.db.commit()

    def _meshcore_map_search(
        self,
        path_id: str,
    ) -> list[Node]:
        self._load_map_index()

        return sorted(
            (
                node
                for public_key, node
                in self._map_nodes.items()
                if public_key.startswith(path_id)
            ),
            key=candidate_sort_key,
        )

    def _online_search(
        self,
        path_id: str,
    ) -> tuple[
        list[Node],
        list[str],
        list[str],
    ]:
        """
        Resolve one Path-ID according to the configured strategy.

        map_first (default):
            1. Search the already loaded/cached MeshCore Map snapshot locally.
            2. If Map has >=1 candidate, return those candidates immediately.
            3. Only when Map has 0 candidates, query CoreScope.

        merged:
            Query both providers and merge/deduplicate all candidates.
        """
        merged: dict[str, Node] = {}
        errors: list[str] = []
        successful_sources: list[str] = []

        # Always try MeshCore Map first. Loading/indexing is done only once
        # per NodeDirectory instance, so a batch of thousands of Path-IDs
        # performs one snapshot load/download and then local prefix searches.
        try:
            meshcore_map = self._meshcore_map_search(path_id)

            if self._map_nodes or not self._map_load_error:
                successful_sources.append("meshcore_map")

            for node in meshcore_map:
                merged[node.public_key] = merge_node(
                    merged.get(node.public_key),
                    node,
                )

            if self._map_load_error:
                errors.append(self._map_load_error)

        except Exception as exc:
            meshcore_map = []
            errors.append(str(exc))

        # Optimized default:
        # Any Map hit is good enough to avoid a CoreScope request. Ambiguous
        # Map results are intentionally kept ambiguous; repeater_report.py can
        # later apply path-context plausibility scoring.
        if (
            self.lookup_strategy == "map_first"
            and meshcore_map
        ):
            return (
                sorted(
                    merged.values(),
                    key=candidate_sort_key,
                ),
                errors,
                successful_sources,
            )

        # CoreScope is only needed as fallback for map_first, or always for
        # merged compatibility mode.
        try:
            corescope = self._corescope_search(path_id)
            successful_sources.append("corescope")

            for node in corescope:
                merged[node.public_key] = merge_node(
                    merged.get(node.public_key),
                    node,
                )

        except Exception as exc:
            errors.append(str(exc))

        return (
            sorted(
                merged.values(),
                key=candidate_sort_key,
            ),
            errors,
            successful_sources,
        )


    def _cached(
        self,
        path_id: str,
    ) -> dict[str, Any] | None:
        row = self.db.execute(
            """
            SELECT *
            FROM path_lookup_cache
            WHERE path_id = ?
            """,
            (path_id,),
        ).fetchone()

        if row is None:
            return None

        if int(row["expires_at"]) < int(time.time()):
            return None

        nodes = self.db.execute(
            """
            SELECT n.*
            FROM path_candidates p
            JOIN nodes n
              ON n.public_key = p.public_key
            WHERE p.path_id = ?
            """,
            (path_id,),
        ).fetchall()

        nodes_sorted = sorted(
            nodes,
            key=candidate_sort_key,
        )

        return {
            "status": str(row["status"]),
            "from_cache": True,
            "candidates": [
                dict(node)
                for node in nodes_sorted
            ],
            "error_text": str(
                row["error_text"] or ""
            ),
        }

    def _save_lookup(
        self,
        path_id: str,
        candidates: list[Node],
        status: str | None = None,
        error_text: str = "",
        lookup_source: str = "directory",
    ) -> str:
        now = int(time.time())

        if status is None:
            if not candidates:
                status = "unresolved"
            elif len(candidates) == 1:
                status = "directory_unique"
            else:
                status = "directory_ambiguous"

        self.db.execute(
            """
            DELETE FROM path_candidates
            WHERE path_id = ?
            """,
            (path_id,),
        )

        for node in candidates:
            self.db.execute(
                """
                INSERT INTO nodes(
                    public_key,
                    node_name,
                    node_role,
                    lat,
                    lon,
                    source,
                    source_url,
                    last_updated,
                    manual_override,
                    last_advert
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(public_key)
                DO UPDATE SET
                    node_name = excluded.node_name,
                    node_role = excluded.node_role,
                    lat = excluded.lat,
                    lon = excluded.lon,
                    source = excluded.source,
                    source_url = excluded.source_url,
                    last_updated = excluded.last_updated,
                    last_advert = excluded.last_advert
                WHERE nodes.manual_override = 0
                """,
                (
                    node.public_key,
                    node.name,
                    node.role,
                    node.lat,
                    node.lon,
                    node.source,
                    node.source_url,
                    node.updated_at,
                    node.last_advert,
                ),
            )

            self.db.execute(
                """
                INSERT INTO path_candidates(
                    path_id,
                    public_key,
                    source,
                    first_seen,
                    last_seen
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(path_id, public_key)
                DO UPDATE SET
                    source = excluded.source,
                    last_seen = excluded.last_seen
                """,
                (
                    path_id,
                    node.public_key,
                    node.source,
                    now,
                    now,
                ),
            )

        if status == "lookup_error":
            ttl = ERROR_TTL
        elif not candidates:
            ttl = NEGATIVE_TTL
        else:
            ttl = POSITIVE_TTL

        self.db.execute(
            """
            INSERT INTO path_lookup_cache(
                path_id,
                status,
                candidate_count,
                checked_at,
                expires_at,
                source,
                error_text
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path_id)
            DO UPDATE SET
                status = excluded.status,
                candidate_count = excluded.candidate_count,
                checked_at = excluded.checked_at,
                expires_at = excluded.expires_at,
                source = excluded.source,
                error_text = excluded.error_text
            """,
            (
                path_id,
                status,
                len(candidates),
                now,
                now + ttl,
                lookup_source,
                error_text,
            ),
        )

        self.db.commit()
        return status

    def lookup(
        self,
        path_id: str,
        refresh: bool = False,
    ) -> dict[str, Any]:
        path_id = norm_hex(path_id)

        if not valid_path_id(path_id):
            raise ValueError(
                "Path-ID muss 1, 2 oder 3 Byte Hex lang sein."
            )

        if not refresh:
            cached = self._cached(path_id)

            if cached is not None:
                return cached

        (
            candidates,
            errors,
            successful_sources,
        ) = self._online_search(path_id)

        lookup_source = (
            "+".join(successful_sources)
            if successful_sources
            else "directory"
        )

        # At least one provider answered successfully: its combined result is
        # authoritative enough to cache. Provider warnings are retained only
        # as diagnostic text and do not force lookup_error.
        if successful_sources:
            error_text = " | ".join(errors)

            status = self._save_lookup(
                path_id,
                candidates,
                error_text=error_text,
                lookup_source=lookup_source,
            )

            return {
                "status": status,
                "from_cache": False,
                "candidates": [
                    {
                        "public_key": node.public_key,
                        "node_name": node.name,
                        "node_role": node.role,
                        "lat": node.lat,
                        "lon": node.lon,
                        "source": node.source,
                        "source_url": node.source_url,
                        "last_updated": node.updated_at,
                        "last_advert": node.last_advert,
                        "manual_override": 0,
                    }
                    for node in candidates
                ],
                "error_text": error_text,
            }

        error_text = (
            " | ".join(errors)
            or "Keine Directory-Quelle erreichbar."
        )

        status = self._save_lookup(
            path_id,
            [],
            status="lookup_error",
            error_text=error_text,
            lookup_source="directory",
        )

        return {
            "status": status,
            "from_cache": False,
            "candidates": [],
            "error_text": error_text,
        }

    def show_cache(self) -> None:
        rows = self.db.execute(
            """
            SELECT
                path_id,
                status,
                candidate_count,
                checked_at,
                expires_at,
                source,
                error_text
            FROM path_lookup_cache
            ORDER BY path_id
            """
        ).fetchall()

        if not rows:
            print("Cache ist leer.")
            return

        print(
            f"{'Path-ID':<10} "
            f"{'Status':<22} "
            f"{'Treffer':<8} "
            f"{'Quelle':<25} "
            f"{'Restzeit'}"
        )
        print("-" * 92)

        now = int(time.time())

        for row in rows:
            remaining = (
                int(row["expires_at"])
                - now
            )

            if remaining <= 0:
                rest = "abgelaufen"
            elif remaining < 3600:
                rest = (
                    f"{remaining // 60} min"
                )
            elif remaining < 86400:
                rest = (
                    f"{remaining // 3600} h"
                )
            else:
                rest = (
                    f"{remaining // 86400} d"
                )

            suffix = ""

            if (
                row["status"] == "lookup_error"
                and row["error_text"]
            ):
                suffix = (
                    "  "
                    + str(
                        row["error_text"]
                    ).replace(
                        "\n",
                        " ",
                    )[:100]
                )

            print(
                f"{row['path_id']:<10} "
                f"{row['status']:<22} "
                f"{row['candidate_count']:<8} "
                f"{str(row['source'] or ''):<25} "
                f"{rest}"
                f"{suffix}"
            )

    def show_map_status(self) -> None:
        print("MeshCore Map Snapshot")
        print("=" * 72)
        print(
            f"Strategie  : {self.lookup_strategy}"
        )
        print(
            f"Datei      : "
            f"{self.map_snapshot_path}"
        )

        if self.map_snapshot_path.exists():
            stat = self.map_snapshot_path.stat()
            age = max(
                0,
                int(
                    time.time()
                    - stat.st_mtime
                ),
            )

            print(
                f"Groesse    : "
                f"{stat.st_size:,} Bytes "
                f"({stat.st_size / (1024 * 1024):.2f} MiB)"
            )
            print(
                f"Alter      : "
                f"{age // 3600} h "
                f"{(age % 3600) // 60} min"
            )
            print(
                f"Gueltig    : "
                f"{'ja' if self._map_snapshot_is_fresh() else 'nein'}"
            )
        else:
            print("Status     : nicht vorhanden")

        state = self.db.execute(
            """
            SELECT *
            FROM directory_source_state
            WHERE source = 'meshcore_map'
            """
        ).fetchone()

        if state is not None:
            print(
                f"Nodes      : "
                f"{state['node_count'] if state['node_count'] is not None else '–'}"
            )
            print(
                f"Letzter OK : "
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(state['last_success'])) if state['last_success'] else '–'}"
            )
            if state["error_text"]:
                print(
                    f"Fehler     : "
                    f"{state['error_text']}"
                )


def print_result(
    path_id: str,
    result: dict[str, Any],
) -> None:
    origin = (
        "Cache"
        if result["from_cache"]
        else "Online"
    )

    candidates = result["candidates"]

    print(
        f"{path_id}: "
        f"{result['status']} "
        f"({len(candidates)} Treffer, {origin})"
    )

    if result.get("error_text"):
        print(
            f"  Hinweis     : "
            f"{result['error_text']}"
        )

    for index, item in enumerate(
        candidates,
        1,
    ):
        position = "–"

        if (
            item.get("lat") is not None
            and item.get("lon") is not None
        ):
            position = (
                f"{item['lat']:.6f}, "
                f"{item['lon']:.6f}"
            )

        print(
            f"  [{index}] "
            f"{item.get('node_name') or '–'}"
        )
        print(
            f"      public_key : "
            f"{item['public_key']}"
        )
        print(
            f"      role       : "
            f"{item.get('node_role') or '–'}"
        )
        print(
            f"      position   : "
            f"{position}"
        )
        print(
            f"      last_advert: "
            f"{item.get('last_advert') or '–'}"
        )
        print(
            f"      source     : "
            f"{item.get('source') or '–'}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Lokaler Multi-Source Node-Directory-Cache "
            f"v{APP_VERSION}."
        )
    )

    parser.add_argument(
        "path_ids",
        nargs="*",
    )

    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="CoreScope Basis-URL.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="CoreScope HTTP-Timeout.",
    )

    parser.add_argument(
        "--map-url",
        default=DEFAULT_MAP_URL,
        help="MeshCore Map Nodes-API.",
    )

    parser.add_argument(
        "--map-snapshot",
        default="",
        help=(
            "Optionaler Snapshot-Pfad. "
            "Standard: neben node_directory.db."
        ),
    )

    parser.add_argument(
        "--map-ttl-hours",
        type=float,
        default=(
            DEFAULT_MAP_SNAPSHOT_TTL
            / 3600
        ),
        help=(
            "Gueltigkeit des MeshCore-Map-Snapshots "
            "in Stunden (Standard: 6)."
        ),
    )

    parser.add_argument(
        "--map-timeout",
        type=float,
        default=DEFAULT_MAP_TIMEOUT,
    )

    parser.add_argument(
        "--lookup-strategy",
        choices=("map_first", "merged"),
        default="map_first",
        help=(
            "Aufloesungsstrategie: 'map_first' (Standard) nutzt den "
            "MeshCore-Map-Snapshot zuerst und fragt CoreScope nur bei "
            "0 Map-Treffern; 'merged' fragt wie v0.4 immer beide Quellen."
        ),
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Path-ID-Cache ignorieren und beide "
            "Directory-Quellen neu auswerten. "
            "Ein noch gueltiger Map-Snapshot wird dabei "
            "weiterverwendet."
        ),
    )

    parser.add_argument(
        "--refresh-map",
        action="store_true",
        help=(
            "MeshCore-Map-Snapshot beim ersten Lookup "
            "dieses Laufs neu herunterladen."
        ),
    )

    parser.add_argument(
        "--show-cache",
        action="store_true",
        help="Aktuellen Lookup-Cache anzeigen.",
    )

    parser.add_argument(
        "--map-status",
        action="store_true",
        help="Status des lokalen MeshCore-Map-Snapshots anzeigen.",
    )

    args = parser.parse_args()

    map_snapshot_path = (
        args.map_snapshot
        if args.map_snapshot
        else None
    )

    directory = NodeDirectory(
        db_path=args.db,
        base_url=args.base_url,
        timeout=args.timeout,
        map_url=args.map_url,
        map_snapshot_path=map_snapshot_path,
        map_snapshot_ttl=int(
            max(
                0.0,
                args.map_ttl_hours,
            )
            * 3600
        ),
        map_timeout=args.map_timeout,
        refresh_map=args.refresh_map,
        lookup_strategy=args.lookup_strategy,
    )

    try:
        displayed = False

        if args.show_cache:
            directory.show_cache()
            displayed = True

        if args.map_status:
            if displayed:
                print()
            directory.show_map_status()
            displayed = True

        if not args.path_ids:
            if not displayed:
                parser.print_help()
            return 0

        if displayed:
            print()

        for raw in args.path_ids:
            path_id = norm_hex(raw)

            try:
                result = directory.lookup(
                    path_id,
                    refresh=args.refresh,
                )
                print_result(
                    path_id,
                    result,
                )
            except Exception as exc:
                print(
                    f"{path_id}: FEHLER: {exc}"
                )

            print()

        return 0

    finally:
        directory.close()


if __name__ == "__main__":
    raise SystemExit(main())
