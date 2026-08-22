#!/usr/bin/env python3
"""
MeshCore PacketTap - Public Channel Updater
Version: 0.3

Neue Channels aus marcelverdult/meshcore-channels werden nur übernommen, wenn
sie gegen historische GRP_TXT-Pakete aus einer oder mehreren QuestDBs
kryptografisch bestätigt werden:

    1-Byte-Hash -> Kandidat -> 2-Byte-MAC -> AES -> gültiger GRP_TXT

Ein Treffer zählt nur, wenn meshcore_decoder.decrypt_grp_txt() gleichzeitig
mac_ok=True UND ok=True liefert.

Standard ist DRY-RUN. Bestehende lokale Channels bleiben erhalten.

v0.2.1:
- --min-matches verwendet standardmäßig 2 statt 1.
- Damit müssen neue Upstream-Channels durch mindestens zwei verschiedene
  gültige historische GRP_TXT-Payloads bestätigt werden.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import sys
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

APP_VERSION = "0.3"

# Windows consoles and subprocess pipes may default to cp1252. Force UTF-8 so
# decoded sender names and message texts can safely contain emoji and Unicode.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
DEFAULT_QUESTDB_URL = "http://127.0.0.1:9000"
UPSTREAM_URL = (
    "https://raw.githubusercontent.com/"
    "marcelverdult/meshcore-channels/main/channels-unique.json"
)


def sha_secret(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]


def channel_hash(secret_hex: str) -> str | None:
    try:
        raw = bytes.fromhex(secret_hex)
    except ValueError:
        return None
    if len(raw) != 16:
        return None
    return hashlib.sha256(raw).hexdigest()[:2]


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": f"meshcore-packettap/{APP_VERSION}",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def qdb(base_url: str, sql: str) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/exec?" + urllib.parse.urlencode({"query": sql})
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read()
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if data.get("error"):
        raise RuntimeError(str(data["error"]))
    return data


def rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    cols = [
        str(c.get("name")) if isinstance(c, dict) else str(c)
        for c in (result.get("columns") or [])
    ]
    return [dict(zip(cols, row)) for row in (result.get("dataset") or [])]


def sqlq(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def normalize_date(value: str | None, end: bool = False) -> str | None:
    if not value:
        return None
    value = value.strip()
    if len(value) == 10:
        datetime.strptime(value, "%Y-%m-%d")
        return value + (
            "T23:59:59.999999Z" if end else "T00:00:00.000000Z"
        )
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def decode_b64_key(value: Any) -> str | None:
    try:
        raw = base64.b64decode(str(value).strip(), validate=True)
    except Exception:
        return None
    return raw.hex() if len(raw) == 16 else None


def load_upstream(data: Any) -> list[dict[str, str]]:
    result = []
    for entry in data.get("channels", []) if isinstance(data, dict) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("channel") or "").strip()
        if not name:
            continue
        secret = sha_secret(name) if name.startswith("#") else decode_b64_key(entry.get("key"))
        if not secret:
            continue
        h = channel_hash(secret)
        if h:
            result.append({"name": name, "secret_hex": secret, "hash": h})
    return result


def load_local(channels_path: Path, keys_path: Path) -> list[dict[str, str]]:
    result = []
    for name in load_json(channels_path, []):
        name = str(name or "").strip()
        if name:
            secret = sha_secret(name)
            h = channel_hash(secret)
            if h:
                result.append({"name": name, "secret_hex": secret, "hash": h})

    for entry in load_json(keys_path, []):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        secret = str(entry.get("key_hex") or "").strip().lower()
        if not name or len(secret) != 32:
            continue
        h = channel_hash(secret)
        if h:
            result.append({"name": name, "secret_hex": secret, "hash": h})
    return result


def load_payloads(
    questdb_url: str,
    date_from: str | None,
    date_to: str | None,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    where = [
        "payload_type = 'GRP_TXT'",
        "packet_payload_hex IS NOT NULL",
        "packet_payload_hex != ''",
    ]
    if date_from:
        where.append(f"ts >= {sqlq(date_from)}")
    if date_to:
        where.append(f"ts <= {sqlq(date_to)}")

    sql = f"""
SELECT
    left(packet_payload_hex, 2) AS channel_hash,
    packet_payload_hex,
    count(*) AS pakete,
    min(ts) AS zuerst,
    max(ts) AS zuletzt
FROM mc_rx
WHERE {' AND '.join(where)}
GROUP BY left(packet_payload_hex, 2), packet_payload_hex
ORDER BY channel_hash, pakete DESC;
"""
    by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    totals: dict[str, int] = defaultdict(int)

    for row in rows(qdb(questdb_url, sql)):
        h = str(row.get("channel_hash") or "").lower()
        payload = str(row.get("packet_payload_hex") or "").lower()
        if len(h) != 2 or not payload:
            continue
        count = int(row.get("pakete") or 0)
        by_hash[h].append({
            "payload": payload,
            "pakete": count,
            "zuerst": row.get("zuerst"),
            "zuletzt": row.get("zuletzt"),
        })
        totals[h] += count

    return dict(by_hash), dict(totals)


def load_payloads_multi(
    questdb_urls: list[str],
    date_from: str | None,
    date_to: str | None,
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, int],
    list[dict[str, Any]],
]:
    """
    Load and merge historical GRP_TXT payloads from multiple QuestDBs.

    Identical packet_payload_hex values seen at several sites are de-duplicated
    for cryptographic verification, while their packet counters are summed for
    reporting. Therefore --min-matches counts different payloads, not duplicate
    receptions of the same payload at several sites.
    """
    merged: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    totals: dict[str, int] = defaultdict(int)
    db_stats: list[dict[str, Any]] = []

    for url in questdb_urls:
        payloads_by_hash, db_totals = load_payloads(url, date_from, date_to)

        distinct_payloads = 0
        for h, items in payloads_by_hash.items():
            for item in items:
                distinct_payloads += 1
                payload = item["payload"]
                existing = merged[h].get(payload)
                if existing is None:
                    merged[h][payload] = dict(item)
                else:
                    existing["pakete"] = int(existing.get("pakete") or 0) + int(
                        item.get("pakete") or 0
                    )

        for h, count in db_totals.items():
            totals[h] += int(count or 0)

        db_stats.append({
            "url": url,
            "hashes": len(payloads_by_hash),
            "packets": sum(db_totals.values()),
            "payloads": distinct_payloads,
        })

    return (
        {
            h: list(payload_map.values())
            for h, payload_map in merged.items()
        },
        dict(totals),
        db_stats,
    )


def verify(
    decoder: Any,
    candidate: dict[str, str],
    payloads: list[dict[str, Any]],
    min_matches: int,
    max_payloads: int | None,
) -> dict[str, Any]:
    tested = mac_matches = valid_matches = 0
    example = None

    for item in payloads:
        if max_payloads is not None and tested >= max_payloads:
            break
        tested += 1
        d = decoder.decrypt_grp_txt(
            item["payload"],
            candidate["name"],
            secret_hex=candidate["secret_hex"],
        )
        if d.get("mac_ok") is True:
            mac_matches += 1
        if d.get("mac_ok") is True and d.get("ok") is True:
            valid_matches += 1
            if example is None:
                example = {
                    "sender": d.get("sender_name"),
                    "body": d.get("body"),
                    "zuerst": item.get("zuerst"),
                    "zuletzt": item.get("zuletzt"),
                    "pakete": item.get("pakete"),
                }
            if valid_matches >= min_matches:
                break

    return {
        "verified": valid_matches >= min_matches,
        "tested": tested,
        "mac_matches": mac_matches,
        "valid_matches": valid_matches,
        "example": example,
    }


def build_outputs(selected: list[dict[str, str]]) -> tuple[list[str], list[dict[str, str]]]:
    channels = sorted({
        x["name"] for x in selected if x["name"].startswith("#")
    })
    keys = {}
    for x in selected:
        if not x["name"].startswith("#"):
            keys[(x["name"], x["secret_hex"])] = {
                "name": x["name"],
                "key_hex": x["secret_hex"],
            }
    return channels, sorted(keys.values(), key=lambda x: (x["name"], x["key_hex"]))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Community-Channels per MAC+Decrypt gegen historische GRP_TXT verifizieren."
    )
    ap.add_argument(
        "--questdb-url",
        action="append",
        dest="questdb_urls",
        help=(
            "QuestDB HTTP URL. Kann mehrfach angegeben werden. "
            f"Default: {DEFAULT_QUESTDB_URL}"
        ),
    )
    ap.add_argument("--upstream-url", default=UPSTREAM_URL)
    ap.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument("--from", dest="date_from")
    ap.add_argument("--to", dest="date_to")
    ap.add_argument("--days", type=int)
    ap.add_argument("--min-matches", type=int, default=2)
    ap.add_argument("--max-payloads-per-candidate", type=int)
    ap.add_argument("--prune-local", action="store_true")
    ap.add_argument("--show", type=int, default=100)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    if args.min_matches < 1:
        ap.error("--min-matches muss >= 1 sein.")
    if args.days is not None and args.days < 1:
        ap.error("--days muss >= 1 sein.")
    if args.days and args.date_from:
        ap.error("--days und --from nicht gleichzeitig verwenden.")

    date_from = normalize_date(args.date_from)
    date_to = normalize_date(args.date_to, end=True)
    if args.days:
        date_from = (
            datetime.now(timezone.utc) - timedelta(days=args.days)
        ).isoformat().replace("+00:00", "Z")

    questdb_urls = args.questdb_urls or [DEFAULT_QUESTDB_URL]

    project = args.project_dir.resolve()
    channels_path = project / "public_channels.json"
    keys_path = project / "public_channel_keys.json"

    if str(project) not in sys.path:
        sys.path.insert(0, str(project))
    import meshcore_decoder as decoder

    print("MeshCore Public Channel Updater")
    print("=" * 92)
    print(f"Version             : {APP_VERSION}")
    print(f"Decoder-Version     : {getattr(decoder, 'APP_VERSION', 'unbekannt')}")
    print(
        "QuestDBs            : "
        + ", ".join(questdb_urls)
    )
    print(f"Zeitraum von        : {date_from or 'gesamter Datenbestand'}")
    print(f"Zeitraum bis        : {date_to or 'offen'}")
    print(f"Min. gültige Matches: {args.min_matches}")
    print(f"Lokale Einträge     : {'nur verifizierte' if args.prune_local else 'bestehende behalten'}")
    print(f"Modus               : {'APPLY' if args.apply else 'DRY-RUN'}")
    print()

    print("Lese historische GRP_TXT-Payloads aus QuestDB ...")
    payloads_by_hash, totals, db_stats = load_payloads_multi(
        questdb_urls,
        date_from,
        date_to,
    )
    print(f"QuestDB-Endpunkte   : {len(db_stats)}")
    print(f"Beobachtete Hashes  : {len(payloads_by_hash)}")
    print(f"GRP_TXT-Pakete      : {sum(totals.values())}")
    print(f"Untersch. Payloads  : {sum(len(v) for v in payloads_by_hash.values())}")
    for stat in db_stats:
        print(
            f"  {stat['url']} -> "
            f"{stat['packets']} Pakete, "
            f"{stat['hashes']} Hashes, "
            f"{stat['payloads']} unterschiedliche Payloads"
        )
    print()

    upstream = load_upstream(fetch_json(args.upstream_url))
    local = load_local(channels_path, keys_path)

    upstream_map = {(x["name"], x["secret_hex"]): x for x in upstream}
    local_map = {(x["name"], x["secret_hex"]): x for x in local}

    to_test = [x for x in upstream_map.values() if x["hash"] in payloads_by_hash]

    print(f"Upstream verwendbar : {len(upstream_map)}")
    print(f"Lokale Quelle       : {len(local_map)}")
    print(f"Upstream zu testen  : {len(to_test)}")
    print("Verifiziere MAC + AES + GRP_TXT ...")

    verified_upstream = []
    details = []
    verified_by_hash: dict[str, list[str]] = defaultdict(list)

    for i, candidate in enumerate(to_test, 1):
        result = verify(
            decoder,
            candidate,
            payloads_by_hash[candidate["hash"]],
            args.min_matches,
            args.max_payloads_per_candidate,
        )
        if result["verified"]:
            verified_upstream.append(candidate)
            details.append((candidate, result))
            verified_by_hash[candidate["hash"]].append(candidate["name"])
        if i % 100 == 0:
            print(f"  {i}/{len(to_test)} getestet, {len(verified_upstream)} verifiziert")

    verified_local = set()
    for key, candidate in local_map.items():
        if candidate["hash"] not in payloads_by_hash:
            continue
        result = verify(
            decoder,
            candidate,
            payloads_by_hash[candidate["hash"]],
            args.min_matches,
            args.max_payloads_per_candidate,
        )
        if result["verified"]:
            verified_local.add(key)

    selected = {}
    if args.prune_local:
        for key in verified_local:
            selected[key] = local_map[key]
    else:
        selected.update(local_map)

    for candidate in verified_upstream:
        selected[(candidate["name"], candidate["secret_hex"])] = candidate

    channels, keys = build_outputs(list(selected.values()))

    print()
    print("Verifizierte Upstream-Channels")
    print("-" * 92)
    for candidate, result in details[:args.show]:
        ex = result["example"] or {}
        body = str(ex.get("body") or "")[:60]
        print(
            f"{candidate['hash']}  {candidate['name']:<28} "
            f"valid={result['valid_matches']} tested={result['tested']} "
            f"sender={ex.get('sender')!r} text={body!r}"
        )
    if len(details) > args.show:
        print(f"... {len(details) - args.show} weitere")
    print()

    unresolved = sorted(
        set(payloads_by_hash) - set(verified_by_hash),
        key=lambda h: (-totals[h], h),
    )
    multi = {
        h: sorted(set(names))
        for h, names in verified_by_hash.items()
        if len(set(names)) > 1
    }

    old_channels = load_json(channels_path, [])
    old_set = set(old_channels) if isinstance(old_channels, list) else set()
    new_set = set(channels)
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)

    print("Ergebnis")
    print("-" * 92)
    print(f"Upstream gesamt     : {len(upstream_map)}")
    print(f"Upstream getestet   : {len(to_test)}")
    print(f"Upstream verifiziert: {len(verified_upstream)}")
    print(f"Lokale verifiziert  : {len(verified_local)} / {len(local_map)}")
    print(f"Ausgabe #Channels   : {len(channels)}")
    print(f"Ausgabe expl. Keys  : {len(keys)}")
    print(f"Verifizierte Hashes : {len(verified_by_hash)}")
    print(f"Mehrfach verifiziert: {len(multi)}")
    print(f"Unaufgelöste Hashes : {len(unresolved)}")
    print(f"Neu                 : {len(added)}")
    print(f"Entfallen            : {len(removed)}")

    if added:
        print("Neue Einträge       : " + ", ".join(added[:50]))
    if removed:
        print("Entfallene Einträge : " + ", ".join(removed[:50]))

    if multi:
        print()
        print("Mehrere vollständig verifizierte Channels für denselben Hash")
        print("-" * 92)
        for h, names in sorted(multi.items()):
            print(f"{h}: {', '.join(names)}")

    if unresolved:
        print()
        print("Top unbeantwortete Hashes")
        print("-" * 92)
        for h in unresolved[:30]:
            print(f"{h}  {totals[h]:8d} Pakete")

    if not args.apply:
        print()
        print("DRY-RUN beendet. Keine Dateien verändert.")
        print("Nur MAC+Decrypt-verifizierte Upstream-Channels würden neu übernommen.")
        return 0

    for path in (channels_path, keys_path):
        if path.exists():
            backup = path.with_suffix(path.suffix + ".bak")
            shutil.copy2(path, backup)
            print(f"Backup              : {backup}")

    channels_path.write_text(
        json.dumps(channels, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    keys_path.write_text(
        json.dumps(keys, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print()
    print(f"Geschrieben          : {channels_path}")
    print(f"Geschrieben          : {keys_path}")
    print("Importer/Analyzer danach neu starten, damit der Decoder-Cache neu geladen wird.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
