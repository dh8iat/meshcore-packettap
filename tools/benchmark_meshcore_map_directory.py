#!/usr/bin/env python3
"""
benchmark_meshcore_map_directory.py

Kleines Benchmark-/Diagnose-Skript fuer die offizielle MeshCore Map API.

Verglichen werden:
  1. JSON:
       /api/v1/nodes?short=1
  2. MessagePack:
       /api/v1/nodes?binary=1&short=1

Gemessen werden:
  - HTTP-Downloadzeit
  - uebertragene Bytes
  - Decode-Zeit
  - Anzahl geladener Nodes
  - Anzahl erkannter Public Keys
  - lokale Prefix-Suchzeit fuer Test-Path-IDs

Das Skript schreibt NICHT nach QuestDB oder SQLite.

Voraussetzung fuer MessagePack:
    pip install msgpack

Beispiele:
    python benchmark_meshcore_map_directory.py
    python benchmark_meshcore_map_directory.py 1dea 827c bbca 1dea8f 6dc4 89e5 01e4
    python benchmark_meshcore_map_directory.py --runs 3
    python benchmark_meshcore_map_directory.py --timeout 90
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

DEFAULT_API_URL = "https://map.meshcore.dev/api/v1/nodes"
DEFAULT_IDS = ["1dea", "827c", "bbca", "1dea8f", "6dc4", "89e5", "01e4"]
USER_AGENT = "MeshCore-PacketTap-MapBenchmark/0.1"


@dataclass
class RunResult:
    label: str
    url: str
    content_type: str
    byte_count: int
    download_s: float
    decode_s: float
    normalize_s: float
    search_s: float
    node_count: int
    key_count: int
    matches: dict[str, list[str]]

    @property
    def total_s(self) -> float:
        return self.download_s + self.decode_s + self.normalize_s + self.search_s


def norm_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return "".join(
        ch for ch in str(value or "").strip().lower()
        if ch in "0123456789abcdef"
    )


def valid_path_id(value: str) -> bool:
    value = norm_hex(value)
    return len(value) in (2, 4, 6)


def public_key_of(node: dict[str, Any]) -> str | None:
    for key in (
        "public_key",
        "pubkey",
        "publicKey",
        "pk",
        "key",
        "node_id",
        "nodeId",
    ):
        value = node.get(key)
        if value not in (None, ""):
            public_key = norm_hex(value)
            if len(public_key) == 64:
                return public_key
    return None


def extract_nodes(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    for key in ("nodes", "items", "results", "data", "entries"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

        if isinstance(value, dict):
            for subkey in ("nodes", "items", "results", "data"):
                sub = value.get(subkey)
                if isinstance(sub, list):
                    return [item for item in sub if isinstance(item, dict)]

    if public_key_of(payload):
        return [payload]

    return []


def request_bytes(url: str, timeout: float) -> tuple[bytes, str, float]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/json, application/msgpack, "
                "application/octet-stream;q=0.9, */*;q=0.1"
            ),
        },
    )

    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
        content_type = response.headers.get("Content-Type", "")
    elapsed = time.perf_counter() - started

    return raw, content_type, elapsed


def decode_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def decode_msgpack(raw: bytes) -> Any:
    try:
        import msgpack  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Python-Paket 'msgpack' fehlt. Installieren mit: pip install msgpack"
        ) from exc

    return msgpack.unpackb(
        raw,
        raw=False,
        strict_map_key=False,
    )


def benchmark_once(
    label: str,
    url: str,
    decoder: Callable[[bytes], Any],
    path_ids: list[str],
    timeout: float,
) -> RunResult:
    raw, content_type, download_s = request_bytes(url, timeout)

    started = time.perf_counter()
    payload = decoder(raw)
    decode_s = time.perf_counter() - started

    started = time.perf_counter()
    nodes = extract_nodes(payload)
    public_keys = [
        key
        for node in nodes
        if (key := public_key_of(node)) is not None
    ]
    normalize_s = time.perf_counter() - started

    started = time.perf_counter()
    matches = {
        path_id: [
            public_key
            for public_key in public_keys
            if public_key.startswith(path_id)
        ]
        for path_id in path_ids
    }
    search_s = time.perf_counter() - started

    return RunResult(
        label=label,
        url=url,
        content_type=content_type,
        byte_count=len(raw),
        download_s=download_s,
        decode_s=decode_s,
        normalize_s=normalize_s,
        search_s=search_s,
        node_count=len(nodes),
        key_count=len(public_keys),
        matches=matches,
    )


def mib(byte_count: int) -> float:
    return byte_count / (1024 * 1024)


def print_run(result: RunResult, run_no: int, runs: int) -> None:
    suffix = f" (Lauf {run_no}/{runs})" if runs > 1 else ""

    print()
    print(f"{result.label}{suffix}")
    print("-" * 76)
    print(f"URL             : {result.url}")
    print(f"Content-Type    : {result.content_type or '–'}")
    print(
        f"Download        : {result.byte_count:,} Bytes "
        f"({mib(result.byte_count):.2f} MiB)"
    )
    print(f"Downloadzeit    : {result.download_s:.3f} s")
    print(f"Decode-Zeit     : {result.decode_s:.3f} s")
    print(f"Normalize-Zeit  : {result.normalize_s:.3f} s")
    print(f"Prefix-Suche    : {result.search_s:.6f} s")
    print(f"Gesamt gemessen : {result.total_s:.3f} s")
    print(f"Nodes           : {result.node_count:,}")
    print(f"Public Keys     : {result.key_count:,}")

    print()
    print("Path-ID-Treffer:")
    for path_id, matches in result.matches.items():
        print(f"  {path_id:<8} {len(matches):>4} Treffer")


def mean(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


def summarize(label: str, results: list[RunResult]) -> None:
    print(f"{label:<18}", end="")
    print(
        f"{mib(int(mean([r.byte_count for r in results]))):>10.2f} "
        f"{mean([r.download_s for r in results]):>12.3f} "
        f"{mean([r.decode_s for r in results]):>10.3f} "
        f"{mean([r.normalize_s for r in results]):>11.3f} "
        f"{mean([r.search_s for r in results]):>10.6f} "
        f"{mean([r.total_s for r in results]):>10.3f}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark JSON vs. MessagePack fuer die offizielle "
            "MeshCore Map Node-API."
        )
    )
    parser.add_argument(
        "path_ids",
        nargs="*",
        default=DEFAULT_IDS,
        help="Path-IDs, z.B. 1dea 827c bbca 1dea8f",
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"API-Endpunkt (Standard: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Anzahl Durchlaeufe je Variante (Standard: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="HTTP-Timeout je Download in Sekunden (Standard: 90)",
    )
    args = parser.parse_args()

    if args.runs < 1:
        parser.error("--runs muss mindestens 1 sein")

    path_ids = [norm_hex(value) for value in args.path_ids]
    invalid = [value for value in path_ids if not valid_path_id(value)]
    if invalid:
        print(
            "Ungueltige Path-ID(s): " + ", ".join(invalid),
            file=sys.stderr,
        )
        return 2

    json_url = args.api_url + "?" + urllib.parse.urlencode(
        {"short": "1"}
    )
    msgpack_url = args.api_url + "?" + urllib.parse.urlencode(
        {"binary": "1", "short": "1"}
    )

    variants: list[tuple[str, str, Callable[[bytes], Any]]] = [
        ("JSON short", json_url, decode_json),
        ("MessagePack short", msgpack_url, decode_msgpack),
    ]

    print("MeshCore Map API Benchmark")
    print("=" * 76)
    print(f"Basis-API : {args.api_url}")
    print(f"Path-IDs  : {', '.join(path_ids)}")
    print(f"Durchlaeufe je Variante: {args.runs}")
    print()
    print(
        "Hinweis: Die Downloadzeiten enthalten Internet-, Server- und "
        "Netzwerklatenz."
    )

    all_results: dict[str, list[RunResult]] = {
        label: [] for label, _, _ in variants
    }

    for run_no in range(1, args.runs + 1):
        for label, url, decoder in variants:
            try:
                result = benchmark_once(
                    label,
                    url,
                    decoder,
                    path_ids,
                    args.timeout,
                )
            except Exception as exc:
                print()
                print(f"{label} (Lauf {run_no}/{args.runs})")
                print("-" * 76)
                print(f"FEHLER: {exc}")
                continue

            all_results[label].append(result)
            print_run(result, run_no, args.runs)

    available = {
        label: results
        for label, results in all_results.items()
        if results
    }

    if not available:
        print()
        print("Keine Variante konnte erfolgreich getestet werden.")
        return 1

    print()
    print("Zusammenfassung / Mittelwerte")
    print("=" * 76)
    print(
        f"{'Variante':<18}"
        f"{'MiB':>10} "
        f"{'Download s':>12} "
        f"{'Decode s':>10} "
        f"{'Norm s':>11} "
        f"{'Suche s':>10} "
        f"{'Gesamt s':>10}"
    )
    print("-" * 76)

    for label, _, _ in variants:
        results = available.get(label)
        if results:
            summarize(label, results)

    json_results = available.get("JSON short")
    msgpack_results = available.get("MessagePack short")

    if json_results and msgpack_results:
        json_bytes = mean([r.byte_count for r in json_results])
        msg_bytes = mean([r.byte_count for r in msgpack_results])
        json_download = mean([r.download_s for r in json_results])
        msg_download = mean([r.download_s for r in msgpack_results])
        json_decode = mean([r.decode_s for r in json_results])
        msg_decode = mean([r.decode_s for r in msgpack_results])

        print()
        print("Direkter Vergleich")
        print("=" * 76)

        if json_bytes > 0:
            saving = 100.0 * (1.0 - msg_bytes / json_bytes)
            factor = json_bytes / msg_bytes if msg_bytes else float("inf")
            print(
                f"MessagePack spart beim Transfer: {saving:.1f} % "
                f"(JSON ist {factor:.2f}x so gross)"
            )

        if msg_download > 0:
            print(
                f"Downloadzeit JSON/MessagePack: "
                f"{json_download:.3f} / {msg_download:.3f} s "
                f"(Faktor {json_download / msg_download:.2f})"
            )

        if msg_decode > 0:
            print(
                f"Decode-Zeit JSON/MessagePack : "
                f"{json_decode:.3f} / {msg_decode:.3f} s "
                f"(Faktor {json_decode / msg_decode:.2f})"
            )

        first_json = json_results[0]
        first_msg = msgpack_results[0]

        same_counts = (
            first_json.node_count == first_msg.node_count
            and first_json.key_count == first_msg.key_count
        )
        same_matches = all(
            len(first_json.matches.get(pid, []))
            == len(first_msg.matches.get(pid, []))
            for pid in path_ids
        )

        print(
            "Datenbestand Node/Public-Key-Anzahl: "
            + ("IDENTISCH" if same_counts else "ABWEICHEND")
        )
        print(
            "Trefferzahlen der Test-Path-IDs    : "
            + ("IDENTISCH" if same_matches else "ABWEICHEND")
        )

        if not same_matches:
            print()
            print("Abweichende Trefferzahlen:")
            for pid in path_ids:
                a = len(first_json.matches.get(pid, []))
                b = len(first_msg.matches.get(pid, []))
                if a != b:
                    print(
                        f"  {pid}: JSON={a}, MessagePack={b}"
                    )

    print()
    print("Hinweis:")
    print(
        "Das Skript schreibt nichts nach QuestDB, SQLite oder "
        "node_directory.db."
    )
    print(
        "Fuer eine realistischere Aussage koennen mehrere Durchlaeufe "
        "mit --runs 3 ausgefuehrt werden."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
