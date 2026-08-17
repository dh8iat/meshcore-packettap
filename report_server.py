#!/usr/bin/env python3
"""
MeshCore PacketTap Web UI v0.39
====================================

Kleine plattformunabhängige Weboberfläche für repeater_report.py.

Abhängigkeiten:
    Python-Standardbibliothek. Für PDF-Speicherung wird lokal
    Microsoft Edge oder Google Chrome verwendet.

Voraussetzungen:
    - report_server.py und repeater_report.py liegen im selben Verzeichnis.
    - report_config.json liegt ebenfalls dort.
    - QuestDB ist vom Rechner aus erreichbar.

Start:
    python report_server.py

Danach im Browser:
    http://127.0.0.1:8080

Unter Linux kann in report_config.json web_host auf 0.0.0.0 gesetzt werden,
damit die Oberfläche im lokalen Netz erreichbar ist.
"""

from __future__ import annotations

import html
import json
import os
import re
import mimetypes
import sys
import subprocess
import shutil
import time
import uuid
from datetime import date, timedelta
from collections import Counter, defaultdict
from statistics import median
import math
import urllib.request
import urllib.error
import unicodedata
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import repeater_report as rr
import mesh_report as mr


APP_VERSION = "0.39"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "report_config.json"
MAP_DIR = BASE_DIR / "map"
REPORTS_DIR = BASE_DIR / "reports"
PREVIEW_DIR = BASE_DIR / "state" / "report_preview"

DEFAULT_CONFIG = {
    "questdb_host": "192.168.1.2",
    "questdb_port": 9000,
    "receiver_name": "Stutensee - Spoeck",
    "receiver_id": "",
    "output_dir": "reports",
    "web_host": "127.0.0.1",
    "web_port": 8080,
    "receiver_script": "receiver.py",
    "receiver_args": ["--append"],
    "receiver_lock": "state/receiver.lock",
    "receiver_stop": "state/receiver.stop",
    "importer_script": "packettap_importer.py",
    "importer_args": ["--follow"],
    "importer_lock": "state/importer.lock",
    "importer_stop": "state/importer.stop",
    "log_dir": "logs",
    "importer_state": "state/importer.state",
    "dashboard_refresh_seconds": 15,
    "auto_start_receiver": True,
    "auto_start_importer": True,
}


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def load_config() -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)

    if CONFIG_FILE.exists():
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise RuntimeError("report_config.json muss ein JSON-Objekt enthalten.")
        config.update(raw)

    config["questdb_host"] = str(config["questdb_host"]).strip()
    config["questdb_port"] = int(config["questdb_port"])
    config["receiver_name"] = str(config.get("receiver_name", "")).strip()
    config["receiver_id"] = str(config.get("receiver_id", "")).strip()
    config["output_dir"] = str(config.get("output_dir", "reports")).strip() or "reports"
    config["web_host"] = str(config.get("web_host", "127.0.0.1")).strip()
    config["web_port"] = int(config.get("web_port", 8080))
    config["receiver_script"] = str(config.get("receiver_script", "receiver.py")).strip() or "receiver.py"
    config["importer_script"] = str(config.get("importer_script", "packettap_importer.py")).strip() or "packettap_importer.py"
    config["log_dir"] = str(config.get("log_dir", "logs")).strip() or "logs"
    config["importer_state"] = str(config.get("importer_state", "state/importer.state")).strip() or "state/importer.state"
    config["receiver_lock"] = str(config.get("receiver_lock", "state/receiver.lock")).strip() or "state/receiver.lock"
    config["receiver_stop"] = str(config.get("receiver_stop", "state/receiver.stop")).strip() or "state/receiver.stop"
    config["importer_lock"] = str(config.get("importer_lock", "state/importer.lock")).strip() or "state/importer.lock"
    config["importer_stop"] = str(config.get("importer_stop", "state/importer.stop")).strip() or "state/importer.stop"
    config["dashboard_refresh_seconds"] = max(
        0,
        int(config.get("dashboard_refresh_seconds", 15)),
    )
    config["auto_start_receiver"] = bool(
        config.get("auto_start_receiver", True)
    )
    config["auto_start_importer"] = bool(
        config.get("auto_start_importer", True)
    )

    def normalize_args(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        if isinstance(value, str):
            # Config strings are accepted for convenience; shell parsing is not used.
            import shlex
            return shlex.split(value, posix=not sys.platform.startswith("win"))
        raise RuntimeError("Script-Argumente müssen als Liste oder Text angegeben werden.")

    config["receiver_args"] = normalize_args(config.get("receiver_args", ["--append"]))
    if "--append" not in config["receiver_args"]:
        config["receiver_args"].append("--append")
    config["importer_args"] = normalize_args(config.get("importer_args", ["--follow"]))

    return config


def save_config(config: dict[str, Any]) -> None:
    CONFIG_FILE.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def output_dir(config: dict[str, Any]) -> Path:
    path = Path(config["output_dir"])
    if not path.is_absolute():
        path = BASE_DIR / path
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def normalize_date(value: str, end: bool = False) -> str:
    value = value.strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise RuntimeError("Datum muss im Format JJJJ-MM-TT angegeben werden.")
    return value + ("T23:59:59Z" if end else "T00:00:00Z")


def safe_filename(value: str) -> str:
    value = unicodedata.normalize("NFKD", value)
    value = value.encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-._")
    return value or "repeater"


def resolve_repeater(
    resolver: rr.ContactResolver,
    query: str,
) -> rr.Contact:
    query = query.strip()
    if not query:
        raise RuntimeError("Bitte einen Repeaternamen oder 2-Byte-Hash angeben.")

    # Vollständiger Public Key.
    if re.fullmatch(r"[0-9a-fA-F]{64}", query):
        return rr.resolve_selected_repeater(
            resolver,
            query,
            None,
        )

    # 2-Byte-Hash = 4 Hex-Zeichen.
    if re.fullmatch(r"[0-9a-fA-F]{4}", query):
        prefix = query.lower()
        matches = [
            contact
            for contact in resolver.repeaters
            if contact.public_key.startswith(prefix)
        ]

        if not matches:
            raise RuntimeError(
                f"Kein Repeater mit 2-Byte-Hash {query!r} gefunden."
            )

        if len(matches) > 1:
            lines = ", ".join(
                f"{c.adv_name or '(ohne Namen)'} ({c.public_key[:8]})"
                for c in matches[:10]
            )
            raise RuntimeError(
                f"Der 2-Byte-Hash {query!r} ist nicht eindeutig: {lines}"
            )

        return matches[0]

    # Ansonsten exakter Repeatername.
    return rr.resolve_selected_repeater(
        resolver,
        None,
        query,
    )


def get_contacts(config: dict[str, Any]) -> list[rr.Contact]:
    db = rr.QuestDB(config["questdb_host"], config["questdb_port"])
    return rr.load_contacts(db)


def generate_report(
    config: dict[str, Any],
    repeater_query: str,
    date_from: str,
    date_to: str,
) -> tuple[str, str, rr.Contact]:
    """Build a repeater report preview without permanently saving it."""
    period_from = normalize_date(date_from, end=False)
    period_to = normalize_date(date_to, end=True)

    db = rr.QuestDB(config["questdb_host"], config["questdb_port"])

    contacts = rr.load_contacts(db)
    resolver = rr.ContactResolver(contacts)
    selected = resolve_repeater(resolver, repeater_query)

    receiver_id = config.get("receiver_id") or None
    receiver_name = config.get("receiver_name") or None

    rx = rr.load_rx(
        db,
        period_from,
        period_to,
        receiver_id,
        receiver_name,
    )

    observations = rr.load_contact_observations(
        db,
        period_from,
        period_to,
        receiver_id,
        receiver_name,
    )

    rr.load_adverts(
        db,
        period_from,
        period_to,
    )

    metrics, neighbors, neighbors_gt3, ranking = rr.analyze(
        rx,
        contacts,
        observations,
        selected,
        period_from,
        period_to,
        receiver_id,
        receiver_name,
    )

    filename = (
        f"{safe_filename(selected.adv_name or selected.public_key[:8])}_"
        f"{date_from}_{date_to}.html"
    )

    report_html = rr.render_html(
        metrics,
        neighbors,
        neighbors_gt3,
        ranking,
        contacts,
    )

    return report_html, filename, selected


def generate_mesh_report(
    config: dict[str, Any],
    date_from: str,
    date_to: str,
) -> tuple[str, str]:
    """Build a mesh report preview without permanently saving it."""
    period_from = normalize_date(date_from, end=False)
    period_to = normalize_date(date_to, end=True)

    db = rr.QuestDB(
        config["questdb_host"],
        config["questdb_port"],
    )

    receiver_id = config.get("receiver_id") or None
    receiver_name = config.get("receiver_name") or None

    rows = mr.load_mesh_rx(
        db,
        period_from,
        period_to,
        receiver_id,
        receiver_name,
    )

    contacts = rr.load_contacts(db)
    resolver = rr.ContactResolver(contacts)

    observer_name, observer_id = mr.determine_observer(
        rows,
        receiver_id,
        receiver_name,
    )
    load, hour_values = mr.analyze_load(
        rows,
        period_from,
        period_to,
    )
    routing = mr.analyze_routing(rows)
    repeaters = mr.analyze_repeater_activity(
        rows,
        resolver,
    )

    geo_repeaters = mr.load_geo_repeaters(db)
    extent, observed_geo = mr.analyze_extent(
        repeaters,
        geo_repeaters,
    )

    (
        far_packets,
        max_pos,
        far_repeaters,
        pos_counts,
    ) = mr.analyze_unscoped_far(
        rows,
        resolver,
    )

    direct_neighbors = mr.analyze_direct_neighbors(
        rows,
        resolver,
    )

    filename = f"mesh_{date_from}_{date_to}.html"

    report_html = mr.render_html(
        observer_name,
        observer_id,
        period_from,
        period_to,
        load,
        hour_values,
        routing,
        repeaters,
        far_packets,
        max_pos,
        far_repeaters,
        pos_counts,
        direct_neighbors,
        extent,
        observed_geo,
    )

    return report_html, filename


def default_report_dates() -> tuple[str, str]:
    """Return a seven-day inclusive default range ending today."""
    today = date.today()
    start = today - timedelta(days=6)
    return start.isoformat(), today.isoformat()


def mesh_overview_dates() -> tuple[str, str]:
    """Return a 28-day inclusive range ending today for the Mesh page map."""
    today = date.today()
    start = today - timedelta(days=27)
    return start.isoformat(), today.isoformat()


def build_mesh_overview(
    config: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Build the 28-day interactive mesh map shown directly on /mesh."""
    date_from, date_to = mesh_overview_dates()
    period_from = normalize_date(date_from, end=False)
    period_to = normalize_date(date_to, end=True)

    db = rr.QuestDB(
        config["questdb_host"],
        config["questdb_port"],
    )

    receiver_id = config.get("receiver_id") or None
    receiver_name = config.get("receiver_name") or None

    rows = mr.load_mesh_rx(
        db,
        period_from,
        period_to,
        receiver_id,
        receiver_name,
    )

    contacts = rr.load_contacts(db)
    resolver = rr.ContactResolver(contacts)

    observer_name, observer_id = mr.determine_observer(
        rows,
        receiver_id,
        receiver_name,
    )

    repeaters = mr.analyze_repeater_activity(
        rows,
        resolver,
    )
    geo_repeaters = mr.load_geo_repeaters(db)
    extent, observed_geo = mr.analyze_extent(
        repeaters,
        geo_repeaters,
    )

    map_html = mr.render_mesh_map(
        observed_geo,
        observer_id,
        extent,
    )

    summary = {
        "repeaters": len(repeaters),
        "geo_repeaters": len(observed_geo),
        "date_from": date_from,
        "date_to": date_to,
    }

    return map_html, summary


def _preview_token(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise RuntimeError("Ungültige Report-Vorschau.")
    return value


def preview_paths(token: str) -> tuple[Path, Path]:
    token = _preview_token(token)
    return (
        PREVIEW_DIR / f"{token}.html",
        PREVIEW_DIR / f"{token}.json",
    )


def create_preview(
    report_html: str,
    filename: str,
    report_type: str,
    title: str,
) -> str:
    PREVIEW_DIR.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    html_path, meta_path = preview_paths(token)

    html_path.write_text(report_html, encoding="utf-8")
    meta_path.write_text(
        json.dumps(
            {
                "filename": filename,
                "report_type": report_type,
                "title": title,
                "created": time.time(),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return token


def load_preview(token: str) -> tuple[Path, dict[str, Any]]:
    html_path, meta_path = preview_paths(token)
    if not html_path.is_file() or not meta_path.is_file():
        raise RuntimeError("Die Report-Vorschau ist nicht mehr verfügbar.")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if not isinstance(meta, dict):
        raise RuntimeError("Ungültige Vorschau-Metadaten.")
    return html_path, meta


def unique_destination(directory: Path, filename: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    original = Path(filename)
    stem = original.stem
    suffix = original.suffix

    candidate = directory / original.name
    counter = 2
    while candidate.exists():
        candidate = directory / f"{stem}-{counter}{suffix}"
        counter += 1
    return candidate


def save_preview_html(
    config: dict[str, Any],
    token: str,
) -> Path:
    html_path, meta = load_preview(token)
    filename = str(meta.get("filename") or f"report-{token}.html")
    destination = unique_destination(output_dir(config), filename)
    shutil.copyfile(html_path, destination)
    return destination


def find_pdf_browser() -> Path | None:
    candidates: list[Path] = []

    for executable in ("msedge", "chrome", "chromium"):
        found = shutil.which(executable)
        if found:
            candidates.append(Path(found))

    if sys.platform.startswith("win"):
        env_candidates = [
            Path(os.environ.get("PROGRAMFILES(X86)", "")) /
            "Microsoft/Edge/Application/msedge.exe",
            Path(os.environ.get("PROGRAMFILES", "")) /
            "Microsoft/Edge/Application/msedge.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) /
            "Microsoft/Edge/Application/msedge.exe",
            Path(os.environ.get("PROGRAMFILES", "")) /
            "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "")) /
            "Google/Chrome/Application/chrome.exe",
        ]
        candidates.extend(env_candidates)

    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    return None


def save_preview_pdf(
    config: dict[str, Any],
    token: str,
) -> Path:
    _, meta = load_preview(token)
    source_name = str(meta.get("filename") or f"report-{token}.html")
    pdf_name = str(Path(source_name).with_suffix(".pdf"))
    destination = unique_destination(output_dir(config), pdf_name)

    browser = find_pdf_browser()
    if browser is None:
        raise RuntimeError(
            "Für PDF wurde weder Microsoft Edge noch Google Chrome gefunden."
        )

    port = int(config.get("web_port", 8080))
    preview_url = (
        f"http://127.0.0.1:{port}/preview-files/{urllib.parse.quote(token)}.html"
    )

    command = [
        str(browser),
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=5000",
        f"--print-to-pdf={destination}",
        preview_url,
    ]

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=45,
    )

    if result.returncode != 0 or not destination.is_file():
        detail = (result.stdout or "").strip()
        raise RuntimeError(
            "PDF-Erzeugung fehlgeschlagen."
            + (f" Browser-Ausgabe: {detail}" if detail else "")
        )

    return destination


def cleanup_previews(max_age_hours: int = 24) -> None:
    PREVIEW_DIR.mkdir(parents=True, exist_ok=True)
    cutoff = time.time() - max_age_hours * 3600

    for path in PREVIEW_DIR.iterdir():
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            pass


def preview_page(
    token: str,
    message: str = "",
    error: bool = False,
) -> bytes:
    _, meta = load_preview(token)
    title = str(meta.get("title") or "Report-Vorschau")
    filename = str(meta.get("filename") or "report.html")

    message_html = ""
    if message:
        cls = "error" if error else "ok"
        message_html = f'<div class="message {cls}">{esc(message)}</div>'

    preview_url = f"/preview-files/{urllib.parse.quote(token)}.html"

    body = f"""
<div class="preview-shell">
  <div class="preview-toolbar">
    <div>
      <h2>{esc(title)}</h2>
      <div class="help">
        Vorschau · noch nicht dauerhaft gespeichert · {esc(filename)}
      </div>
    </div>
    <div class="preview-actions">
      <form method="post" action="/save-preview">
        <input type="hidden" name="token" value="{esc(token)}">
        <button type="submit" name="format" value="pdf">
          PDF speichern
        </button>
      </form>
    </div>
  </div>
  {message_html}
  <iframe
    class="report-preview-frame"
    src="{esc(preview_url)}"
    title="{esc(title)}"
  ></iframe>
</div>
"""
    return page(title, body)


def fmt_int(value: int | None) -> str:
    if value is None:
        return "–"
    return f"{value:,}".replace(",", ".")


def config_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = BASE_DIR / path
    return path.resolve()


def lock_is_held(lock_path: Path) -> tuple[bool, str]:
    """Probe the same OS file lock used by receiver/importer."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+", encoding="utf-8")

    try:
        if sys.platform.startswith("win"):
            import msvcrt
            handle.seek(0, 2)
            if handle.tell() == 0:
                handle.write(" ")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                held = True
            else:
                held = False
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        else:
            import fcntl
            try:
                fcntl.flock(
                    handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except OSError:
                held = True
            else:
                held = False
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

        detail = ""
        try:
            handle.seek(0)
            raw = handle.read().strip()
            if raw:
                data = json.loads(raw)
                pid = data.get("pid")
                started = data.get("started")
                parts = []
                if pid:
                    parts.append(f"PID {pid}")
                if started:
                    parts.append(f"Start {started}")
                detail = " · ".join(parts)
        except Exception:
            pass

        return held, detail
    finally:
        handle.close()


def service_status(lock_name: str) -> tuple[bool, str]:
    lock_path = config_path(lock_name)
    held, detail = lock_is_held(lock_path)
    if held:
        return True, detail or "OS-Lock aktiv"
    return False, "OS-Lock frei"


def request_stop(stop_name: str) -> Path:
    stop_path = config_path(stop_name)
    stop_path.parent.mkdir(parents=True, exist_ok=True)
    stop_path.touch(exist_ok=True)
    return stop_path


def wait_for_stop(
    lock_name: str,
    timeout_seconds: float = 15.0,
) -> bool:
    import time
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        held, _ = lock_is_held(config_path(lock_name))
        if not held:
            return True
        time.sleep(0.25)
    return False


def find_process_pids(script_name: str) -> list[int]:
    """Find only real Python processes running the configured script."""
    target_name = Path(script_name).name.lower()
    target_path = str(resolve_script(script_name)).lower() if (
        (Path(script_name).is_absolute() and Path(script_name).is_file())
        or (BASE_DIR / script_name).is_file()
    ) else ""

    pids: list[int] = []

    try:
        if sys.platform.startswith("win"):
            # Important: filter to python/pythonw processes first. Otherwise the
            # PowerShell process executing this very query also contains the
            # searched script name in its own command line and becomes a false hit.
            ps = r"""
$items = Get-CimInstance Win32_Process |
  Where-Object {
    $_.CommandLine -and
    ($_.Name -ieq 'python.exe' -or $_.Name -ieq 'pythonw.exe')
  } |
  Select-Object ProcessId,Name,CommandLine
$items | ConvertTo-Json -Compress
"""
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=5,
            )

            raw = result.stdout.strip()
            if not raw:
                return []

            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]

            for item in data:
                command_line = str(item.get("CommandLine") or "").lower()
                pid = item.get("ProcessId")

                if not isinstance(pid, int):
                    continue

                # Match either the configured absolute path or the script name
                # as a command-line token. This avoids unrelated text matches.
                matched = False
                if target_path and target_path in command_line:
                    matched = True
                else:
                    tokens = re.findall(
                        r'"[^"]+"|\S+',
                        command_line,
                    )
                    cleaned = [
                        token.strip('"').replace("\\", "/").lower()
                        for token in tokens
                    ]
                    matched = any(
                        Path(token).name.lower() == target_name
                        for token in cleaned
                    )

                if matched:
                    pids.append(pid)

        else:
            result = subprocess.run(
                ["ps", "-eo", "pid=,comm=,args="],
                capture_output=True,
                text=True,
                timeout=5,
            )

            for line in result.stdout.splitlines():
                m = re.match(r"\s*(\d+)\s+(\S+)\s+(.*)", line)
                if not m:
                    continue

                pid = int(m.group(1))
                command = m.group(2).lower()
                args = m.group(3).lower()

                # Restrict to Python interpreters on Linux as well.
                if "python" not in command:
                    continue

                tokens = re.findall(r'"[^"]+"|\S+', args)
                cleaned = [
                    token.strip('"').replace("\\", "/").lower()
                    for token in tokens
                ]

                if (
                    (target_path and target_path.replace("\\", "/") in args.replace("\\", "/"))
                    or any(Path(token).name.lower() == target_name for token in cleaned)
                ):
                    pids.append(pid)

    except Exception:
        return []

    current_pid = __import__("os").getpid()
    return sorted(set(pid for pid in pids if pid != current_pid))


def process_status(script_name: str) -> tuple[bool, str]:
    pids = find_process_pids(script_name)
    return (True, "PID " + ", ".join(map(str, pids))) if pids else (False, "nicht gefunden")


def resolve_script(script_name: str) -> Path:
    path = Path(script_name)
    if not path.is_absolute():
        path = BASE_DIR / path
    path = path.resolve()
    if not path.is_file():
        raise RuntimeError(f"Script nicht gefunden: {path}")
    return path


def log_dir(config: dict[str, Any]) -> Path:
    path = Path(config.get("log_dir", "logs"))
    if not path.is_absolute():
        path = BASE_DIR / path
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def script_log_path(config: dict[str, Any], script_name: str) -> Path:
    return log_dir(config) / f"{Path(script_name).stem}.log"


def tail_log(config: dict[str, Any], script_name: str, max_lines: int = 8) -> str:
    path = script_log_path(config, script_name)
    if not path.is_file():
        return "Noch keine Logdatei vorhanden."
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-max_lines:]) if lines else "Logdatei ist leer."
    except Exception as exc:
        return f"Log konnte nicht gelesen werden: {exc}"


def start_script(
    script_name: str,
    script_args: list[str],
    lock_name: str,
    stop_name: str,
    config: dict[str, Any],
) -> str:
    running, detail = service_status(lock_name)
    if running:
        return (
            f"{Path(script_name).name} läuft bereits"
            + (f" ({detail})." if detail else ".")
        )

    # A stale stop request must never immediately stop a new process.
    try:
        config_path(stop_name).unlink()
    except FileNotFoundError:
        pass

    script = resolve_script(script_name)
    logfile = script_log_path(config, script_name)

    log_handle = logfile.open("a", encoding="utf-8")
    command = [sys.executable, "-u", str(script), *script_args]
    log_handle.write(
        f"\n--- Start durch PacketTap Web UI v{APP_VERSION} ---\n"
        f"Kommando: {' '.join(command)}\n"
        "Python I/O: UTF-8\n"
        f"Detached: {'ja' if sys.platform.startswith('win') else 'session'}\n"
    )
    log_handle.flush()

    child_env = os.environ.copy()
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"

    kwargs: dict[str, Any] = {
        "cwd": str(BASE_DIR),
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
        "env": child_env,
    }

    if sys.platform.startswith("win"):
        kwargs["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.DETACHED_PROCESS
        )
    else:
        kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(command, **kwargs)
    finally:
        log_handle.close()

    import time
    deadline = time.time() + 3.0
    while time.time() < deadline:
        running, detail = service_status(lock_name)
        if running:
            return (
                f"{script.name} gestartet"
                + (f" ({detail})." if detail else ".")
            )
        if proc.poll() is not None:
            break
        time.sleep(0.15)

    exit_code = proc.poll()
    suffix = (
        f" Exit-Code {exit_code}."
        if exit_code is not None
        else ""
    )
    return (
        f"{script.name} wurde gestartet, aber kein aktiver "
        f"Instanz-Lock erkannt.{suffix} Siehe Log."
    )


def stop_script(
    script_name: str,
    lock_name: str,
    stop_name: str,
    timeout_seconds: float = 15.0,
) -> str:
    """Request the script's tested stop-file shutdown path."""
    running, detail = service_status(lock_name)
    if not running:
        # Remove a stale command file when no instance is active.
        try:
            config_path(stop_name).unlink()
        except FileNotFoundError:
            pass
        return f"{Path(script_name).name} läuft nicht."

    stop_path = request_stop(stop_name)

    if wait_for_stop(lock_name, timeout_seconds):
        return (
            f"{Path(script_name).name} geordnet beendet "
            f"(Stop-Datei {stop_path.name})."
        )

    return (
        f"{Path(script_name).name} läuft nach {timeout_seconds:.0f} Sekunden "
        "noch. Es wurde bewusst KEIN harter Prozessabbruch ausgeführt."
    )


def checkpoint_status(config: dict[str, Any]) -> tuple[str, str]:
    """Return a conservative status for the importer's persistent state file."""
    raw = Path(config.get("importer_state", "state/importer.state"))
    path = raw if raw.is_absolute() else (BASE_DIR / raw)
    path = path.resolve()

    if not path.is_file():
        return "Nicht gefunden", str(path)

    try:
        import datetime
        stat = path.stat()
        changed = datetime.datetime.fromtimestamp(stat.st_mtime).astimezone()
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if len(content) > 180:
            content = content[:177] + "…"
        detail = (
            f"geändert {changed.strftime('%Y-%m-%d %H:%M:%S %Z')}"
            f" · {stat.st_size} Byte"
        )
        if content:
            detail += f" · Inhalt: {content}"
        return "Vorhanden", detail
    except Exception as exc:
        return "Fehler", f"{path}: {exc}"


def format_local_datetime(value: str) -> tuple[str, float | None]:
    """Format an ISO-8601 timestamp in the host's local timezone."""
    import datetime

    raw = str(value).strip()
    if not raw:
        return "–", None

    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        local = dt.astimezone()
        age_seconds = max(
            0.0,
            (datetime.datetime.now().astimezone() - local).total_seconds(),
        )
        return local.strftime("%d.%m.%Y · %H:%M:%S"), age_seconds
    except Exception:
        return str(value), None


def format_age(age_seconds: float | None) -> str:
    if age_seconds is None:
        return ""

    seconds = int(max(0, age_seconds))
    if seconds < 5:
        return "gerade eben"
    if seconds < 60:
        return f"vor {seconds} s"

    minutes = seconds // 60
    if minutes < 60:
        return f"vor {minutes} min"

    hours = minutes // 60
    if hours < 24:
        return f"vor {hours} h"

    days = hours // 24
    return f"vor {days} d"


def latest_packet_status(config: dict[str, Any]) -> tuple[str, str, float | None]:
    query = urllib.parse.quote("select max(ts) latest_ts from mc_rx")
    url = f"http://{config['questdb_host']}:{config['questdb_port']}/exec?query={query}"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
        dataset = data.get("dataset") or []
        if dataset and dataset[0] and dataset[0][0]:
            formatted, age = format_local_datetime(str(dataset[0][0]))
            return formatted, format_age(age), age
        return "keine Paketdaten", "", None
    except Exception as exc:
        return f"nicht ermittelbar: {exc}", "", None


def log_activity(
    config: dict[str, Any],
    script_name: str,
    label: str,
) -> tuple[str, str, float | None]:
    """Return latest visible sequence number and log-file activity age."""
    path = script_log_path(config, script_name)

    if not path.is_file():
        return f"{label}: –", "Noch keine Logdatei", None

    try:
        import datetime

        stat = path.stat()
        changed = datetime.datetime.fromtimestamp(stat.st_mtime).astimezone()
        age_seconds = max(
            0.0,
            (datetime.datetime.now().astimezone() - changed).total_seconds(),
        )

        with path.open("rb") as handle:
            size = handle.seek(0, 2)
            handle.seek(max(0, size - 32768))
            tail = handle.read().decode("utf-8", errors="replace")

        numbers = re.findall(r"(?m)^\[(\d+)\]\s", tail)
        sequence = numbers[-1] if numbers else None

        main = f"{label} #{sequence}" if sequence else f"{label}: –"
        detail = (
            f"{changed.strftime('%d.%m.%Y · %H:%M:%S')}"
            f" · {format_age(age_seconds)}"
        )
        return main, detail, age_seconds

    except Exception as exc:
        return f"{label}: –", f"nicht ermittelbar: {exc}", None


def pipeline_state(
    db_ok: bool,
    receiver_ok: bool,
    importer_ok: bool,
    packet_age: float | None,
    receiver_age: float | None,
    importer_age: float | None,
) -> tuple[bool, str, str]:
    if not db_ok:
        return False, "Störung", "QuestDB ist nicht erreichbar."
    if not receiver_ok:
        return False, "Störung", "Receiver ist nicht aktiv."
    if not importer_ok:
        return False, "Störung", "Importer ist nicht aktiv."

    ages = [
        age
        for age in (packet_age, receiver_age, importer_age)
        if age is not None
    ]
    if ages and max(ages) <= 60:
        return True, "Aktuell", "Receiver, Importer und Datenbank sind aktiv."

    if packet_age is not None and packet_age > 300:
        return False, "Keine aktuelle Aktivität", "Seit mehr als 5 Minuten kein neues Paket in QuestDB."

    return True, "Aktiv", "Dienste laufen; aktuell ist nur geringe oder keine Paketaktivität sichtbar."


def questdb_status(config: dict[str, Any]) -> tuple[bool, str]:
    url = f"http://{config['questdb_host']}:{config['questdb_port']}/exec?query=select%201"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            if 200 <= response.status < 300:
                return True, "Verbindung erfolgreich"
            return False, f"HTTP {response.status}"
    except Exception as exc:
        return False, str(exc)


def dashboard_page(
    config: dict[str, Any],
    message: str = "",
    error: bool = False,
) -> bytes:
    db_ok, db_detail = questdb_status(config)
    packet_time, packet_age_text, packet_age = (
        latest_packet_status(config)
        if db_ok
        else ("–", "", None)
    )

    receiver_script = config["receiver_script"]
    importer_script = config["importer_script"]

    receiver_ok, receiver_detail = service_status(config["receiver_lock"])
    importer_ok, importer_detail = service_status(config["importer_lock"])

    receiver_activity, receiver_activity_detail, receiver_age = log_activity(
        config,
        receiver_script,
        "Frame",
    )
    importer_activity, importer_activity_detail, importer_age = log_activity(
        config,
        importer_script,
        "Import",
    )

    pipeline_ok, pipeline_label, pipeline_detail = pipeline_state(
        db_ok,
        receiver_ok,
        importer_ok,
        packet_age,
        receiver_age,
        importer_age,
    )

    def status_card(
        title: str,
        ok: bool,
        state: str,
        main: str,
        detail: str,
        service: str | None = None,
    ) -> str:
        cls = "ok" if ok else "error"
        controls = ""

        if service:
            controls = f"""
            <form class="controls" method="post" action="/service">
              <input type="hidden" name="service" value="{esc(service)}">
              <button name="action" value="start" type="submit">Starten</button>
              <button name="action" value="stop" type="submit">Geordnet stoppen</button>
              <button name="action" value="restart" type="submit">Neustarten</button>
            </form>"""

        return f"""
        <div class="status-card">
          <div class="status-title">{esc(title)}</div>
          <div class="status-value {cls}">{esc(state)}</div>
          <div class="activity-main">{esc(main)}</div>
          <div class="help">{esc(detail)}</div>
          {controls}
        </div>"""

    msg_html = ""
    if message:
        cls = "error" if error else "ok"
        msg_html = f'<div class="message {cls}">{esc(message)}</div>'

    refresh_seconds = int(config.get("dashboard_refresh_seconds", 15))
    refresh_text = (
        f"Automatische Aktualisierung: {refresh_seconds} s"
        if refresh_seconds > 0
        else "Automatische Aktualisierung: aus"
    )

    quest_main = packet_time
    quest_detail = db_detail
    if packet_age_text:
        quest_detail += f" · {packet_age_text}"

    body = f"""
{msg_html}
<div class="card">
  <div class="dashboard-heading">
    <div>
      <h2>PacketTap Übersicht</h2>
      <p class="help">
        Betriebszustand und letzte sichtbare Aktivität der PacketTap-Pipeline.
      </p>
    </div>
    <div class="refresh-note">{esc(refresh_text)}</div>
  </div>

  <div class="pipeline-banner {'ok' if pipeline_ok else 'error'}">
    <strong>Pipeline: {esc(pipeline_label)}</strong>
    <span>{esc(pipeline_detail)}</span>
  </div>

  <div class="status-grid">
    {status_card(
        "QuestDB",
        db_ok,
        "OK" if db_ok else "Nicht erreichbar",
        quest_main,
        quest_detail,
    )}
    {status_card(
        Path(receiver_script).name,
        receiver_ok,
        "Läuft" if receiver_ok else "Gestoppt",
        receiver_activity,
        receiver_activity_detail + (
            f" · {receiver_detail}" if receiver_detail else ""
        ),
        "receiver",
    )}
    {status_card(
        Path(importer_script).name,
        importer_ok,
        "Läuft" if importer_ok else "Gestoppt",
        importer_activity,
        importer_activity_detail + (
            f" · {importer_detail}" if importer_detail else ""
        ),
        "importer",
    )}
  </div>

  <div class="dashboard-actions">
    <a class="button" href="/">Jetzt aktualisieren</a>
    <a class="button secondary" href="/settings">Refresh einstellen</a>
  </div>
</div>
"""
    return page(
        "PacketTap Übersicht",
        body,
        refresh_seconds=refresh_seconds,
    )




def page(title: str, body: str, refresh_seconds: int = 0) -> bytes:
    doc = f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{f'<meta http-equiv="refresh" content="{refresh_seconds}">' if refresh_seconds > 0 else ''}
<link rel="stylesheet" href="/map/leaflet/leaflet.css">
<script src="/map/leaflet/leaflet.js"></script>
<title>{esc(title)}</title>
<style>
:root {{
  --fg:#171717;
  --muted:#666;
  --line:#d8d8d8;
  --soft:#f6f6f6;
  --ok:#246b3c;
  --err:#9a3300;
}}
* {{ box-sizing:border-box; }}
body {{
  font-family:Arial,Helvetica,sans-serif;
  color:var(--fg);
  max-width:900px;
  margin:36px auto;
  padding:0 22px 50px;
  line-height:1.45;
}}
header {{
  display:flex;
  justify-content:space-between;
  gap:20px;
  align-items:flex-end;
  border-bottom:2px solid var(--fg);
  padding-bottom:14px;
  margin-bottom:28px;
}}
h1 {{ margin:0; font-size:1.75rem; }}
nav a {{
  color:var(--fg);
  text-decoration:none;
  margin-left:18px;
}}
nav a:hover {{ text-decoration:underline; }}
.card {{
  border:1px solid var(--line);
  border-radius:10px;
  padding:20px;
  background:#fff;
  margin-bottom:20px;
}}
.grid {{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:16px;
}}
.field {{ margin-bottom:16px; }}
label {{
  display:block;
  font-size:.88rem;
  font-weight:700;
  margin-bottom:5px;
}}
input, select {{
  width:100%;
  border:1px solid #aaa;
  border-radius:6px;
  padding:12px 13px;
  font:inherit;
  background:white;
}}
button, .button {{
  display:inline-block;
  border:0;
  border-radius:6px;
  padding:10px 16px;
  background:#1f1f1f;
  color:white;
  font:inherit;
  font-weight:700;
  cursor:pointer;
  text-decoration:none;
}}
button:hover, .button:hover {{ opacity:.88; }}
.help {{
  color:var(--muted);
  font-size:.86rem;
  margin-top:5px;
}}
.message {{
  border:1px solid var(--line);
  border-radius:7px;
  padding:12px 14px;
  margin-bottom:18px;
}}
.message.ok {{ color:var(--ok); }}
.message.error {{ color:var(--err); }}
.status-grid {{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:14px;
  margin-top:18px;
}}
.status-card {{
  border:1px solid var(--line);
  border-radius:8px;
  padding:16px;
  background:var(--soft);
}}
.status-title {{ font-weight:700; margin-bottom:10px; }}
.status-value {{ font-size:1.15rem; font-weight:700; margin-bottom:5px; }}
.status-value.ok {{ color:var(--ok); }}
.status-value.error {{ color:var(--err); }}
.activity-main {{
  font-size:1rem;
  font-weight:700;
  margin:8px 0 4px;
}}
.dashboard-heading {{
  display:flex;
  justify-content:space-between;
  gap:20px;
  align-items:flex-start;
}}
.refresh-note {{
  color:var(--muted);
  font-size:.82rem;
  white-space:nowrap;
  margin-top:7px;
}}
.pipeline-banner {{
  display:flex;
  gap:12px;
  align-items:baseline;
  border:1px solid var(--line);
  border-radius:8px;
  padding:11px 13px;
  margin:16px 0;
  background:var(--soft);
}}
.pipeline-banner.ok strong {{ color:var(--ok); }}
.pipeline-banner.error strong {{ color:var(--err); }}
.dashboard-actions {{
  display:flex;
  gap:10px;
  flex-wrap:wrap;
  margin-top:16px;
}}
.button.secondary {{
  background:#666;
}}
.controls {{
  display:flex;
  flex-wrap:wrap;
  gap:6px;
  margin-top:18px;
}}
.controls button {{
  padding:7px 9px;
  font-size:.8rem;
}}
.log-grid {{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:14px;
  margin-top:14px;
}}
.log-card {{
  border:1px solid var(--line);
  border-radius:8px;
  padding:14px;
  min-width:0;
}}
.log-card pre {{
  margin:8px 0 0;
  padding:10px;
  background:var(--soft);
  border-radius:5px;
  overflow:auto;
  max-height:190px;
  font-size:.76rem;
  white-space:pre-wrap;
  word-break:break-word;
}}
.mono {{
  font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
}}
.mesh-overview {{
  margin-top:26px;
}}
.mesh-overview-header {{
  display:flex;
  justify-content:space-between;
  gap:18px;
  align-items:flex-end;
  margin-bottom:10px;
}}
.mesh-overview-header h2 {{
  margin:0;
}}
.mesh-overview-summary {{
  color:var(--muted);
  font-size:.84rem;
  text-align:right;
}}
.mesh-overview-facts {{
  display:grid;
  grid-template-columns:2fr 1fr 1fr;
  gap:10px;
  margin:12px 0 14px;
}}
.mesh-overview-fact {{
  border:1px solid var(--line);
  border-radius:8px;
  background:var(--soft);
  padding:10px 12px;
}}
.fact-label {{
  display:block;
  color:var(--muted);
  font-size:.76rem;
  margin-bottom:3px;
}}
.map-search {{
  margin-bottom:10px;
  position:relative;
}}
.map-search label {{display:block;font-size:.84rem;font-weight:700;margin-bottom:5px}}
.map-search-row {{display:flex;gap:8px;align-items:center}}
.map-search-row input {{flex:1 1 auto;min-width:0}}
.map-search-row button {{white-space:nowrap}}
.map-search-row .map-search-reset {{background:#666}}
.map-search-status {{min-height:1.2em;margin-top:5px;color:var(--muted);font-size:.8rem}}

/* Autocomplete-Ergebnisse dürfen nicht die globale schwarze Button-Optik erben. */
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
.map-search-suggestions.visible {{
  display:block;
}}
.map-search-suggestion {{
  width:100%;
  display:block;
  border:0;
  border-bottom:1px solid #ececec;
  border-radius:0;
  padding:9px 11px;
  background:#fff !important;
  color:var(--fg) !important;
  text-align:left;
  font:inherit;
  font-weight:400;
  cursor:pointer;
  box-shadow:none;
}}
.map-search-suggestion:last-child {{
  border-bottom:0;
}}
.map-search-suggestion:hover,
.map-search-suggestion.active {{
  background:#f6f6f6 !important;
  color:var(--fg) !important;
  opacity:1;
}}
.map-search-suggestion.empty {{
  cursor:default;
  color:var(--muted) !important;
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
.offline-map-shell {{
  border:1px solid var(--line);
  border-radius:10px;
  padding:12px;
  background:#fff;
}}
.leaflet-map {{
  width:100%;
  height:520px;
  border-radius:7px;
  background:#ececec;
}}
.map-note {{
  color:var(--muted);
  font-size:.8rem;
  margin-top:8px;
}}
.map-empty, .map-error {{
  border:1px solid var(--line);
  border-radius:9px;
  padding:16px;
  background:var(--soft);
  color:var(--muted);
  margin-top:14px;
}}
.map-error {{
  display:flex;
  align-items:center;
  justify-content:center;
  min-height:180px;
  text-align:center;
}}

.neighbor-detail {{
  margin-top:26px;
}}
.report-doc-header {{
  padding-bottom:17px;
  border-bottom:2px solid var(--fg);
  margin-bottom:20px;
}}
.report-doc-brand {{
  color:var(--muted);
  font-size:.78rem;
  text-transform:uppercase;
  letter-spacing:.09em;
  font-weight:700;
}}
.report-doc-type {{
  margin:5px 0 3px;
  font-size:1.75rem;
  line-height:1.15;
}}
.report-doc-object {{
  font-size:1.18rem;
  font-weight:700;
  margin-top:7px;
}}
.report-doc-key {{
  color:var(--muted);
  font-size:.8rem;
  margin-top:4px;
}}
.report-doc-context {{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:10px;
  margin-top:14px;
}}
.report-doc-card {{
  border:1px solid var(--line);
  border-radius:8px;
  background:var(--soft);
  padding:10px 12px;
}}
.report-doc-label {{
  color:var(--muted);
  font-size:.76rem;
  margin-bottom:3px;
}}
.report-doc-value {{
  font-weight:700;
}}
.report-doc-sub {{
  color:var(--muted);
  font-size:.76rem;
  margin-top:3px;
}}
.neighbor-heading {{
  display:flex;
  justify-content:space-between;
  gap:20px;
  align-items:flex-end;
  margin-bottom:18px;
}}
.neighbor-heading h2 {{
  margin:0;
}}
.neighbor-save-actions {{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  justify-content:flex-end;
}}
.neighbor-kpis {{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:12px;
  margin-bottom:26px;
}}
.neighbor-kpi {{
  border:1px solid var(--line);
  border-radius:9px;
  background:var(--soft);
  padding:14px;
}}
.neighbor-kpi span {{
  display:block;
  color:var(--muted);
  font-size:.8rem;
  margin-bottom:5px;
}}
.neighbor-kpi strong {{
  display:block;
  font-size:1.25rem;
}}
.neighbor-kpi small {{
  display:block;
  color:var(--muted);
  margin-top:5px;
}}
.neighbor-section {{
  margin-top:28px;
}}
.neighbor-section h2 {{
  border-bottom:1px solid var(--line);
  padding-bottom:7px;
  margin-bottom:8px;
}}
.neighbor-chart {{
  display:block;
  width:100%;
  height:auto;
  border:1px solid var(--line);
  border-radius:9px;
  background:#fff;
}}
.neighbor-chart-grid {{
  stroke:#e5e5e5;
  stroke-width:1;
}}
.neighbor-chart-label {{
  fill:#666;
  font:12px Arial,Helvetica,sans-serif;
}}
.neighbor-signal-block {{
  display:grid;
  gap:14px;
}}
.signal-explanation {{
  margin-top:8px;
}}
.signal-explanation h3 {{
  margin:0 0 4px;
  font-size:1rem;
}}
.signal-explanation p {{
  margin:0;
  color:var(--muted);
  font-size:.86rem;
}}
.neighbor-chart-wrap {{
  border:1px solid var(--line);
  border-radius:9px;
  background:#fff;
  overflow:hidden;
}}
.neighbor-chart-title {{
  display:flex;
  justify-content:space-between;
  gap:16px;
  align-items:center;
  padding:10px 14px 0;
}}
.neighbor-chart-title span {{
  color:var(--muted);
  font-size:.8rem;
}}
.neighbor-chart-wrap .neighbor-chart {{
  border:0;
  border-radius:0;
}}
.neighbor-chart-grid {{
  stroke:#e5e5e5;
  stroke-width:1;
}}
.neighbor-chart-tick {{
  stroke:#999;
  stroke-width:1;
}}
.neighbor-chart-label {{
  fill:#666;
  font:11px Arial,Helvetica,sans-serif;
}}
.neighbor-chart-line {{
  fill:none;
  stroke-width:2.4;
  stroke-linejoin:round;
  stroke-linecap:round;
}}
.neighbor-chart-line.rssi {{
  stroke:#2f6fb0;
}}
.neighbor-chart-line.snr {{
  stroke:#c06a2b;
}}
.neighbor-map {{
  width:100%;
  height:430px;
  border:1px solid var(--line);
  border-radius:9px;
  background:#ececec;
}}
.neighbor-advert-table {{
  width:100%;
  border-collapse:collapse;
  table-layout:fixed;
  margin-top:12px;
  background:#fff;
}}
.neighbor-advert-table thead th {{
  background:var(--soft);
  border-bottom:1px solid var(--line);
  padding:10px 12px;
  font-size:.84rem;
  font-weight:700;
  text-align:left;
}}
.neighbor-advert-table tbody td {{
  border-bottom:1px solid #e7e7e7;
  padding:10px 12px;
  vertical-align:middle;
}}
.neighbor-advert-table tbody tr:last-child td {{
  border-bottom:0;
}}
.neighbor-advert-table .num {{
  text-align:right;
  white-space:nowrap;
  font-variant-numeric:tabular-nums;
}}
.neighbor-advert-type {{
  width:12%;
}}
.neighbor-advert-time {{
  width:34%;
}}
.neighbor-advert-signal {{
  width:15%;
}}
.neighbor-advert-region {{
  width:24%;
}}
.advert-type {{
  display:inline-block;
  min-width:62px;
  padding:4px 8px;
  border-radius:999px;
  font-size:.76rem;
  font-weight:700;
  text-align:center;
  line-height:1.1;
}}
.advert-type.direct {{
  background:#f0f0f0;
  color:#444;
}}
.advert-type.flood {{
  background:#e9eef5;
  color:#2f4f6f;
}}
.flood-advert-row {{
  background:#fafcff;
}}
.flood-advert-row td {{
  font-weight:600;
}}
.neighbor-empty {{
  border:1px solid var(--line);
  border-radius:9px;
  background:var(--soft);
  color:var(--muted);
  padding:16px;
}}

.preview-shell {{
  width:100%;
  max-width:100%;
  margin:0;
}}
.preview-toolbar {{
  display:flex;
  justify-content:space-between;
  align-items:flex-end;
  gap:18px;
  margin-bottom:14px;
}}
.preview-toolbar h2 {{
  margin:0;
}}
.preview-actions form {{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
}}
.report-preview-frame {{
  display:block;
  width:100%;
  height:calc(100vh - 220px);
  min-height:680px;
  border:1px solid var(--line);
  border-radius:10px;
  background:white;
}}
footer {{
  margin-top:32px;
  border-top:1px solid var(--line);
  padding-top:12px;
  color:var(--muted);
  font-size:.8rem;
}}
@media(max-width:650px) {{
  header {{ display:block; }}
  nav {{ margin-top:12px; }}
  nav a {{ margin-left:0; margin-right:16px; }}
  .grid, .status-grid, .log-grid {{ grid-template-columns:1fr; }}
  .dashboard-heading {{ display:block; }}
  .refresh-note {{ margin-top:12px; white-space:normal; }}
  .pipeline-banner {{ display:block; }}
  .pipeline-banner span {{ display:block; margin-top:4px; }}
  .preview-toolbar {{ display:block; }}
  .preview-actions {{ margin-top:12px; }}
  .report-preview-frame {{ min-height:560px; height:70vh; }}
  .mesh-overview-header {{ display:block; }}
  .mesh-overview-summary {{ text-align:left; margin-top:6px; }}
  .mesh-overview-facts {{ grid-template-columns:1fr; }}
  .neighbor-kpis {{ grid-template-columns:1fr; }}
  .report-doc-context {{ grid-template-columns:1fr; }}
  .neighbor-map {{ height:350px; }}
  .neighbor-advert-table {{
    table-layout:auto;
    font-size:.9rem;
  }}
  .neighbor-advert-table thead th,
  .neighbor-advert-table tbody td {{
    padding:8px 7px;
  }}
  .map-search-row {{ flex-wrap:wrap; }}
  .map-search-row input {{ flex-basis:100%; }}
  .map-search-suggestions {{ right:0; }}
  .leaflet-map {{ height:420px; }}
}}
</style>
</head>
<body>
<header>
  <div>
    <div class="help">MeshCore</div>
    <h1>PacketTap</h1>
  </div>
  <nav>
    <a href="/">Übersicht</a>
    <a href="/mesh">Mesh</a>
    <a href="/report">Repeater</a>
    <a href="/neighbors">Nachbarn</a>
    <a href="/settings">Einstellungen</a>
  </nav>
</header>
{body}
<footer>Report Web UI v{APP_VERSION}</footer>
</body>
</html>"""
    return doc.encode("utf-8")



def _resolve_direct_neighbor(
    resolver: rr.ContactResolver,
    path_id: str,
) -> rr.Contact | None:
    value = rr.norm(path_id)
    if not value or len(value) % 2 != 0:
        return None
    if not all(ch in "0123456789abcdef" for ch in value):
        return None

    matches = resolver.resolve_path_id(
        value,
        len(value) // 2,
    )
    return matches[0] if len(matches) == 1 else None


def direct_neighbor_dataset(
    config: dict[str, Any],
    date_from: str,
    date_to: str,
) -> tuple[
    list[dict[str, Any]],
    list[rr.Contact],
    dict[str, dict[str, Any]],
]:
    period_from = normalize_date(date_from, end=False)
    period_to = normalize_date(date_to, end=True)

    db = rr.QuestDB(
        config["questdb_host"],
        config["questdb_port"],
    )
    contacts = rr.load_contacts(db)
    resolver = rr.ContactResolver(contacts)

    rows = rr.load_rx(
        db,
        period_from,
        period_to,
        config.get("receiver_id") or None,
        config.get("receiver_name") or None,
    )

    by_key: dict[str, dict[str, Any]] = {}

    for row in rows:
        contact = _resolve_direct_neighbor(
            resolver,
            rr.text_value(row.get("repeater")),
        )
        if contact is None:
            continue

        entry = by_key.setdefault(
            contact.public_key,
            {
                "contact": contact,
                "rows": [],
            },
        )
        entry["rows"].append(row)

    direct_contacts = sorted(
        (entry["contact"] for entry in by_key.values()),
        key=lambda c: (
            (c.adv_name or "").lower(),
            c.public_key,
        ),
    )

    return rows, direct_contacts, by_key


def resolve_direct_neighbor_selection(
    direct_contacts: list[rr.Contact],
    query: str,
) -> rr.Contact:
    wanted = rr.norm(query)
    if not wanted:
        raise RuntimeError("Bitte einen direkten Nachbarn auswählen.")

    exact_key = [
        c for c in direct_contacts
        if c.public_key == wanted
    ]
    if len(exact_key) == 1:
        return exact_key[0]

    exact_name = [
        c for c in direct_contacts
        if rr.norm(c.adv_name) == wanted
    ]
    if len(exact_name) == 1:
        return exact_name[0]

    prefix = [
        c for c in direct_contacts
        if c.public_key.startswith(wanted)
    ]
    if len(prefix) == 1:
        return prefix[0]

    if len(exact_name) > 1 or len(prefix) > 1:
        raise RuntimeError(
            "Die Nachbar-Auswahl ist nicht eindeutig."
        )

    raise RuntimeError(
        "Dieser Repeater wurde im gewählten Zeitraum nicht als "
        "direkter Nachbar des Receivers erkannt."
    )


def neighbor_hourly_signal(
    rows: list[dict[str, Any]],
) -> list[tuple[Any, float | None, float | None]]:
    buckets: dict[Any, dict[str, list[float]]] = defaultdict(
        lambda: {"rssi": [], "snr": []}
    )

    for row in rows:
        dt = mr.parse_ts(row.get("ts"))
        if dt is None:
            continue

        hour = dt.replace(minute=0, second=0, microsecond=0)

        try:
            buckets[hour]["rssi"].append(float(row.get("rssi_dbm")))
        except (TypeError, ValueError):
            pass

        try:
            buckets[hour]["snr"].append(float(row.get("snr_db")))
        except (TypeError, ValueError):
            pass

    return [
        (
            hour,
            float(median(values["rssi"])) if values["rssi"] else None,
            float(median(values["snr"])) if values["snr"] else None,
        )
        for hour, values in sorted(buckets.items())
        if values["rssi"] or values["snr"]
    ]


def _neighbor_time_ticks(
    values: list[tuple[Any, float | None, float | None]],
    max_ticks: int = 7,
) -> list[int]:
    if not values:
        return []
    if len(values) <= max_ticks:
        return list(range(len(values)))

    last = len(values) - 1
    raw = [
        round(i * last / (max_ticks - 1))
        for i in range(max_ticks)
    ]

    result = []
    for idx in raw:
        if idx not in result:
            result.append(idx)
    return result


def _neighbor_single_signal_svg(
    values: list[tuple[Any, float | None, float | None]],
    metric: str,
) -> str:
    if metric not in {"rssi", "snr"}:
        raise ValueError("Unbekannte Signal-Kennzahl.")

    if metric == "rssi":
        series = [
            (dt, rssi)
            for dt, rssi, _ in values
            if rssi is not None
        ]
        unit = "dBm"
        title = "RSSI"
        css_class = "rssi"
        step = 10.0
        min_span = 20.0
    else:
        series = [
            (dt, snr)
            for dt, _, snr in values
            if snr is not None
        ]
        unit = "dB"
        title = "SNR"
        css_class = "snr"
        step = 5.0
        min_span = 10.0

    if not series:
        return (
            "<div class='neighbor-empty'>"
            f"Keine {esc(title)}-Werte für diesen Zeitraum verfügbar."
            "</div>"
        )

    width = 820
    height = 270
    pad_left = 58
    pad_right = 20
    pad_top = 26
    pad_bottom = 54

    numeric = [value for _, value in series]

    low = math.floor(min(numeric) / step) * step
    high = math.ceil(max(numeric) / step) * step
    if high - low < min_span:
        middle = (low + high) / 2
        low = middle - min_span / 2
        high = middle + min_span / 2

    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    def px(index: int) -> float:
        if len(series) <= 1:
            return pad_left + plot_w / 2
        return pad_left + index / (len(series) - 1) * plot_w

    def py(value: float) -> float:
        ratio = (high - value) / (high - low)
        return pad_top + ratio * plot_h

    points = " ".join(
        f"{px(i):.1f},{py(value):.1f}"
        for i, (_, value) in enumerate(series)
    )

    grid_lines = []
    y_labels = []
    for i in range(6):
        y = pad_top + (i / 5) * plot_h
        level = high - (i / 5) * (high - low)

        grid_lines.append(
            f"<line x1='{pad_left}' y1='{y:.1f}' "
            f"x2='{width-pad_right}' y2='{y:.1f}' "
            "class='neighbor-chart-grid'/>"
        )

        label = (
            f"{level:.0f}"
            if metric == "rssi"
            else f"{level:.1f}".replace(".", ",")
        )
        y_labels.append(
            f"<text x='{pad_left-9}' y='{y+4:.1f}' "
            "text-anchor='end' class='neighbor-chart-label'>"
            f"{label}</text>"
        )

    tick_indexes = _neighbor_time_ticks(series, 7)
    x_ticks = []

    same_day = (
        series[0][0].date() == series[-1][0].date()
        if len(series) > 1 else True
    )

    for idx in tick_indexes:
        dt = series[idx][0]
        x = px(idx)
        label = (
            dt.strftime("%H:%M")
            if same_day
            else dt.strftime("%d.%m. %H:%M")
        )

        anchor = "middle"
        if idx == 0:
            anchor = "start"
        elif idx == len(series) - 1:
            anchor = "end"

        x_ticks.append(
            f"<line x1='{x:.1f}' y1='{pad_top+plot_h}' "
            f"x2='{x:.1f}' y2='{pad_top+plot_h+5}' "
            "class='neighbor-chart-tick'/>"
            f"<text x='{x:.1f}' y='{height-16}' "
            f"text-anchor='{anchor}' class='neighbor-chart-label'>"
            f"{esc(label)}</text>"
        )

    return f"""
    <div class="neighbor-chart-wrap">
      <div class="neighbor-chart-title">
        <strong>{esc(title)}</strong>
        <span>{esc(unit)}</span>
      </div>
      <svg class="neighbor-chart"
           viewBox="0 0 {width} {height}"
           role="img"
           aria-label="Median {esc(title)} pro Stunde">
        {''.join(grid_lines)}
        {''.join(y_labels)}
        <polyline points="{points}"
                  class="neighbor-chart-line {css_class}"/>
        {''.join(x_ticks)}
      </svg>
    </div>
    """


def neighbor_signal_charts(
    values: list[tuple[Any, float | None, float | None]],
) -> str:
    if not values:
        return (
            "<div class='neighbor-empty'>"
            "Keine RSSI- oder SNR-Werte für diesen Zeitraum verfügbar."
            "</div>"
        )

    return f"""
    <div class="neighbor-signal-block">
      <div class="signal-explanation">
        <h3>SNR – Signalqualität gegenüber Rauschen</h3>
        <p>
          SNR beschreibt, wie weit das empfangene Signal dieses Nachbarn
          gegenüber dem lokalen Rausch- und Störpegel am Beobachtungsstandort
          hervortritt. Höhere Werte bedeuten günstigere Empfangsbedingungen;
          LoRa kann auch Pakete mit negativem SNR noch dekodieren.
        </p>
      </div>
      {_neighbor_single_signal_svg(values, "snr")}

      <div class="signal-explanation">
        <h3>RSSI – empfangene Paketleistung</h3>
        <p>
          RSSI beschreibt die am Receiver gemessene Leistung des empfangenen
          Pakets in dBm. Weniger negative Werte stehen für ein stärker
          empfangenes Signal.
        </p>
      </div>
      {_neighbor_single_signal_svg(values, "rssi")}
    </div>
    """


def _geo_by_key(
    config: dict[str, Any],
) -> dict[str, Any]:
    """
    Load the latest known coordinates for all contacts from mc_contacts.

    Important: unlike mesh_report.load_geo_repeaters(), this intentionally
    does NOT filter node_role == repeater. The PacketTap receiver can also
    have a contact entry with adv_lat/adv_lon and is required for the
    direct-neighbor distance calculation.
    """
    db = rr.QuestDB(
        config["questdb_host"],
        config["questdb_port"],
    )

    available = db.table_columns("mc_contacts")
    required = {"ts", "public_key", "adv_lat", "adv_lon"}
    missing = required - available
    if missing:
        raise RuntimeError(
            "mc_contacts fehlen Spalten: " + ", ".join(sorted(missing))
        )

    rows = db.rows("""
        SELECT
            ts,
            public_key,
            adv_name,
            node_role,
            adv_lat,
            adv_lon
        FROM mc_contacts
        WHERE public_key IS NOT NULL
        ORDER BY ts
    """)

    latest: dict[str, Any] = {}

    for row in rows:
        key = rr.norm(row.get("public_key"))
        if not rr.is_full_public_key(key):
            continue

        try:
            lat = float(row.get("adv_lat"))
            lon = float(row.get("adv_lon"))
        except (TypeError, ValueError):
            continue

        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            continue
        if abs(lat) < 1e-9 and abs(lon) < 1e-9:
            continue

        latest[key] = mr.GeoRepeater(
            public_key=key,
            name=rr.text_value(row.get("adv_name")) or "–",
            lat=lat,
            lon=lon,
        )

    return latest


def distance_and_bearing(
    first: Any,
    second: Any,
) -> tuple[float, float]:
    distance = mr.haversine_km(
        first.lat,
        first.lon,
        second.lat,
        second.lon,
    )

    lat1 = math.radians(first.lat)
    lat2 = math.radians(second.lat)
    dlon = math.radians(second.lon - first.lon)

    x = math.sin(dlon) * math.cos(lat2)
    y = (
        math.cos(lat1) * math.sin(lat2)
        - math.sin(lat1) * math.cos(lat2) * math.cos(dlon)
    )
    bearing = (
        math.degrees(math.atan2(x, y)) + 360.0
    ) % 360.0

    return distance, bearing


def compass_direction(bearing: float) -> str:
    names = [
        "N", "NNO", "NO", "ONO",
        "O", "OSO", "SO", "SSO",
        "S", "SSW", "SW", "WSW",
        "W", "WNW", "NW", "NNW",
    ]
    index = int((bearing + 11.25) // 22.5) % 16
    return names[index]


def neighbor_map_html(
    receiver_geo: Any | None,
    neighbor_geo: Any | None,
    receiver_name: str,
    neighbor_name: str,
) -> str:
    if receiver_geo is None or neighbor_geo is None:
        return (
            "<div class='neighbor-empty'>"
            "Für Receiver und Nachbar sind nicht beide Koordinaten verfügbar."
            "</div>"
        )

    payload = json.dumps(
        {
            "receiver": {
                "name": receiver_name,
                "lat": receiver_geo.lat,
                "lon": receiver_geo.lon,
            },
            "neighbor": {
                "name": neighbor_name,
                "lat": neighbor_geo.lat,
                "lon": neighbor_geo.lon,
            },
        },
        ensure_ascii=False,
    ).replace("</", "<\\/")

    return f"""
    <div id="neighbor-map" class="neighbor-map"></div>
    <script>
    (function() {{
      const data = {payload};
      if (typeof L === "undefined") {{
        document.getElementById("neighbor-map").innerHTML =
          "<div class='map-error'>Leaflet wurde nicht geladen.</div>";
        return;
      }}

      const map = L.map("neighbor-map", {{
        attributionControl: true,
        zoomControl: true,
        fadeAnimation: false,
        zoomAnimation: false
      }});

      L.tileLayer(
        "https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png",
        {{
          maxZoom: 19,
          attribution: "&copy; OpenStreetMap contributors"
        }}
      ).addTo(map);

      const a = [data.receiver.lat, data.receiver.lon];
      const b = [data.neighbor.lat, data.neighbor.lon];

      L.circleMarker(a, {{
        radius: 7,
        weight: 3,
        color: "#111",
        fillColor: "#fff",
        fillOpacity: 1
      }}).addTo(map).bindTooltip(
        "<strong>" + data.receiver.name + "</strong><br>Receiver"
      );

      L.circleMarker(b, {{
        radius: 7,
        weight: 2,
        color: "#555",
        fillColor: "#555",
        fillOpacity: .85
      }}).addTo(map).bindTooltip(
        "<strong>" + data.neighbor.name + "</strong><br>Direkter Nachbar"
      );

      L.polyline([a, b], {{
        weight: 2,
        opacity: .8
      }}).addTo(map);

      map.fitBounds([a, b], {{
        padding: [35, 35],
        maxZoom: 12
      }});
    }})();
    </script>
    """


def neighbor_advert_summary(
    config: dict[str, Any],
    public_key: str,
    date_from: str,
    date_to: str,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """
    Return the last 3 own Direct-Adverts and the last own Flood-Advert.

    Advert ownership is linked via public_key + packet_payload_sha256.
    The route type is taken from mc_rx:
      RT 2 + hop 0 -> Direct-Advert
      RT 0         -> Flood-Advert

    For Flood-Adverts the region is taken from the matching mc_rx packet,
    because Direct-Adverts normally do not carry a routing region.
    """
    db = rr.QuestDB(
        config["questdb_host"],
        config["questdb_port"],
    )

    period_from = normalize_date(date_from, end=False)
    period_to = normalize_date(date_to, end=True)
    receiver_id = config.get("receiver_id") or None
    receiver_name = config.get("receiver_name") or None

    observations = rr.load_contact_observations(
        db,
        period_from,
        period_to,
        receiver_id,
        receiver_name,
    )

    rx = rr.load_rx(
        db,
        period_from,
        period_to,
        receiver_id,
        receiver_name,
    )

    selected_key = rr.norm(public_key)

    obs_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in observations:
        if (
            rr.norm(row.get("public_key")) == selected_key
            and rr.norm(row.get("source_type")) == "advert"
        ):
            payload_hash = rr.norm(row.get("packet_payload_sha256"))
            if payload_hash:
                obs_by_hash[payload_hash].append(row)

    rx_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rx:
        payload_hash = rr.norm(row.get("packet_payload_sha256"))
        if (
            payload_hash in obs_by_hash
            and rr.norm(row.get("payload_type")) == "advert"
        ):
            rx_by_hash[payload_hash].append(row)

    direct_events: list[dict[str, Any]] = []
    flood_events: list[dict[str, Any]] = []

    for payload_hash, packet_rows in rx_by_hash.items():
        matching_obs = obs_by_hash[payload_hash]

        direct_rows = [
            row for row in packet_rows
            if rr.route_type(row) == rr.RT_DIRECT
            and rr.to_int(row.get("hop_count")) == 0
        ]

        flood_rows = [
            row for row in packet_rows
            if rr.route_type(row) == rr.RT_TRANSPORT_FLOOD
        ]

        if direct_rows:
            packet = min(
                direct_rows,
                key=lambda row: rr.text_value(row.get("ts")),
            )
            obs = min(
                matching_obs,
                key=lambda row: abs(
                    (
                        (mr.parse_ts(row.get("ts")) or mr.parse_ts(packet.get("ts")))
                        - (mr.parse_ts(packet.get("ts")) or mr.parse_ts(row.get("ts")))
                    ).total_seconds()
                ),
            )
            direct_events.append(
                {
                    "type": "Direct",
                    "ts": packet.get("ts") or obs.get("ts"),
                    "rssi_dbm": obs.get("rssi_dbm"),
                    "snr_db": obs.get("snr_db"),
                    "region": None,
                    "packet_payload_sha256": payload_hash,
                }
            )

        if flood_rows:
            # One Flood-Advert can be received multiple times over different
            # paths. Count it as one event and use the earliest reception.
            packet = min(
                flood_rows,
                key=lambda row: rr.text_value(row.get("ts")),
            )
            obs = min(
                matching_obs,
                key=lambda row: abs(
                    (
                        (mr.parse_ts(row.get("ts")) or mr.parse_ts(packet.get("ts")))
                        - (mr.parse_ts(packet.get("ts")) or mr.parse_ts(row.get("ts")))
                    ).total_seconds()
                ),
            )

            region = (
                rr.text_value(packet.get("region"))
                or rr.text_value(obs.get("region"))
                or "–"
            )

            flood_events.append(
                {
                    "type": "Flood",
                    "ts": packet.get("ts") or obs.get("ts"),
                    "rssi_dbm": obs.get("rssi_dbm"),
                    "snr_db": obs.get("snr_db"),
                    "region": region,
                    "packet_payload_sha256": payload_hash,
                }
            )

    direct_events.sort(
        key=lambda row: rr.text_value(row.get("ts")),
        reverse=True,
    )
    flood_events.sort(
        key=lambda row: rr.text_value(row.get("ts")),
        reverse=True,
    )

    return direct_events[:3], (flood_events[0] if flood_events else None)



def fmt_rssi(value: Any) -> str:
    try:
        return f"{float(value):.0f} dBm"
    except (TypeError, ValueError):
        return "–"


def fmt_snr(value: Any) -> str:
    try:
        return f"{float(value):+.1f} dB".replace(".", ",")
    except (TypeError, ValueError):
        return "–"

def fmt_neighbor_time(value: Any) -> str:
    dt = mr.parse_ts(value)
    if dt is None:
        return rr.text_value(value) or "–"
    return dt.astimezone().strftime("%d.%m.%Y · %H:%M:%S")


def neighbor_page(
    config: dict[str, Any],
    selected_query: str = "",
    date_from: str | None = None,
    date_to: str | None = None,
    message: str = "",
    error: bool = False,
    export_mode: bool = False,
) -> bytes:
    if not date_from or not date_to:
        default_from, default_to = default_report_dates()
        date_from = date_from or default_from
        date_to = date_to or default_to

    msg_html = ""
    if message:
        cls = "error" if error else "ok"
        msg_html = f'<div class="message {cls}">{esc(message)}</div>'

    try:
        all_rows, direct_contacts, by_key = direct_neighbor_dataset(
            config,
            date_from,
            date_to,
        )
        options = "\n".join(
            f'<option value="{esc(c.adv_name or c.public_key)}">'
            f'{esc(c.public_key[:8])}…'
            "</option>"
            for c in direct_contacts
        )
        neighbor_note = (
            f"{len(direct_contacts)} direkte Nachbarn im gewählten "
            "Zeitraum eindeutig erkannt."
        )
    except Exception as exc:
        direct_contacts = []
        by_key = {}
        all_rows = []
        options = ""
        neighbor_note = f"Nachbarliste konnte nicht geladen werden: {exc}"

    details_html = ""

    if selected_query:
        try:
            selected = resolve_direct_neighbor_selection(
                direct_contacts,
                selected_query,
            )
            selected_rows = by_key[selected.public_key]["rows"]

            # Rank by packet count among direct neighbors.
            ranking = sorted(
                (
                    (
                        key,
                        len(entry["rows"]),
                    )
                    for key, entry in by_key.items()
                ),
                key=lambda item: (
                    -item[1],
                    item[0],
                ),
            )
            rank_by_key = {
                key: idx
                for idx, (key, _) in enumerate(ranking, start=1)
            }

            rssi_values = []
            snr_values = []
            for row in selected_rows:
                try:
                    rssi_values.append(float(row.get("rssi_dbm")))
                except (TypeError, ValueError):
                    pass
                try:
                    snr_values.append(float(row.get("snr_db")))
                except (TypeError, ValueError):
                    pass

            median_rssi = (
                float(median(rssi_values))
                if rssi_values
                else None
            )
            median_snr = (
                float(median(snr_values))
                if snr_values
                else None
            )

            signal_values = neighbor_hourly_signal(selected_rows)
            chart_html = neighbor_signal_charts(signal_values)

            last_ts = max(
                (
                    mr.parse_ts(row.get("ts"))
                    for row in selected_rows
                    if mr.parse_ts(row.get("ts")) is not None
                ),
                default=None,
            )

            geo = _geo_by_key(config)

            # Use the same receiver identity resolution as the Mesh report.
            # If receiver_id is not explicitly configured, determine it from
            # mc_rx. This is how the observation site (e.g. Stutensee - Spoeck)
            # is identified for the Mesh map as well.
            observer_name, observer_id = mr.determine_observer(
                all_rows,
                config.get("receiver_id") or None,
                config.get("receiver_name") or None,
            )

            receiver_geo = geo.get(rr.norm(observer_id))
            neighbor_geo = geo.get(selected.public_key)

            distance_text = "–"
            direction_text = "–"
            if receiver_geo is not None and neighbor_geo is not None:
                distance, bearing = distance_and_bearing(
                    receiver_geo,
                    neighbor_geo,
                )
                distance_text = f"{distance:.1f} km".replace(".", ",")
                direction_text = (
                    f"{bearing:.0f}° · {compass_direction(bearing)}"
                )

            map_html = neighbor_map_html(
                receiver_geo,
                neighbor_geo,
                observer_name or "Receiver",
                selected.adv_name or selected.public_key[:8],
            )

            direct_adverts, flood_advert = neighbor_advert_summary(
                config,
                selected.public_key,
                date_from,
                date_to,
            )

            advert_rows_parts = []

            for row in direct_adverts:
                advert_rows_parts.append(
                    "<tr>"
                    "<td><span class='advert-type direct'>Direct</span></td>"
                    f"<td>{esc(fmt_neighbor_time(row.get('ts')).replace(' · ', ' '))}</td>"
                    f"<td class='num'>{esc(fmt_rssi(row.get('rssi_dbm')))}</td>"
                    f"<td class='num'>{esc(fmt_snr(row.get('snr_db')))}</td>"
                    "<td class='muted'>–</td>"
                    "</tr>"
                )

            if flood_advert is not None:
                advert_rows_parts.append(
                    "<tr class='flood-advert-row'>"
                    "<td><span class='advert-type flood'>Flood</span></td>"
                    f"<td>{esc(fmt_neighbor_time(flood_advert.get('ts')).replace(' · ', ' '))}</td>"
                    f"<td class='num'>{esc(fmt_rssi(flood_advert.get('rssi_dbm')))}</td>"
                    f"<td class='num'>{esc(fmt_snr(flood_advert.get('snr_db')))}</td>"
                    f"<td><strong>{esc(flood_advert.get('region') or '–')}</strong></td>"
                    "</tr>"
                )

            advert_rows = "".join(advert_rows_parts)

            if not advert_rows:
                advert_rows = (
                    "<tr><td colspan='5' class='muted'>"
                    "Keine eigenen Direct- oder Flood-Adverts im Zeitraum erkannt."
                    "</td></tr>"
                )

            details_html = f"""
<section class="neighbor-detail">
  <div class="report-doc-header">
    <div class="report-doc-brand">MESHCORE PACKETTAP</div>
    <h2 class="report-doc-type">Nachbar-Report</h2>
    <div class="report-doc-object">{esc(selected.adv_name or "(ohne Namen)")}</div>
    <div class="report-doc-key mono">Public Key: {esc(selected.public_key)}</div>
    <div class="report-doc-context">
      <div class="report-doc-card">
        <div class="report-doc-label">Beobachtungsstandort</div>
        <div class="report-doc-value">{esc(observer_name)}</div>
        <div class="report-doc-sub mono">
          Public Key: {esc(mr.short_receiver_key(observer_id))}
        </div>
      </div>
      <div class="report-doc-card">
        <div class="report-doc-label">Beobachtungszeitraum</div>
        <div class="report-doc-value">
          {esc(mr.format_period_de(normalize_date(date_from)))} – {esc(mr.format_period_de(normalize_date(date_to, end=True)))}
        </div>
      </div>
    </div>
    {"" if export_mode else f"""
    <form class="neighbor-save-actions" method="post" action="/save-neighbor">
      <input type="hidden" name="neighbor" value="{esc(selected.public_key)}">
      <input type="hidden" name="date_from" value="{esc(date_from)}">
      <input type="hidden" name="date_to" value="{esc(date_to)}">
      <button type="submit" name="format" value="pdf">PDF speichern</button>
    </form>
    """}
  </div>

  <div class="neighbor-kpis">
    <div class="neighbor-kpi">
      <span>Pakete</span>
      <strong>{fmt_int(len(selected_rows))}</strong>
      <small>{esc(date_from)} – {esc(date_to)}</small>
    </div>
    <div class="neighbor-kpi">
      <span>Rang unter direkten Nachbarn</span>
      <strong>#{esc(rank_by_key.get(selected.public_key, "–"))}</strong>
      <small>von {fmt_int(len(ranking))}</small>
    </div>
    <div class="neighbor-kpi">
      <span>Median RSSI</span>
      <strong>{(f"{median_rssi:.1f} dBm".replace(".", ",")) if median_rssi is not None else "–"}</strong>
      <small>alle direkt empfangenen Pakete</small>
    </div>
    <div class="neighbor-kpi">
      <span>Median SNR</span>
      <strong>{(f"{median_snr:.1f} dB".replace(".", ",")) if median_snr is not None else "–"}</strong>
      <small>alle direkt empfangenen Pakete</small>
    </div>
    <div class="neighbor-kpi">
      <span>Entfernung</span>
      <strong>{esc(distance_text)}</strong>
      <small>{esc(direction_text)}</small>
    </div>
    <div class="neighbor-kpi">
      <span>Zuletzt direkt gehört</span>
      <strong>{esc(fmt_neighbor_time(last_ts) if last_ts else "–")}</strong>
      <small>letztes Paket im Zeitraum</small>
    </div>
  </div>

  <div class="neighbor-section neighbor-position-section">
    <h2>Position und Entfernung</h2>
    <p class="help">
      Luftlinie zwischen PacketTap-Receiver und direktem Nachbarn anhand der
      zuletzt bekannten Advert-Koordinaten.
    </p>
    {map_html}
  </div>

  <div class="neighbor-section">
    <h2>Signalstärke im Zeitverlauf</h2>
    <p class="help">
      Für beide Kennzahlen wird der Median pro Stunde aus den unmittelbar
      empfangenen Paketen dieses Nachbarn dargestellt. SNR und RSSI erhalten
      jeweils ein eigenes Diagramm und eine eigene Skala.
    </p>
    {chart_html}
  </div>

  <div class="neighbor-section">
    <h2>Letzte Adverts des Nachbarn</h2>
    <p class="help">
      Angezeigt werden die letzten drei eigenen Direct-Adverts sowie das
      zuletzt erkannte eigene Flood-Advert. Direct-Adverts besitzen
      normalerweise keine Routing-Region; beim Flood-Advert wird die Region
      aus dem zugehörigen RT-0-Paket übernommen.
    </p>
    <table class="neighbor-advert-table">
      <colgroup>
        <col class="neighbor-advert-type">
        <col class="neighbor-advert-time">
        <col class="neighbor-advert-signal">
        <col class="neighbor-advert-signal">
        <col class="neighbor-advert-region">
      </colgroup>
      <thead>
        <tr>
          <th>Typ</th>
          <th>Zeitpunkt</th>
          <th class="num">RSSI</th>
          <th class="num">SNR</th>
          <th>Region</th>
        </tr>
      </thead>
      <tbody>{advert_rows}</tbody>
    </table>
  </div>
</section>
"""
        except Exception as exc:
            msg_html += (
                f'<div class="message error">{esc(exc)}</div>'
            )

    selection_html = ""
    if not export_mode:
        selection_html = f"""
<div class="card">
  <h2>Direkten Nachbarn auswählen</h2>
  <p class="help">
    Es werden nur Repeater angeboten, die im gewählten Zeitraum als letzter
    Repeater unmittelbar vor dem PacketTap-Receiver eindeutig erkannt wurden.
  </p>

  <form method="get" action="/neighbors">
    <div class="field">
      <label for="neighbor">Nachbar</label>
      <input
        id="neighbor"
        name="neighbor"
        list="direct-neighbors"
        value="{esc(selected_query)}"
        required
        placeholder="Name oder Public Key"
        autocomplete="off"
      >
      <datalist id="direct-neighbors">
        {options}
      </datalist>
      <div class="help">{esc(neighbor_note)}</div>
    </div>

    <div class="grid">
      <div class="field">
        <label for="date_from">Von</label>
        <input id="date_from" name="date_from" type="date"
               value="{esc(date_from)}" required>
      </div>
      <div class="field">
        <label for="date_to">Bis</label>
        <input id="date_to" name="date_to" type="date"
               value="{esc(date_to)}" required>
      </div>
    </div>

    <button type="submit">Nachbar anzeigen</button>
  </form>
</div>
"""

    body = f"""
{msg_html}
{selection_html}
{details_html}
"""
    return page("Nachbarn", body)


def neighbor_export_page(
    config: dict[str, Any],
    selected: rr.Contact,
    date_from: str,
    date_to: str,
    details_html: str,
    observer_name: str,
    observer_id: str,
) -> bytes:
    """Render a clean standalone HTML/PDF neighbor report."""
    created = date.today().strftime("%d.%m.%Y")
    title = (
        f"Nachbar-Report – {selected.adv_name or selected.public_key[:8]}"
    )

    # The interactive page detail starts with its own neighbor heading.
    # In the export this information belongs in the dedicated report header.
    export_details = details_html
    start = export_details.find('<div class="report-doc-header">')
    if start >= 0:
        end = export_details.find("</div>\n\n  <div class=\"neighbor-kpis\">", start)
        if end >= 0:
            export_details = (
                export_details[:start]
                + '<div class="neighbor-kpis">'
                + export_details[end + len("</div>\n\n  <div class=\"neighbor-kpis\">"):]
            )

    report_header = f"""
<header class="neighbor-report-header">
  <div class="neighbor-report-kicker">MESHCORE PACKETTAP</div>
  <h1>Nachbar-Report</h1>
  <div class="neighbor-report-object">{esc(selected.adv_name or "(ohne Namen)")}</div>
  <div class="neighbor-report-object-key mono">
    Public Key: {esc(selected.public_key)}
  </div>
  <div class="neighbor-report-meta">
    <div>
      <span>Beobachtungsstandort</span>
      <strong>{esc(observer_name or "–")}</strong>
      <small class="mono">Public Key: {esc(mr.short_receiver_key(observer_id))}</small>
    </div>
    <div>
      <span>Beobachtungszeitraum</span>
      <strong>{esc(mr.format_period_de(normalize_date(date_from)))} – {esc(mr.format_period_de(normalize_date(date_to, end=True)))}</strong>
    </div>
  </div>
</header>
"""

    footer = f"""
<footer class="neighbor-report-footer">
  MeshCore PacketTap · Nachbar-Report · erstellt am {esc(created)}
</footer>
"""

    css = r"""
:root {
  --fg:#1f1f1f;
  --muted:#6a6a6a;
  --line:#d8d8d8;
  --soft:#f5f5f5;
}
* { box-sizing:border-box; }
body {
  margin:0;
  background:#fff;
  color:var(--fg);
  font-family:Arial,Helvetica,sans-serif;
  line-height:1.4;
}
.report-page {
  max-width:1100px;
  margin:0 auto;
  padding:34px 38px 26px;
}
.neighbor-report-header {
  border-bottom:2px solid #333;
  padding-bottom:18px;
  margin-bottom:22px;
}
.neighbor-report-kicker {
  color:var(--muted);
  font-size:.82rem;
  font-weight:700;
  letter-spacing:.08em;
  text-transform:uppercase;
}
.neighbor-report-header h1 {
  margin:4px 0 3px;
  font-size:1.7rem;
}
.neighbor-report-object {
  font-size:1.12rem;
  font-weight:700;
  margin-top:7px;
}
.neighbor-report-object-key {
  color:var(--muted);
  font-size:.8rem;
  margin-top:3px;
  margin-bottom:16px;
}
.neighbor-report-meta {
  display:grid;
  grid-template-columns:2fr 1fr;
  gap:14px;
}
.neighbor-report-meta > div {
  border:1px solid var(--line);
  border-radius:8px;
  background:var(--soft);
  padding:10px 12px;
}
.neighbor-report-meta span,
.neighbor-kpi span {
  display:block;
  color:var(--muted);
  font-size:.78rem;
  margin-bottom:4px;
}
.neighbor-report-meta strong { display:block; }
.neighbor-report-meta small {
  display:block;
  margin-top:3px;
  color:var(--muted);
  overflow-wrap:anywhere;
}
.mono { font-family:Consolas,monospace; }
.help,.muted { color:var(--muted); }
.neighbor-kpis {
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:12px;
  margin-bottom:26px;
}
.neighbor-kpi {
  border:1px solid var(--line);
  border-radius:9px;
  background:var(--soft);
  padding:14px;
}
.neighbor-kpi strong {
  display:block;
  font-size:1.22rem;
}
.neighbor-kpi small {
  display:block;
  color:var(--muted);
  margin-top:5px;
}
.neighbor-section {
  margin-top:28px;
  break-inside:avoid;
}
.neighbor-section h2 {
  border-bottom:1px solid var(--line);
  padding-bottom:7px;
  margin-bottom:8px;
}
.neighbor-signal-block { display:grid; gap:14px; }
.signal-explanation { margin-top:8px; }
.signal-explanation h3 { margin:0 0 4px; font-size:1rem; }
.signal-explanation p {
  margin:0;
  color:var(--muted);
  font-size:.86rem;
}
.neighbor-chart-wrap {
  border:1px solid var(--line);
  border-radius:9px;
  background:#fff;
  overflow:hidden;
  break-inside:avoid;
}
.neighbor-chart-title {
  display:flex;
  justify-content:space-between;
  padding:10px 14px 0;
}
.neighbor-chart-title span { color:var(--muted); font-size:.8rem; }
.neighbor-chart { display:block; width:100%; height:auto; }
.neighbor-chart-grid { stroke:#e5e5e5; stroke-width:1; }
.neighbor-chart-tick { stroke:#999; stroke-width:1; }
.neighbor-chart-label { fill:#666; font:11px Arial,Helvetica,sans-serif; }
.neighbor-chart-line {
  fill:none;
  stroke-width:2.4;
  stroke-linejoin:round;
  stroke-linecap:round;
}
.neighbor-chart-line.rssi { stroke:#2f6fb0; }
.neighbor-chart-line.snr { stroke:#c06a2b; }
.neighbor-map {
  width:100%;
  height:430px;
  border:1px solid var(--line);
  border-radius:9px;
  background:#ececec;
}
.neighbor-map .leaflet-tile-pane,
.neighbor-map .leaflet-tile {
  opacity:1 !important;
  filter:none !important;
}
.neighbor-empty {
  border:1px solid var(--line);
  border-radius:9px;
  background:var(--soft);
  color:var(--muted);
  padding:16px;
}
table.neighbor-advert-table {
  width:100%;
  border-collapse:collapse;
  table-layout:fixed;
  margin-top:12px;
}
.neighbor-advert-table th {
  background:var(--soft);
  border-bottom:1px solid var(--line);
  padding:10px 12px;
  text-align:left;
  font-size:.84rem;
}
.neighbor-advert-table td {
  border-bottom:1px solid #e7e7e7;
  padding:10px 12px;
}
.neighbor-advert-table .num {
  text-align:right;
  white-space:nowrap;
  font-variant-numeric:tabular-nums;
}
.neighbor-advert-type { width:12%; }
.neighbor-advert-time { width:34%; }
.neighbor-advert-signal { width:15%; }
.neighbor-advert-region { width:24%; }
.advert-type {
  display:inline-block;
  min-width:62px;
  padding:4px 8px;
  border-radius:999px;
  font-size:.76rem;
  font-weight:700;
  text-align:center;
}
.advert-type.direct { background:#f0f0f0; color:#444; }
.advert-type.flood { background:#e9eef5; color:#2f4f6f; }
.flood-advert-row { background:#fafcff; }
.neighbor-report-footer {
  border-top:1px solid var(--line);
  margin-top:32px;
  padding-top:10px;
  color:var(--muted);
  font-size:.76rem;
}
@page {
  margin:10mm;
}
@media print {
  body { margin:0; padding:0; }
  .report-page { max-width:none; margin:0; padding:0; }

  /* Erste Seite kompakter halten. */
  .neighbor-report-header {
    break-after:avoid-page;
    padding-bottom:16px;
    margin-bottom:14px;
  }
  .neighbor-report-header h1 {
    margin-bottom:2px;
  }
  .neighbor-report-meta {
    margin-top:10px;
    gap:10px;
  }
  .neighbor-report-meta > div {
    padding:10px 12px;
  }
  .neighbor-kpis {
    break-inside:avoid-page;
    gap:8px;
    margin-bottom:14px;
  }
  .neighbor-kpi {
    padding:10px 11px;
  }
  .neighbor-kpi strong {
    font-size:1.12rem;
  }
  .neighbor-kpi small {
    margin-top:3px;
  }

  /* Alle weiteren Kapitel beginnen bewusst auf einer neuen Seite. */
  .neighbor-section {
    break-before:page;
    break-inside:auto;
  }

  /* Position bleibt auf Seite 1 und wird als kompletter Block behandelt. */
  .neighbor-position-section {
    break-before:auto;
    break-inside:avoid-page;
    margin-top:14px;
  }
  .neighbor-position-section h2 {
    margin-top:0;
  }
  .neighbor-position-section .help {
    margin-bottom:8px;
  }
  .neighbor-position-section .neighbor-map {
    height:330px;
    break-inside:avoid-page;
  }

  .neighbor-section h2 { break-after:avoid-page; }
  .neighbor-section > .help { break-after:avoid-page; }
  .neighbor-chart-wrap { break-inside:avoid-page; }
  .neighbor-map { break-inside:avoid-page; }
  .neighbor-advert-table { break-inside:avoid-page; }
  .neighbor-advert-table thead { display:table-header-group; }
  .neighbor-advert-table tr { break-inside:avoid-page; }
}
"""

    html = f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<link rel="stylesheet" href="/map/leaflet/leaflet.css">
<script src="/map/leaflet/leaflet.js"></script>
<style>{css}</style>
</head>
<body>
  <main class="report-page">
    {report_header}
    {export_details}
    {footer}
  </main>
</body>
</html>"""
    return html.encode("utf-8")



def save_neighbor_analysis(
    config: dict[str, Any],
    neighbor_query: str,
    date_from: str,
    date_to: str,
    output_format: str,
) -> Path:
    """Persist the current neighbor analysis as HTML or PDF."""
    if not neighbor_query:
        raise RuntimeError("Kein Nachbar ausgewählt.")
    if not date_from or not date_to:
        raise RuntimeError("Beobachtungszeitraum fehlt.")
    if date_to < date_from:
        raise RuntimeError(
            "Das Bis-Datum darf nicht vor dem Von-Datum liegen."
        )

    # Resolve once so the filename is stable and readable.
    _, direct_contacts, _ = direct_neighbor_dataset(
        config,
        date_from,
        date_to,
    )
    selected = resolve_direct_neighbor_selection(
        direct_contacts,
        neighbor_query,
    )

    clean_name = safe_filename(
        selected.adv_name or selected.public_key[:8]
    )
    filename = (
        f"neighbor_{clean_name}_{date_from}_{date_to}.html"
    )

    # Build the detail once using the existing analysis implementation.
    rendered = neighbor_page(
        config,
        selected_query=selected.public_key,
        date_from=date_from,
        date_to=date_to,
        export_mode=True,
    ).decode("utf-8")

    detail_start = rendered.find('<section class="neighbor-detail">')
    detail_end = rendered.find("</section>", detail_start)
    if detail_start < 0 or detail_end < 0:
        raise RuntimeError(
            "Nachbar-Report konnte nicht für den Export aufbereitet werden."
        )
    detail_end += len("</section>")
    details_html = rendered[detail_start:detail_end]

    # Determine exactly the same observation-site identity used by the
    # neighbor analysis and Mesh map.
    all_rows, _, _ = direct_neighbor_dataset(
        config,
        date_from,
        date_to,
    )
    observer_name, observer_id = mr.determine_observer(
        all_rows,
        config.get("receiver_id") or None,
        config.get("receiver_name") or None,
    )

    html_text = neighbor_export_page(
        config,
        selected,
        date_from,
        date_to,
        details_html,
        observer_name,
        observer_id,
    ).decode("utf-8")

    token = create_preview(
        html_text,
        filename,
        "neighbor",
        f"Nachbar – {selected.adv_name or selected.public_key[:8]}",
    )

    try:
        if output_format == "pdf":
            return save_preview_pdf(config, token)
        raise RuntimeError("Es wird nur PDF als Speicherformat unterstützt.")
    finally:
        try:
            html_path, meta_path = preview_paths(token)
            if html_path.exists():
                html_path.unlink()
            if meta_path.exists():
                meta_path.unlink()
        except OSError:
            pass



def form_page(
    config: dict[str, Any],
    message: str = "",
    error: bool = False,
) -> bytes:
    try:
        contacts = get_contacts(config)
        repeaters = sorted(
            (
                c for c in contacts
                if c.node_role == "repeater"
            ),
            key=lambda c: (c.adv_name.lower(), c.public_key),
        )
        options = "\n".join(
            f'<option value="{esc(c.adv_name)}">'
            f'{esc(c.public_key[:4])} · {esc(c.public_key[:12])}…'
            "</option>"
            for c in repeaters
            if c.adv_name
        )
        contact_note = (
            f"{len(repeaters)} bekannte Repeater aus QuestDB geladen."
        )
    except Exception as exc:
        options = ""
        contact_note = f"Repeaterliste konnte nicht geladen werden: {exc}"

    msg_html = ""
    if message:
        cls = "error" if error else "ok"
        msg_html = f'<div class="message {cls}">{esc(message)}</div>'

    default_from, default_to = default_report_dates()

    body = f"""
{msg_html}
<div class="card">
  <h2>Repeater Report erzeugen</h2>
  <p class="help">
    Repeater über exakten Namen oder 2-Byte-Hash auswählen. Die
    QuestDB- und Receiver-Einstellungen werden aus report_config.json gelesen.
  </p>

  <form method="post" action="/generate">
    <div class="field">
      <label for="repeater">Repeater</label>
      <input
        id="repeater"
        name="repeater"
        list="repeaters"
        required
        placeholder="z. B. Bruchsal Tower oder 11b1"
        autocomplete="off"
      >
      <datalist id="repeaters">
        {options}
      </datalist>
      <div class="help">{esc(contact_note)}</div>
    </div>

    <div class="grid">
      <div class="field">
        <label for="date_from">Von</label>
        <input id="date_from" name="date_from" type="date" value="{esc(default_from)}" required>
      </div>
      <div class="field">
        <label for="date_to">Bis</label>
        <input id="date_to" name="date_to" type="date" value="{esc(default_to)}" required>
      </div>
    </div>

    <button type="submit">Report erzeugen</button>
  </form>
</div>
"""
    return page("Repeater Report", body)


def mesh_form_page(
    config: dict[str, Any],
    message: str = "",
    error: bool = False,
) -> bytes:
    msg_html = ""
    if message:
        cls = "error" if error else "ok"
        msg_html = f'<div class="message {cls}">{esc(message)}</div>'

    default_from, default_to = default_report_dates()

    try:
        mesh_map_html, mesh_map_summary = build_mesh_overview(config)
    except Exception as exc:
        mesh_map_html = (
            "<div class='map-error'>"
            "Mesh-Karte konnte nicht geladen werden: "
            f"{esc(exc)}"
            "</div>"
        )
        map_from, map_to = mesh_overview_dates()
        mesh_map_summary = {
            "repeaters": "–",
            "geo_repeaters": "–",
            "date_from": map_from,
            "date_to": map_to,
        }

    body = f"""
{msg_html}
<div class="card">
  <h2>Mesh Report erzeugen</h2>
  <p class="help">
    Erstellt einen standortbezogenen Report über das vom konfigurierten
    PacketTap-Receiver beobachtete Mesh. Repeater-Auswahl ist nicht notwendig.
  </p>

  <div class="message">
    <strong>Beobachtungsstandort:</strong>
    {esc(config.get('receiver_name') or 'nicht konfiguriert')}
  </div>

  <form method="post" action="/generate-mesh">
    <div class="grid">
      <div class="field">
        <label for="date_from">Von</label>
        <input id="date_from" name="date_from" type="date" value="{esc(default_from)}" required>
      </div>
      <div class="field">
        <label for="date_to">Bis</label>
        <input id="date_to" name="date_to" type="date" value="{esc(default_to)}" required>
      </div>
    </div>

    <button type="submit">Mesh Report erzeugen</button>
  </form>
</div>

<section class="mesh-overview">
  <div class="mesh-overview-header">
    <div>
      <h2>Karte des beobachteten Mesh</h2>
      <div class="help">
        Langzeitübersicht der letzten 28 Tage, unabhängig vom Report-Zeitraum.
      </div>
    </div>
  </div>
  <div class="mesh-overview-facts">
    <div class="mesh-overview-fact">
      <span class="fact-label">Zeitraum</span>
      <strong>{esc(mesh_map_summary['date_from'])} – {esc(mesh_map_summary['date_to'])}</strong>
    </div>
    <div class="mesh-overview-fact">
      <span class="fact-label">Beobachtete Repeater</span>
      <strong>{esc(mesh_map_summary['repeaters'])}</strong>
    </div>
    <div class="mesh-overview-fact">
      <span class="fact-label">Mit bekannten Koordinaten</span>
      <strong>{esc(mesh_map_summary['geo_repeaters'])}</strong>
    </div>
  </div>
  {mesh_map_html}
</section>
"""
    return page("Mesh Report", body)


def settings_page(
    config: dict[str, Any],
    message: str = "",
    error: bool = False,
) -> bytes:
    msg_html = ""
    if message:
        cls = "error" if error else "ok"
        msg_html = f'<div class="message {cls}">{esc(message)}</div>'

    body = f"""
{msg_html}
<div class="card">
  <h2>Einstellungen</h2>
  <p class="help">
    Diese Werte werden in <span class="mono">report_config.json</span>
    gespeichert. Änderungen an Web Host oder Web Port werden erst nach einem
    Neustart des Servers aktiv.
  </p>

  <form method="post" action="/settings">
    <div class="grid">
      <div class="field">
        <label for="questdb_host">QuestDB Host</label>
        <input id="questdb_host" name="questdb_host"
               value="{esc(config['questdb_host'])}" required>
      </div>
      <div class="field">
        <label for="questdb_port">QuestDB Port</label>
        <input id="questdb_port" name="questdb_port" type="number"
               value="{esc(config['questdb_port'])}" required>
      </div>
    </div>

    <div class="field">
      <label for="receiver_name">Receiver Name</label>
      <input id="receiver_name" name="receiver_name"
             value="{esc(config.get('receiver_name', ''))}">
    </div>

    <div class="field">
      <label for="receiver_id">Receiver Public Key / ID</label>
      <input id="receiver_id" name="receiver_id"
             value="{esc(config.get('receiver_id', ''))}">
      <div class="help">
        Optional. Leer lassen, wenn über den Receiver-Namen gefiltert wird.
      </div>
    </div>

    <div class="field">
      <label for="output_dir">Ausgabeordner</label>
      <input id="output_dir" name="output_dir"
             value="{esc(config['output_dir'])}" required>
    </div>

    <div class="grid">
      <div class="field">
        <label for="log_dir">Log-Verzeichnis</label>
        <input id="log_dir" name="log_dir"
               value="{esc(config['log_dir'])}" required>
      </div>
      <div class="field">
        <label for="importer_state">Importer Checkpoint-Datei</label>
        <input id="importer_state" name="importer_state"
               value="{esc(config['importer_state'])}" required>
      </div>
    </div>

    <div class="grid">
      <div class="field">
        <label for="receiver_script">Receiver Script</label>
        <input id="receiver_script" name="receiver_script"
               value="{esc(config['receiver_script'])}" required>
      </div>
      <div class="field">
        <label for="importer_script">Importer Script</label>
        <input id="importer_script" name="importer_script"
               value="{esc(config['importer_script'])}" required>
      </div>
    </div>

    <div class="grid">
      <div class="field">
        <label for="receiver_args">Receiver Argumente</label>
        <input id="receiver_args" name="receiver_args"
               value="{esc(' '.join(config['receiver_args']))}"
               placeholder="optional">
      </div>
      <div class="field">
        <label for="importer_args">Importer Argumente</label>
        <input id="importer_args" name="importer_args"
               value="{esc(' '.join(config['importer_args']))}"
               placeholder="z. B. --follow">
      </div>
    </div>

    <div class="grid">
      <div class="field">
        <label for="receiver_lock">Receiver Lock-Datei</label>
        <input id="receiver_lock" name="receiver_lock"
               value="{esc(config['receiver_lock'])}" required>
      </div>
      <div class="field">
        <label for="receiver_stop">Receiver Stop-Datei</label>
        <input id="receiver_stop" name="receiver_stop"
               value="{esc(config['receiver_stop'])}" required>
      </div>
    </div>

    <div class="grid">
      <div class="field">
        <label for="importer_lock">Importer Lock-Datei</label>
        <input id="importer_lock" name="importer_lock"
               value="{esc(config['importer_lock'])}" required>
      </div>
      <div class="field">
        <label for="importer_stop">Importer Stop-Datei</label>
        <input id="importer_stop" name="importer_stop"
               value="{esc(config['importer_stop'])}" required>
      </div>
    </div>

    <div class="grid">
      <div class="field">
        <label>
          <input type="checkbox"
                 name="auto_start_receiver"
                 value="1"
                 {'checked' if config['auto_start_receiver'] else ''}>
          Receiver beim Start der Weboberfläche automatisch starten
        </label>
      </div>
      <div class="field">
        <label>
          <input type="checkbox"
                 name="auto_start_importer"
                 value="1"
                 {'checked' if config['auto_start_importer'] else ''}>
          Importer beim Start der Weboberfläche automatisch starten
        </label>
      </div>
    </div>

    <div class="field">
      <label for="dashboard_refresh_seconds">Dashboard Refresh (Sekunden)</label>
      <input id="dashboard_refresh_seconds"
             name="dashboard_refresh_seconds"
             type="number"
             min="0"
             value="{esc(config['dashboard_refresh_seconds'])}" required>
      <div class="help">0 = automatische Aktualisierung deaktiviert.</div>
    </div>

    <div class="grid">
      <div class="field">
        <label for="web_host">Web Host</label>
        <input id="web_host" name="web_host"
               value="{esc(config['web_host'])}" required>
        <div class="help">
          Windows lokal: 127.0.0.1 · Linux/LAN später: 0.0.0.0
        </div>
      </div>
      <div class="field">
        <label for="web_port">Web Port</label>
        <input id="web_port" name="web_port" type="number"
               value="{esc(config['web_port'])}" required>
      </div>
    </div>

    <button type="submit">Einstellungen speichern</button>
  </form>
</div>
"""
    return page("Einstellungen", body)


def auto_start_services(config: dict[str, Any]) -> None:
    """Start missing PacketTap services in safe dependency order."""
    import time

    if config.get("auto_start_receiver", True):
        running, _ = service_status(config["receiver_lock"])
        if not running:
            message = start_script(
                config["receiver_script"],
                config["receiver_args"],
                config["receiver_lock"],
                config["receiver_stop"],
                config,
            )
            print(f"[WEB] Auto-Start Receiver: {message}")

    # Give the receiver a brief chance to acquire its lock before importer start.
    if config.get("auto_start_importer", True):
        if config.get("auto_start_receiver", True):
            deadline = time.time() + 3.0
            while time.time() < deadline:
                receiver_running, _ = service_status(config["receiver_lock"])
                if receiver_running:
                    break
                time.sleep(0.15)

        running, _ = service_status(config["importer_lock"])
        if not running:
            message = start_script(
                config["importer_script"],
                config["importer_args"],
                config["importer_lock"],
                config["importer_stop"],
                config,
            )
            print(f"[WEB] Auto-Start Importer: {message}")


def dashboard_redirect_url(message: str = "", error: bool = False) -> str:
    params: dict[str, str] = {}
    if message:
        params["message"] = message
    if error:
        params["error"] = "1"
    query = urllib.parse.urlencode(params)
    return "/" + (f"?{query}" if query else "")


def reports_asset_path(url_path: str) -> Path | None:
    """Resolve /reports/... safely below BASE_DIR/reports."""
    if not url_path.startswith("/reports/"):
        return None

    relative = urllib.parse.unquote(url_path[len("/reports/"):])
    candidate = (REPORTS_DIR / relative).resolve()
    root = REPORTS_DIR.resolve()

    try:
        candidate.relative_to(root)
    except ValueError:
        return None

    return candidate


def map_asset_path(url_path: str) -> Path | None:
    """Resolve /map/... safely below BASE_DIR/map."""
    if not url_path.startswith("/map/"):
        return None

    relative = urllib.parse.unquote(url_path[len("/map/"):])
    candidate = (MAP_DIR / relative).resolve()
    root = MAP_DIR.resolve()

    try:
        candidate.relative_to(root)
    except ValueError:
        return None

    return candidate


def map_content_type(path: Path) -> str:
    suffix = path.suffix.lower()
    explicit = {
        ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".svg": "image/svg+xml",
        ".webp": "image/webp",
    }
    if suffix in explicit:
        return explicit[suffix]
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "application/octet-stream"


class Handler(BaseHTTPRequestHandler):
    server_version = "MeshCoreReportUI/" + APP_VERSION

    def log_message(self, fmt: str, *args: Any) -> None:
        print(
            f"[WEB] {self.address_string()} "
            + (fmt % args),
            file=sys.stdout,
        )

    def send_html(
        self,
        content: bytes,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def parse_post(self) -> dict[str, str]:
        size = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(size).decode("utf-8")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {
            key: values[-1]
            for key, values in parsed.items()
        }

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            config = load_config()

            if path.startswith("/map/"):
                asset = map_asset_path(path)
                if asset is None or not asset.is_file():
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return

                data = asset.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", map_content_type(asset))
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(data)
                return

            if path == "/":
                query = urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
                message = query.get("message", [""])[-1]
                error = query.get("error", ["0"])[-1] == "1"
                self.send_html(
                    dashboard_page(
                        config,
                        message=message,
                        error=error,
                    )
                )
                return

            if path == "/report":
                self.send_html(form_page(config))
                return

            if path == "/mesh":
                self.send_html(mesh_form_page(config))
                return

            if path == "/neighbors":
                query = urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
                neighbor = query.get("neighbor", [""])[-1]
                date_from = query.get("date_from", [""])[-1] or None
                date_to = query.get("date_to", [""])[-1] or None
                message = query.get("message", [""])[-1]
                error = query.get("error", ["0"])[-1] == "1"
                self.send_html(
                    neighbor_page(
                        config,
                        selected_query=neighbor,
                        date_from=date_from,
                        date_to=date_to,
                        message=message,
                        error=error,
                    )
                )
                return

            if path == "/settings":
                self.send_html(settings_page(config))
                return

            if path.startswith("/preview/"):
                token = path[len("/preview/"):]
                query = urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                )
                message = query.get("message", [""])[-1]
                error = query.get("error", ["0"])[-1] == "1"
                self.send_html(
                    preview_page(
                        token,
                        message=message,
                        error=error,
                    )
                )
                return

            if path.startswith("/preview-files/"):
                filename = path[len("/preview-files/"):]
                match = re.fullmatch(r"([0-9a-f]{32})\.html", filename)
                if not match:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return

                html_path, _ = preview_paths(match.group(1))
                if not html_path.is_file():
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return

                data = html_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                return

            if path.startswith("/reports/"):
                candidate = reports_asset_path(path)

                if candidate is None or not candidate.is_file():
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return

                data = candidate.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", map_content_type(candidate))
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(data)
                return

            self.send_error(HTTPStatus.NOT_FOUND)

        except Exception as exc:
            self.send_html(
                page(
                    "Fehler",
                    f'<div class="message error">{esc(exc)}</div>',
                ),
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            config = load_config()
            data = self.parse_post()

            if path == "/service":
                service = data.get("service", "")
                action = data.get("action", "")
                services = {
                    "receiver": (
                        config["receiver_script"],
                        config["receiver_args"],
                        config["receiver_lock"],
                        config["receiver_stop"],
                    ),
                    "importer": (
                        config["importer_script"],
                        config["importer_args"],
                        config["importer_lock"],
                        config["importer_stop"],
                    ),
                }
                if service not in services:
                    raise RuntimeError("Unbekannter Dienst.")

                script, script_args, lock_name, stop_name = services[service]

                if action == "start":
                    message = start_script(
                        script,
                        script_args,
                        lock_name,
                        stop_name,
                        config,
                    )
                elif action == "stop":
                    message = stop_script(
                        script,
                        lock_name,
                        stop_name,
                    )
                elif action == "restart":
                    stop_message = stop_script(
                        script,
                        lock_name,
                        stop_name,
                    )
                    running, _ = service_status(lock_name)
                    if running:
                        message = stop_message
                    else:
                        start_message = start_script(
                            script,
                            script_args,
                            lock_name,
                            stop_name,
                            config,
                        )
                        message = stop_message + " " + start_message
                else:
                    raise RuntimeError("Unbekannte Aktion.")

                self.redirect(
                    dashboard_redirect_url(message)
                )
                return

            if path == "/generate-mesh":
                date_from = data.get("date_from", "")
                date_to = data.get("date_to", "")

                if date_to < date_from:
                    raise RuntimeError(
                        "Das Bis-Datum darf nicht vor dem Von-Datum liegen."
                    )

                report_html, filename = generate_mesh_report(
                    config,
                    date_from,
                    date_to,
                )

                token = create_preview(
                    report_html,
                    filename,
                    "mesh",
                    "Mesh Report",
                )
                self.redirect(f"/preview/{token}")
                return


            if path == "/settings":
                updated = {
                    "questdb_host": data.get("questdb_host", "").strip(),
                    "questdb_port": int(data.get("questdb_port", "9000")),
                    "receiver_name": data.get("receiver_name", "").strip(),
                    "receiver_id": data.get("receiver_id", "").strip(),
                    "output_dir": data.get("output_dir", "reports").strip(),
                    "web_host": data.get("web_host", "127.0.0.1").strip(),
                    "web_port": int(data.get("web_port", "8080")),
                    "receiver_script": data.get("receiver_script", "receiver.py").strip(),
                    "receiver_args": data.get("receiver_args", "").strip(),
                    "importer_script": data.get("importer_script", "packettap_importer.py").strip(),
                    "importer_args": data.get("importer_args", "--follow").strip(),
                    "log_dir": data.get("log_dir", "logs").strip(),
                    "importer_state": data.get(
                        "importer_state",
                        "state/importer.state",
                    ).strip(),
                    "receiver_lock": data.get(
                        "receiver_lock",
                        "state/receiver.lock",
                    ).strip(),
                    "receiver_stop": data.get(
                        "receiver_stop",
                        "state/receiver.stop",
                    ).strip(),
                    "importer_lock": data.get(
                        "importer_lock",
                        "state/importer.lock",
                    ).strip(),
                    "importer_stop": data.get(
                        "importer_stop",
                        "state/importer.stop",
                    ).strip(),
                    "dashboard_refresh_seconds": int(
                        data.get("dashboard_refresh_seconds", "15")
                    ),
                    "auto_start_receiver": (
                        data.get("auto_start_receiver") == "1"
                    ),
                    "auto_start_importer": (
                        data.get("auto_start_importer") == "1"
                    ),
                }

                import shlex
                updated["receiver_args"] = shlex.split(
                    updated["receiver_args"],
                    posix=not sys.platform.startswith("win"),
                )
                updated["importer_args"] = shlex.split(
                    updated["importer_args"],
                    posix=not sys.platform.startswith("win"),
                )

                if not updated["questdb_host"]:
                    raise RuntimeError("QuestDB Host darf nicht leer sein.")
                if not updated["output_dir"]:
                    raise RuntimeError("Ausgabeordner darf nicht leer sein.")

                save_config(updated)
                self.send_html(
                    settings_page(
                        updated,
                        "Einstellungen gespeichert.",
                    )
                )
                return

            if path == "/generate":
                repeater_query = data.get("repeater", "")
                date_from = data.get("date_from", "")
                date_to = data.get("date_to", "")

                if date_to < date_from:
                    raise RuntimeError(
                        "Das Bis-Datum darf nicht vor dem Von-Datum liegen."
                    )

                report_html, filename, selected = generate_report(
                    config,
                    repeater_query,
                    date_from,
                    date_to,
                )

                token = create_preview(
                    report_html,
                    filename,
                    "repeater",
                    (
                        "Repeater Report – "
                        + (selected.adv_name or selected.public_key[:8])
                    ),
                )
                self.redirect(f"/preview/{token}")
                return

            if path == "/save-neighbor":
                neighbor_query = data.get("neighbor", "")
                date_from = data.get("date_from", "")
                date_to = data.get("date_to", "")
                output_format = data.get("format", "").lower()

                destination = save_neighbor_analysis(
                    config,
                    neighbor_query,
                    date_from,
                    date_to,
                    output_format,
                )

                message = f"Gespeichert: {destination.name}"
                query_string = urllib.parse.urlencode(
                    {
                        "neighbor": neighbor_query,
                        "date_from": date_from,
                        "date_to": date_to,
                        "message": message,
                    }
                )
                self.redirect(f"/neighbors?{query_string}")
                return

            if path == "/save-preview":
                token = data.get("token", "")
                output_format = data.get("format", "").lower()

                if output_format == "pdf":
                    destination = save_preview_pdf(config, token)
                else:
                    raise RuntimeError("Es wird nur PDF als Speicherformat unterstützt.")

                message = f"Gespeichert: {destination.name}"
                self.redirect(
                    f"/preview/{urllib.parse.quote(token)}?"
                    + urllib.parse.urlencode({"message": message})
                )
                return

            self.send_error(HTTPStatus.NOT_FOUND)

        except Exception as exc:
            try:
                config = load_config()
            except Exception:
                config = dict(DEFAULT_CONFIG)

            if path == "/settings":
                self.send_html(
                    settings_page(config, str(exc), error=True),
                    HTTPStatus.BAD_REQUEST,
                )
            elif path == "/generate-mesh":
                self.send_html(
                    mesh_form_page(config, str(exc), error=True),
                    HTTPStatus.BAD_REQUEST,
                )
            elif path == "/save-neighbor":
                neighbor_query = data.get("neighbor", "")
                date_from = data.get("date_from", "")
                date_to = data.get("date_to", "")
                query_string = urllib.parse.urlencode(
                    {
                        "neighbor": neighbor_query,
                        "date_from": date_from,
                        "date_to": date_to,
                        "message": str(exc),
                        "error": "1",
                    }
                )
                self.redirect(f"/neighbors?{query_string}")
            elif path == "/save-preview":
                token = ""
                try:
                    token = data.get("token", "")
                    _preview_token(token)
                    self.redirect(
                        f"/preview/{urllib.parse.quote(token)}?"
                        + urllib.parse.urlencode(
                            {
                                "message": str(exc),
                                "error": "1",
                            }
                        )
                    )
                except Exception:
                    self.send_html(
                        page(
                            "Fehler",
                            f'<div class="message error">{esc(exc)}</div>',
                        ),
                        HTTPStatus.BAD_REQUEST,
                    )
            elif path == "/service":
                self.redirect(
                    dashboard_redirect_url(
                        str(exc),
                        error=True,
                    )
                )
            else:
                self.send_html(
                    form_page(config, str(exc), error=True),
                    HTTPStatus.BAD_REQUEST,
                )


def main() -> int:
    config = load_config()

    # Create config on first run so it can immediately be edited.
    if not CONFIG_FILE.exists():
        save_config(config)

    host = config["web_host"]
    port = config["web_port"]

    MAP_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PREVIEW_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_previews()

    auto_start_services(config)

    server = ThreadingHTTPServer((host, port), Handler)

    print(
        f"[WEB] MeshCore Repeater Report Web UI v{APP_VERSION}"
    )
    print(
        f"[WEB] Öffnen: http://"
        f"{'127.0.0.1' if host == '0.0.0.0' else host}:{port}"
    )
    print(
        f"[WEB] Konfiguration: {CONFIG_FILE}"
    )
    print(
        "[WEB] Reports: http://"
        f"{'127.0.0.1' if host == '0.0.0.0' else host}:{port}/reports/"
    )
    print("[WEB] Beenden mit Strg+C")
    print("[WEB] Receiver und Importer laufen dabei weiter.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[WEB] Beendet.")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
