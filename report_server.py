#!/usr/bin/env python3
"""
MeshCore PacketTap Web UI v0.9
====================================

Kleine plattformunabhängige Weboberfläche für repeater_report.py.

Abhängigkeiten:
    Nur Python-Standardbibliothek.

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
import sys
import subprocess
import urllib.request
import urllib.error
import unicodedata
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import repeater_report as rr


APP_VERSION = "0.9"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "report_config.json"

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
) -> tuple[Path, rr.Contact]:
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

    # Beibehaltung derselben Datenmodell-Prüfung wie im CLI-Report.
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

    destination = output_dir(config) / filename
    destination.write_text(
        rr.render_html(
            metrics,
            neighbors,
            neighbors_gt3,
            ranking,
            contacts,
        ),
        encoding="utf-8",
    )

    return destination, selected


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

    if not sys.platform.startswith("win"):
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


def latest_packet_status(config: dict[str, Any]) -> str:
    query = urllib.parse.quote("select max(ts) latest_ts from mc_rx")
    url = f"http://{config['questdb_host']}:{config['questdb_port']}/exec?query={query}"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
        dataset = data.get("dataset") or []
        if dataset and dataset[0] and dataset[0][0]:
            return str(dataset[0][0])
        return "keine Paketdaten"
    except Exception as exc:
        return f"nicht ermittelbar: {exc}"


def questdb_status(config: dict[str, Any]) -> tuple[bool, str]:
    url = f"http://{config['questdb_host']}:{config['questdb_port']}/exec?query=select%201"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            if 200 <= response.status < 300:
                return True, "Verbindung erfolgreich"
            return False, f"HTTP {response.status}"
    except Exception as exc:
        return False, str(exc)


def dashboard_page(config: dict[str, Any], message: str = "", error: bool = False) -> bytes:
    db_ok, db_detail = questdb_status(config)
    latest = latest_packet_status(config) if db_ok else "–"
    receiver_script = config["receiver_script"]
    importer_script = config["importer_script"]
    receiver_ok, receiver_detail = service_status(config["receiver_lock"])
    importer_ok, importer_detail = service_status(config["importer_lock"])
    checkpoint_state, checkpoint_detail = checkpoint_status(config)

    def status_card(
        title: str,
        ok: bool,
        detail: str,
        service: str | None = None,
        extra: str = "",
        state_text: str | None = None,
    ) -> str:
        state = state_text or ("Läuft" if ok else "Gestoppt")
        cls = "ok" if ok else "error"
        controls = ""
        if service:
            restart = '<button name="action" value="restart" type="submit">Neustarten</button>'
            controls = f"""
            <form class="controls" method="post" action="/service">
              <input type="hidden" name="service" value="{esc(service)}">
              <button name="action" value="start" type="submit">Starten</button>
              <button name="action" value="stop" type="submit">Geordnet stoppen</button>
              {restart}
            </form>"""
        return f"""
        <div class="status-card">
          <div class="status-title">{esc(title)}</div>
          <div class="status-value {cls}">{esc(state)}</div>
          <div class="help">{esc(detail)}</div>
          {extra}
          {controls}
        </div>"""

    msg_html = ""
    if message:
        cls = "error" if error else "ok"
        msg_html = f'<div class="message {cls}">{esc(message)}</div>'

    db_extra = f'<div class="help"><strong>Letztes Paket:</strong> {esc(latest)}</div>'
    body = f"""
{msg_html}
<div class="card">
  <h2>PacketTap Übersicht</h2>
  <p class="help">
    Zustand der Datenbank und der PacketTap-Prozesse. Die Steuerung nutzt
    die getesteten OS-Locks und Stop-Dateien. Stoppen und Neustarten erfolgen
    geordnet; ein harter Prozessabbruch wird nicht verwendet.
  </p>
  <div class="status-grid">
    {status_card(
        "QuestDB",
        db_ok,
        db_detail,
        extra=db_extra,
        state_text="OK" if db_ok else "Nicht erreichbar",
    )}
    {status_card(Path(receiver_script).name, receiver_ok, receiver_detail, "receiver")}
    {status_card(Path(importer_script).name, importer_ok, importer_detail, "importer")}
  </div>

  <div class="card" style="margin-top:14px;margin-bottom:0">
    <div class="status-title">Importer Checkpoint</div>
    <div><strong>{esc(checkpoint_state)}</strong></div>
    <div class="help">{esc(checkpoint_detail)}</div>
    <div class="help">
      Die Weboberfläche verändert oder löscht die Checkpoint-Datei nicht.
    </div>
  </div>

  <div class="log-grid">
    <div class="log-card">
      <div class="status-title">Log · {esc(Path(receiver_script).name)}</div>
      <pre>{esc(tail_log(config, receiver_script))}</pre>
    </div>
    <div class="log-card">
      <div class="status-title">Log · {esc(Path(importer_script).name)}</div>
      <pre>{esc(tail_log(config, importer_script))}</pre>
    </div>
  </div>
  <div style="margin-top:16px">
    <a class="button" href="/">Status aktualisieren</a>
  </div>
</div>
"""
    return page("PacketTap Übersicht", body)



def page(title: str, body: str) -> bytes:
    doc = f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
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
  padding:10px 11px;
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
.status-title {{ font-weight:700; margin-bottom:8px; }}
.status-value {{ font-size:1.15rem; font-weight:700; margin-bottom:5px; }}
.status-value.ok {{ color:var(--ok); }}
.status-value.error {{ color:var(--err); }}
.controls {{
  display:flex;
  flex-wrap:wrap;
  gap:6px;
  margin-top:14px;
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
    <a href="/report">Reports</a>
    <a href="/settings">Einstellungen</a>
  </nav>
</header>
{body}
<footer>Report Web UI v{APP_VERSION}</footer>
</body>
</html>"""
    return doc.encode("utf-8")


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

    body = f"""
{msg_html}
<div class="card">
  <h2>Report erzeugen</h2>
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
        <input id="date_from" name="date_from" type="date" required>
      </div>
      <div class="field">
        <label for="date_to">Bis</label>
        <input id="date_to" name="date_to" type="date" required>
      </div>
    </div>

    <button type="submit">Report erzeugen</button>
  </form>
</div>
"""
    return page("Repeater Report", body)


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

            if path == "/":
                self.send_html(dashboard_page(config))
                return

            if path == "/report":
                self.send_html(form_page(config))
                return

            if path == "/settings":
                self.send_html(settings_page(config))
                return

            if path.startswith("/reports/"):
                filename = urllib.parse.unquote(path[len("/reports/"):])
                report_root = output_dir(config)
                candidate = (report_root / filename).resolve()

                if (
                    candidate.parent != report_root
                    or not candidate.is_file()
                    or candidate.suffix.lower() != ".html"
                ):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return

                data = candidate.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
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
                self.send_html(dashboard_page(config, message))
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

                destination, selected = generate_report(
                    config,
                    repeater_query,
                    date_from,
                    date_to,
                )

                report_url = (
                    "/reports/"
                    + urllib.parse.quote(destination.name)
                )

                body = f"""
<div class="message ok">
  Report für <strong>{esc(selected.adv_name or selected.public_key)}</strong>
  wurde erstellt.
</div>
<div class="card">
  <div class="field">
    <label>Datei</label>
    <div class="mono">{esc(destination.name)}</div>
  </div>
  <a class="button" href="{esc(report_url)}" target="_blank">
    Report öffnen
  </a>
  <a class="button" href="/report" style="margin-left:8px">
    Weiteren Report erzeugen
  </a>
</div>
"""
                self.send_html(page("Report erstellt", body))
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
            elif path == "/service":
                self.send_html(
                    dashboard_page(config, str(exc), error=True),
                    HTTPStatus.BAD_REQUEST,
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
    print("[WEB] Beenden mit Strg+C")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[WEB] Beendet.")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
