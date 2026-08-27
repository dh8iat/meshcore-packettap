#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import html
import json
import secrets
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

APP_VERSION = "0.1"
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = BASE_DIR / "admin_config.json"
ALLOWED_ACTIONS = {"start", "stop", "restart"}
SERVICE_STATE_MAP = {1:"STOPPED",2:"START_PENDING",3:"STOP_PENDING",4:"RUNNING",5:"CONTINUE_PENDING",6:"PAUSE_PENDING",7:"PAUSED"}
SERVICE_LOCK = threading.Lock()

def load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    mode = str(data.get("mode", "")).lower()
    if mode not in {"controller", "agent"}:
        raise RuntimeError("mode muss controller oder agent sein")
    data["mode"] = mode
    data.setdefault("web_host", "0.0.0.0")
    data.setdefault("web_port", 8081 if mode == "controller" else 8082)
    data.setdefault("request_timeout", 8)
    data.setdefault("action_timeout", 25)
    if not isinstance(data.get("services"), dict):
        raise RuntimeError("services fehlt")
    if mode == "controller":
        if not data.get("admin_username") or not data.get("admin_password"):
            raise RuntimeError("Controller-Zugangsdaten fehlen")
    else:
        if not data.get("agent_token"):
            raise RuntimeError("agent_token fehlt")
    return data

def run_sc(*args: str, timeout: float = 15):
    return subprocess.run(
        ["sc.exe", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )

def service_status(name: str) -> dict[str, Any]:
    r = run_sc("queryex", name)
    out = r.stdout or ""
    if r.returncode != 0:
        return {
            "service": name,
            "state": "NOT_INSTALLED" if "1060" in out else "ERROR",
            "pid": None,
            "ok": False,
            "detail": out.strip(),
        }

    state = "UNKNOWN"
    pid = None
    for raw in out.splitlines():
        line = raw.strip()
        up = line.upper()
        if up.startswith("STATE") or up.startswith("STATUS"):
            for token in line.replace(":", " ").split():
                if token.isdigit():
                    state = SERVICE_STATE_MAP.get(int(token), f"STATE_{token}")
                    break
        elif up.startswith("PID"):
            for token in line.replace(":", " ").split():
                if token.isdigit():
                    pid = int(token)
                    break

    return {
        "service": name,
        "state": state,
        "pid": pid,
        "ok": state not in {"ERROR", "NOT_INSTALLED", "UNKNOWN"},
        "detail": "",
    }

def wait_state(name: str, wanted: str, timeout: float) -> dict[str, Any]:
    end = time.time() + timeout
    last = service_status(name)
    while time.time() < end:
        last = service_status(name)
        if last["state"] == wanted:
            return last
        time.sleep(0.4)
    return last

def service_action(name: str, action: str, timeout: float) -> dict[str, Any]:
    if action not in ALLOWED_ACTIONS:
        raise ValueError("ungueltige Aktion")

    with SERVICE_LOCK:
        before = service_status(name)
        if before["state"] == "NOT_INSTALLED":
            return {"ok": False, "message": "Dienst ist nicht installiert.", "before": before, "after": before}

        if action == "start":
            if before["state"] != "RUNNING":
                run_sc("start", name, timeout=timeout)
            after = wait_state(name, "RUNNING", timeout)
            ok = after["state"] == "RUNNING"

        elif action == "stop":
            if before["state"] != "STOPPED":
                run_sc("stop", name, timeout=timeout)
            after = wait_state(name, "STOPPED", timeout)
            ok = after["state"] == "STOPPED"

        else:
            if before["state"] != "STOPPED":
                run_sc("stop", name, timeout=timeout)
                stopped = wait_state(name, "STOPPED", timeout)
                if stopped["state"] != "STOPPED":
                    return {"ok": False, "message": "Dienst konnte nicht gestoppt werden.", "before": before, "after": stopped}
            run_sc("start", name, timeout=timeout)
            after = wait_state(name, "RUNNING", timeout)
            ok = after["state"] == "RUNNING"

        return {
            "ok": ok,
            "message": "Aktion erfolgreich." if ok else "Zielstatus nicht erreicht.",
            "before": before,
            "after": after,
        }

def basic_ok(handler: BaseHTTPRequestHandler, config: dict[str, Any]) -> bool:
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return False
    try:
        username, password = base64.b64decode(header[6:]).decode("utf-8").split(":", 1)
    except Exception:
        return False
    return (
        secrets.compare_digest(username, str(config["admin_username"]))
        and secrets.compare_digest(password, str(config["admin_password"]))
    )

def bearer_ok(handler: BaseHTTPRequestHandler, config: dict[str, Any]) -> bool:
    return secrets.compare_digest(
        handler.headers.get("Authorization", ""),
        f"Bearer {config['agent_token']}",
    )

def request_json(url: str, token: str, method: str = "GET", payload: dict[str, Any] | None = None, timeout: float = 8):
    data = None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))

def local_status(config: dict[str, Any]) -> dict[str, Any]:
    items = []
    for key, svc in config["services"].items():
        status = service_status(svc["service_name"])
        items.append({"key": key, "label": svc["label"], **status})
    return {"ok": True, "services": items}

def controller_hosts(config: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for host in config["hosts"]:
        row = {
            "id": host["id"],
            "label": host["label"],
            "address": host.get("address", ""),
            "kind": host["kind"],
        }
        if host["kind"] == "local":
            row.update(local_status(config))
            row["reachable"] = True
        else:
            try:
                row.update(
                    request_json(
                        f"http://{host['address']}:{host['port']}/api/status",
                        str(host["token"]),
                        timeout=float(config["request_timeout"]),
                    )
                )
                row["reachable"] = True
            except Exception as exc:
                row.update({"ok": False, "reachable": False, "services": [], "error": str(exc)})
        rows.append(row)
    return rows

def host_action(config: dict[str, Any], host_id: str, service_key: str, action: str) -> dict[str, Any]:
    service = config["services"].get(service_key)
    host = next((h for h in config["hosts"] if h["id"] == host_id), None)
    if not service or not host:
        return {"ok": False, "message": "Host oder Dienst unbekannt."}

    if host["kind"] == "local":
        return service_action(service["service_name"], action, float(config["action_timeout"]))

    try:
        return request_json(
            f"http://{host['address']}:{host['port']}/api/action",
            str(host["token"]),
            method="POST",
            payload={"service": service_key, "action": action},
            timeout=float(config["action_timeout"]) + 5,
        )
    except Exception as exc:
        return {"ok": False, "message": f"Agent nicht erreichbar: {exc}"}

def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)

def state_class(state: str) -> str:
    if state == "RUNNING":
        return "ok"
    if state == "STOPPED":
        return "off"
    if "PENDING" in state:
        return "warn"
    return "bad"

def render(config: dict[str, Any], message: str = "", error: bool = False) -> str:
    cards = []
    for host in controller_hosts(config):
        rows = []
        if not host.get("reachable"):
            rows.append(f'<div class="err">Nicht erreichbar: {esc(host.get("error", ""))}</div>')
        else:
            by_key = {item["key"]: item for item in host["services"]}
            for key, svc_cfg in config["services"].items():
                status = by_key.get(key, {"state": "UNKNOWN", "pid": None})
                state = status["state"]
                pid = f"PID {status['pid']}" if status.get("pid") else "keine PID"
                rows.append(
                    '<div class="row">'
                    f'<div><b>{esc(svc_cfg["label"])}</b>'
                    f'<div class="meta"><span class="{state_class(state)}">{esc(state)}</span> | {esc(pid)} | '
                    f'<code>{esc(svc_cfg["service_name"])}</code></div></div>'
                    '<form method="post" action="/action">'
                    f'<input type="hidden" name="host" value="{esc(host["id"])}">'
                    f'<input type="hidden" name="service" value="{esc(key)}">'
                    '<button name="action" value="start">Start</button>'
                    '<button name="action" value="stop">Stop</button>'
                    '<button name="action" value="restart">Neustart</button>'
                    '</form></div>'
                )
        cards.append(
            f'<section><h2>{esc(host["label"])} <small>{esc(host["address"] or "lokal")}</small></h2>{"".join(rows)}</section>'
        )

    banner = ""
    if message:
        banner = f'<div class="banner {"bad" if error else "ok"}">{esc(message)}</div>'

    return f'''<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<meta http-equiv="refresh" content="15">
<title>MeshCore Service Admin</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#f5f7fa;color:#1f2937;margin:0}}
main{{max-width:1150px;margin:auto;padding:28px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(480px,1fr));gap:18px}}
section{{background:#fff;border:1px solid #ddd;border-radius:12px;overflow:hidden}}
h1{{margin-bottom:4px}} h2{{padding:18px;margin:0;border-bottom:1px solid #eee}}
small,.meta{{color:#667085;font-size:13px}}
.row{{display:flex;justify-content:space-between;gap:20px;align-items:center;padding:16px 18px;border-bottom:1px solid #eee}}
form{{display:flex;gap:6px}}
button{{padding:7px 10px;border:0;border-radius:7px;background:#1967d2;color:white;cursor:pointer}}
.ok{{color:#087a46}} .off{{color:#667085}} .warn{{color:#a15c00}} .bad,.err{{color:#b42318}}
.banner{{margin:14px 0;padding:10px;border:1px solid #ddd;border-radius:8px}}
code{{font-size:12px}}
@media(max-width:700px){{.grid{{grid-template-columns:1fr}}.row{{align-items:flex-start;flex-direction:column}}}}
</style>
</head>
<body>
<main>
<h1>MeshCore Service Admin</h1>
<div class="meta">v{APP_VERSION} | PROD und DEV | Aktualisierung alle 15 s</div>
{banner}
<div class="grid">{"".join(cards)}</div>
</main>
</body>
</html>'''

class AdminServer(ThreadingHTTPServer):
    def __init__(self, address, handler, config):
        super().__init__(address, handler)
        self.config = config

class Handler(BaseHTTPRequestHandler):
    @property
    def config(self):
        return self.server.config

    def log_message(self, fmt, *args):
        print(f"[ADMIN] {self.client_address[0]} {fmt % args}", flush=True)

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, status, body):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def require_controller_auth(self):
        if basic_ok(self, self.config):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="MeshCore Admin"')
        self.end_headers()
        return False

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if self.config["mode"] == "agent":
            if parsed.path == "/health":
                return self.send_json(200, {"ok": True, "mode": "agent", "version": APP_VERSION})
            if parsed.path == "/api/status":
                if not bearer_ok(self, self.config):
                    return self.send_json(401, {"ok": False, "error": "unauthorized"})
                return self.send_json(200, local_status(self.config))
            return self.send_json(404, {"ok": False, "error": "not found"})

        if not self.require_controller_auth():
            return
        if parsed.path == "/":
            query = urllib.parse.parse_qs(parsed.query)
            return self.send_html(
                200,
                render(
                    self.config,
                    query.get("message", [""])[-1],
                    query.get("error", ["0"])[-1] == "1",
                ),
            )
        self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if self.config["mode"] == "agent":
            if parsed.path != "/api/action":
                return self.send_json(404, {"ok": False})
            if not bearer_ok(self, self.config):
                return self.send_json(401, {"ok": False, "error": "unauthorized"})

            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            service = self.config["services"].get(str(data.get("service", "")))
            if not service:
                return self.send_json(400, {"ok": False, "message": "Unbekannter Dienst."})

            result = service_action(
                service["service_name"],
                str(data.get("action", "")),
                float(self.config["action_timeout"]),
            )
            return self.send_json(200 if result["ok"] else 409, result)

        if not self.require_controller_auth():
            return
        if parsed.path != "/action":
            return self.send_error(404)

        length = int(self.headers.get("Content-Length", "0"))
        form = {k: v[-1] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8")).items()}
        result = host_action(
            self.config,
            form.get("host", ""),
            form.get("service", ""),
            form.get("action", ""),
        )

        query = {"message": result.get("message", "")}
        if not result.get("ok"):
            query["error"] = "1"
        self.send_response(303)
        self.send_header("Location", "/?" + urllib.parse.urlencode(query))
        self.end_headers()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()

    config = load_config(args.config.resolve())
    print(
        f"[ADMIN] MeshCore Service Admin v{APP_VERSION} | "
        f"{config['mode']} | {config['web_host']}:{config['web_port']}",
        flush=True,
    )

    server = AdminServer((config["web_host"], int(config["web_port"])), Handler, config)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
