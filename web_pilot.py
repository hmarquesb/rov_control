"""
Web pilot controller for phones and browsers.

The browser talks HTTP to this process. This process runs the existing
PilotNode and talks to the relay through the project's UDP transport.
"""

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pilot_client import PilotNode, parse_addr


INDEX_HTML = """<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Piloto ROV</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0f141b;
      --panel: #171f29;
      --panel-2: #1f2a36;
      --text: #eef4f8;
      --muted: #91a4b5;
      --accent: #43c6ac;
      --warn: #f2b84b;
      --bad: #f06969;
      --line: #2d3c4c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(720px, 100%);
      margin: 0 auto;
      padding: 16px;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }
    h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 750;
    }
    .pill {
      min-width: 94px;
      padding: 7px 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: var(--muted);
      text-align: center;
      font-size: 13px;
      font-weight: 700;
      white-space: nowrap;
    }
    .pill.ok { color: #081311; background: var(--accent); border-color: var(--accent); }
    .pill.warn { color: #1b1302; background: var(--warn); border-color: var(--warn); }
    .pill.bad { color: #210707; background: var(--bad); border-color: var(--bad); }
    section {
      border-top: 1px solid var(--line);
      padding: 14px 0;
    }
    .status-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .metric {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      min-height: 74px;
    }
    .metric span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .metric strong {
      display: block;
      margin-top: 6px;
      font-size: 24px;
      line-height: 1.1;
    }
    .control-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-top: 12px;
    }
    button {
      width: 100%;
      border: 0;
      border-radius: 8px;
      padding: 15px 12px;
      background: var(--panel-2);
      color: var(--text);
      font: inherit;
      font-size: 17px;
      font-weight: 800;
      touch-action: manipulation;
    }
    button.primary { background: var(--accent); color: #061210; }
    button.warn { background: var(--warn); color: #1d1302; }
    button.bad { background: var(--bad); color: #230808; }
    button:disabled { opacity: .45; }
    label {
      display: block;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      margin-bottom: 8px;
    }
    input[type="range"] {
      width: 100%;
      accent-color: var(--accent);
    }
    .power-line {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 10px;
      margin-bottom: 8px;
    }
    .power-line output {
      font-size: 22px;
      font-weight: 800;
    }
    .notice {
      margin-top: 12px;
      min-height: 44px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 11px 12px;
      color: var(--muted);
      background: #101720;
      font-size: 14px;
      font-weight: 700;
    }
    .notice.ok { color: var(--accent); }
    .notice.warn { color: var(--warn); }
    .notice.bad { color: var(--bad); }
    .log {
      height: 170px;
      overflow: auto;
      background: #0a0e13;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      color: #cad6df;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
    }
    @media (max-width: 460px) {
      main { padding: 12px; }
      .status-grid { grid-template-columns: 1fr; }
      h1 { font-size: 22px; }
      button { min-height: 58px; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Piloto ROV</h1>
      <div id="status-pill" class="pill">offline</div>
    </header>

    <section>
      <div class="status-grid">
        <div class="metric"><span>Relay</span><strong id="relay">-</strong></div>
        <div class="metric"><span>Controle</span><strong id="control">-</strong></div>
        <div class="metric"><span>Bateria</span><strong id="battery">-</strong></div>
        <div class="metric"><span>Profundidade</span><strong id="depth">-</strong></div>
        <div class="metric"><span>Temperatura</span><strong id="temperature">-</strong></div>
        <div class="metric"><span>Thruster</span><strong id="thruster">-</strong></div>
      </div>
    </section>

    <section>
      <button id="connect" class="primary">Conectar ao relay</button>
      <button id="request" style="margin-top: 10px;">Solicitar controle do ROV</button>
      <div id="notice" class="notice">Aguardando conexao.</div>
      <div class="power-line" style="margin-top: 16px;">
        <label for="power">Potencia</label>
        <output id="power-value">50%</output>
      </div>
      <input id="power" type="range" min="0" max="100" value="50">
      <div class="control-row">
        <button id="forward" class="primary">Frente</button>
        <button id="reverse" class="warn">Re</button>
      </div>
      <div class="control-row">
        <button id="stop" class="bad">Parar</button>
        <button id="release">Soltar</button>
      </div>
    </section>

    <section>
      <div class="log" id="log"></div>
    </section>
  </main>

  <script>
    const els = {
      pill: document.getElementById("status-pill"),
      relay: document.getElementById("relay"),
      control: document.getElementById("control"),
      battery: document.getElementById("battery"),
      depth: document.getElementById("depth"),
      temperature: document.getElementById("temperature"),
      thruster: document.getElementById("thruster"),
      connect: document.getElementById("connect"),
      request: document.getElementById("request"),
      notice: document.getElementById("notice"),
      forward: document.getElementById("forward"),
      reverse: document.getElementById("reverse"),
      stop: document.getElementById("stop"),
      release: document.getElementById("release"),
      power: document.getElementById("power"),
      powerValue: document.getElementById("power-value"),
      log: document.getElementById("log")
    };

    async function post(path, body = {}) {
      const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    }

    function setPill(state) {
      els.pill.className = "pill";
      if (state.connected && state.authed && state.controlling) {
        els.pill.textContent = "controlando";
        els.pill.classList.add("ok");
      } else if (state.connected || state.connecting) {
        els.pill.textContent = state.authed ? "autenticado" : "conectando";
        els.pill.classList.add("warn");
      } else {
        els.pill.textContent = "offline";
        els.pill.classList.add("bad");
      }
    }

    function render(state) {
      setPill(state);
      els.relay.textContent = state.relay || "-";
      els.control.textContent = state.controlling || state.target || "-";
      els.battery.textContent = state.telemetry.battery == null ? "-" : state.telemetry.battery + " %";
      els.depth.textContent = state.telemetry.depth == null ? "-" : state.telemetry.depth + " m";
      els.temperature.textContent = state.telemetry.temperature == null ? "-" : state.telemetry.temperature + " C";
      els.thruster.textContent = state.telemetry.thruster_power == null ? "-" : state.telemetry.thruster_power;
      els.connect.disabled = state.connecting || state.connected;
      els.request.disabled = !state.authed || Boolean(state.controlling);
      const canCommand = Boolean(state.authed && state.controlling);
      els.forward.disabled = !canCommand;
      els.reverse.disabled = !canCommand;
      els.stop.disabled = !canCommand;
      els.release.disabled = !canCommand;
      els.notice.className = "notice";
      if (state.controlling) {
        els.notice.textContent = "Controle concedido para " + state.controlling + ".";
        els.notice.classList.add("ok");
      } else if (state.authed) {
        els.notice.textContent = state.control_reason || ("Autenticado, mas sem controle de " + state.target + ".");
        els.notice.classList.add(state.control_status === "denied" ? "bad" : "warn");
      } else if (state.connecting) {
        els.notice.textContent = "Conectando e autenticando no relay.";
        els.notice.classList.add("warn");
      } else {
        els.notice.textContent = "Aguardando conexao.";
      }
      els.log.textContent = state.log.join("\\n");
      els.log.scrollTop = els.log.scrollHeight;
    }

    async function refresh() {
      try {
        const res = await fetch("/api/status", { cache: "no-store" });
        render(await res.json());
      } catch (err) {
        els.pill.textContent = "sem servidor";
        els.pill.className = "pill bad";
      }
    }

    els.power.addEventListener("input", () => {
      els.powerValue.textContent = els.power.value + "%";
    });
    els.connect.addEventListener("click", async () => {
      await post("/api/connect");
      refresh();
    });
    els.request.addEventListener("click", async () => {
      await post("/api/request-control");
      refresh();
    });
    els.forward.addEventListener("click", () => post("/api/command", {
      action: "thruster_frente", value: Number(els.power.value)
    }).then(refresh));
    els.reverse.addEventListener("click", () => post("/api/command", {
      action: "thruster_re", value: Number(els.power.value)
    }).then(refresh));
    els.stop.addEventListener("click", () => post("/api/command", {
      action: "parar", value: 0
    }).then(refresh));
    els.release.addEventListener("click", () => post("/api/release").then(refresh));

    refresh();
    setInterval(refresh, 700);
  </script>
</body>
</html>
"""


class WebPilot:
    def __init__(self, node):
        self.node = node
        self.lock = threading.Lock()
        self.state = {
            "connected": False,
            "connecting": False,
            "authed": False,
            "relay": "",
            "target": node.target,
            "controlling": "",
            "control_status": "idle",
            "control_reason": "",
            "telemetry": {
                "battery": None,
                "depth": None,
                "temperature": None,
                "thruster_power": None,
            },
            "log": [],
        }
        self.node.on_event = self.on_event
        self.node.start(autoconnect=False)

    def on_event(self, event):
        with self.lock:
            kind = event.get("kind")
            if kind == "log":
                self.state["log"].append(event.get("text", ""))
                self.state["log"] = self.state["log"][-80:]
            elif kind == "conn":
                status = event.get("state")
                self.state["relay"] = event.get("relay", self.state["relay"])
                self.state["connecting"] = status in ("connecting", "failover")
                self.state["connected"] = status == "connected"
                if status in ("idle", "failover"):
                    self.state["authed"] = False
                    self.state["controlling"] = ""
                    self.state["control_status"] = "idle"
                    self.state["control_reason"] = ""
            elif kind == "auth":
                self.state["authed"] = event.get("state") == "ok"
                if self.state["authed"] and not self.state["controlling"]:
                    self.state["control_status"] = "waiting"
                    self.state["control_reason"] = f"Aguardando controle de {self.state['target']}."
            elif kind == "control":
                status = event.get("state")
                if status == "granted":
                    self.state["controlling"] = event.get("rov", "")
                    self.state["control_status"] = "granted"
                    self.state["control_reason"] = ""
                elif status in ("released", "rov_offline"):
                    self.state["controlling"] = ""
                    self.state["control_status"] = status
                    self.state["control_reason"] = (
                        "ROV ficou offline." if status == "rov_offline"
                        else f"Controle de {self.state['target']} liberado."
                    )
                elif status == "denied":
                    self.state["controlling"] = ""
                    self.state["control_status"] = "denied"
                    reason = event.get("reason") or "controle negado"
                    self.state["control_reason"] = f"Sem controle de {self.state['target']}: {reason}."
            elif kind == "telemetry":
                for name in ("battery", "depth", "temperature", "thruster_power"):
                    if name in event:
                        self.state["telemetry"][name] = event[name]

    def connect(self):
        self.node.connect()

    def command(self, action, value):
        self.node.send_command(action, int(value))

    def request_control(self):
        self.node.request_control(self.node.target)

    def release(self):
        self.node.release_control()

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.state))

    def stop(self):
        self.node.stop()


def make_handler(controller):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send(self, status, body, content_type="application/json"):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _json(self, status, body):
            self._send(status, json.dumps(body).encode("utf-8"))

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            if not length:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/?"):
                self._send(200, INDEX_HTML, "text/html; charset=utf-8")
            elif self.path == "/api/status":
                self._json(200, controller.snapshot())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            try:
                if self.path == "/api/connect":
                    controller.connect()
                    self._json(200, {"ok": True})
                elif self.path == "/api/request-control":
                    controller.request_control()
                    self._json(200, {"ok": True})
                elif self.path == "/api/command":
                    body = self._read_json()
                    action = body.get("action")
                    if action not in ("thruster_frente", "thruster_re", "parar"):
                        self._json(400, {"error": "invalid action"})
                        return
                    controller.command(action, body.get("value", 0))
                    self._json(200, {"ok": True})
                elif self.path == "/api/release":
                    controller.release()
                    self._json(200, {"ok": True})
                else:
                    self._json(404, {"error": "not found"})
            except Exception as exc:
                self._json(500, {"error": str(exc)})

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Controle web do piloto ROV")
    ap.add_argument("--id", default="pilotoA")
    ap.add_argument("--private-key", default=None)
    ap.add_argument("--target", default="rov1")
    ap.add_argument("--relays", default="127.0.0.1:5000")
    ap.add_argument("--loss", type=float, default=0.0)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    relays = [parse_addr(item) for item in args.relays.split(",") if item.strip()]
    node = PilotNode(args.id, args.private_key, args.target, relays, loss=args.loss)
    controller = WebPilot(node)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(controller))
    print(f"Piloto web em http://{args.host}:{args.port}")
    print("Abra no celular usando o IP deste PC, por exemplo: http://192.168.1.87:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        server.server_close()


if __name__ == "__main__":
    main()
