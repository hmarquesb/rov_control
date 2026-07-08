"""
rov_simulator.py
-----------------
Finge ser o ROV (já que não temos o hardware). Ele:

  1. Registra-se em um relay (o primário) e passa a mandar TELEMETRIA
     periódica (bateria, profundidade, temperatura) pelo canal
     NÃO-CONFIÁVEL — se um pacote se perde, o próximo já traz dado novo.
  2. Recebe COMANDOS do piloto (via relay) pelo canal CONFIÁVEL e atualiza
     seu estado físico simulado.
  3. Manda heartbeat para o relay saber que está vivo.
  4. FAILOVER: monitora os "relay_heartbeat". Se o relay atual ficar mudo
     (caiu), o ROV troca sozinho para o relay backup e se re-registra —
     mantendo seu estado interno (bateria, profundidade) intacto.

Separa a lógica (RovNode) da interface (run_gui) para permitir teste headless.
"""

import argparse
import random
import threading
import time

import quiclite as q
from dh_exchange import (
    GROUP_ID, confirmation_transcript, decode_public, derive_session_key,
    encode_public, fingerprint, generate_keypair, transcript,
)
from identity_keys import load_network_key, sign_transcript, verify_transcript
from video_stream import generate_ppm, fragment_frame

TELEMETRY_INTERVAL = 1.5
HEARTBEAT_INTERVAL = 1.0
FAILOVER_TIMEOUT = 6.0    # relay mudo por mais que isso => trocar de relay
VIDEO_INTERVAL = 0.5
# (maior que o PRIMARY_TIMEOUT do relay, para o backup assumir antes)


class RovState:
    """Estado físico simulado do ROV."""

    def __init__(self):
        self.battery = 100.0
        self.depth = 0.0
        self.temperature = 18.0
        self.thruster_power = 0
        self.lock = threading.Lock()

    def apply_command(self, action, value):
        with self.lock:
            if action == "thruster_frente":
                self.thruster_power = value
                self.depth = self.depth + 0.3 * (value / 100)
            elif action == "thruster_re":
                self.thruster_power = -value
                self.depth = max(0.0, self.depth - 0.3 * (value / 100))
            elif action == "parar":
                self.thruster_power = 0

    def tick(self):
        with self.lock:
            consumo = 0.05 + abs(self.thruster_power) * 0.001
            self.battery = max(0.0, self.battery - consumo)
            self.temperature = 18.0 + random.uniform(-0.3, 0.3)

    def snapshot(self):
        with self.lock:
            return {"battery": round(self.battery, 1),
                    "depth": round(self.depth, 2),
                    "temperature": round(self.temperature, 1),
                    "thruster_power": self.thruster_power}


class RovNode:
    def __init__(self, rov_id, relays, loss=0.0, on_event=None,
                 secret=None, video=True):
        self.rov_id = rov_id
        self.relays = relays            # lista de (ip, porta), [primário, backup]
        self.idx = 0
        self.current = relays[0]
        self.loss = loss
        self.on_event = on_event
        self.secret = load_network_key(secret)
        self.video_enabled = video

        self.state = RovState()
        self.endpoint = None
        self.running = False
        self.registered = False
        self.session_key = None
        self.auth_transcript = None
        self.auth_relay_identity = None
        self.last_relay_seen = time.time()
        self.relay_role = "?"
        self.highest_term = 0
        self.active_lease = None
        self.last_command_seq = -1
        self._connect_started = False

    # -- infraestrutura -----------------------------------------------------
    def start(self, autoconnect=True):
        sock = q.make_udp_socket(("0.0.0.0", 0))  # porta efêmera qualquer
        self.endpoint = q.Endpoint(sock, self._on_message, loss=self.loss,
                                   name=f"rov-{self.rov_id}")
        self.running = True
        threading.Thread(target=self._telemetry_loop, daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._failover_monitor, daemon=True).start()
        if self.video_enabled:
            threading.Thread(target=self._video_loop, daemon=True).start()
        if autoconnect:
            self.connect()
        else:
            self._emit({"kind": "conn", "state": "idle", "rov": self.rov_id})

    def connect(self):
        """Inicia autenticação e registro do dispositivo no relay."""
        if self._connect_started:
            return
        self._connect_started = True
        self._register()

    def stop(self):
        self.running = False
        if self.endpoint:
            self.endpoint.close()

    def _emit(self, event):
        if self.on_event:
            self.on_event(event)

    def _log(self, text):
        print(f"[rov-{self.rov_id}] {text}")
        self._emit({"kind": "log", "text": text})

    def _register(self):
        if not self._connect_started:
            return
        self.registered = False
        self.session_key = None
        self.auth_transcript = None
        self.auth_relay_identity = None
        self.last_relay_seen = time.time()
        self.endpoint.send_reliable(self.current,
                                    {"type": "register", "role": "rov", "id": self.rov_id})
        self._emit({"kind": "conn", "relay": f"{self.current[0]}:{self.current[1]}",
                    "state": "connecting"})
        self._log(f"registrando em {self.current[0]}:{self.current[1]}…")

    # -- recepção -----------------------------------------------------------
    def _on_message(self, addr, msg, reliable):
        if addr == self.current:
            self.last_relay_seen = time.time()
        mtype = msg.get("type")
        if mtype == "auth_challenge" and msg.get("role") == "rov":
            nonce = msg.get("nonce", "")
            relay_identity = msg.get("relay_identity")
            try:
                relay_public = decode_public(msg.get("dh_public"))
                private, public = generate_keypair()
                hs = transcript("rov", self.rov_id, nonce, public, relay_public)
                signature = sign_transcript(self.secret, hs)
                self.session_key = derive_session_key(private, relay_public, nonce, hs)
                self.auth_transcript = hs
                self.auth_relay_identity = relay_identity
            except ValueError as exc:
                self._log(f"troca DH recusada: {exc}")
                return
            self.endpoint.send_reliable(
                self.current, {"type": "auth_response", "dh_group": GROUP_ID,
                               "dh_public": encode_public(public),
                               "signature": signature})
            self._log("chave DH efêmera enviada; transcript autenticado com HMAC")
        elif mtype == "registered":
            expected = fingerprint(self.session_key) if self.session_key else None
            relay_ok = bool(expected and self.auth_transcript and verify_transcript(
                self.secret,
                confirmation_transcript(self.auth_transcript, expected),
                msg.get("relay_signature", ""),
            ))
            if (not relay_ok or msg.get("relay_identity") != self.auth_relay_identity
                    or msg.get("key_fingerprint") != expected):
                self.registered = False
                self.session_key = None
                self.auth_transcript = None
                self.auth_relay_identity = None
                self._log("AUTENTICAÇÃO DO ROV FALHOU: assinatura do relay ou chave DH divergiu")
                return
            self.registered = True
            self.highest_term = max(self.highest_term, int(msg.get("term", 0)))
            self._log(f"conectado ao relay {self.current[0]}:{self.current[1]}")
            self._emit({"kind": "conn", "relay": f"{self.current[0]}:{self.current[1]}",
                        "state": "connected"})
        elif mtype == "command":
            term = int(msg.get("term", 0))
            lease = msg.get("lease_id")
            command_seq = int(msg.get("command_seq", -1))
            if term < self.highest_term:
                self._log(f"comando rejeitado: termo obsoleto {term} < {self.highest_term}")
                return
            if term > self.highest_term or lease != self.active_lease:
                self.highest_term, self.active_lease, self.last_command_seq = term, lease, -1
            if not lease or command_seq <= self.last_command_seq:
                self._log("comando rejeitado: lease inválida ou sequência duplicada")
                return
            self.last_command_seq = command_seq
            action, value = msg.get("action"), msg.get("value")
            self.state.apply_command(action, value)
            self._log(f"comando de '{msg.get('from')}': {action} = {value}")
            self._emit({"kind": "command", "from": msg.get("from"),
                        "action": action, "value": value})
            self._emit({"kind": "telemetry", **self.state.snapshot()})
        elif mtype == "relay_heartbeat":
            self.relay_role = msg.get("role", "?")
            self.highest_term = max(self.highest_term, int(msg.get("term", 0)))
        elif mtype == "not_leader":
            leader = msg.get("leader")
            if leader:
                self._switch_to(tuple(leader), reason="redirecionado pelo follower")
        elif mtype == "auth_fail":
            self._log(f"AUTENTICAÇÃO DO ROV FALHOU: {msg.get('reason')}")
        elif mtype == "error":
            self._log(f"erro do relay: {msg.get('message')}")

    # -- laços periódicos ---------------------------------------------------
    def _telemetry_loop(self):
        while self.running:
            self.state.tick()
            snap = self.state.snapshot()
            # Telemetria vai pelo canal NÃO-CONFIÁVEL (último valor vence).
            if self.registered:
                self.endpoint.send_unreliable(self.current, {"type": "telemetry", **snap})
            self._emit({"kind": "telemetry", **snap})
            time.sleep(TELEMETRY_INTERVAL)

    def _heartbeat_loop(self):
        while self.running:
            if self.registered:
                self.endpoint.send_unreliable(self.current, {"type": "heartbeat"})
            time.sleep(HEARTBEAT_INTERVAL)

    def _video_loop(self):
        frame_id = 0
        while self.running:
            if self.registered:
                ppm = generate_ppm(frame_id)
                for chunk in fragment_frame(self.rov_id, frame_id, ppm):
                    self.endpoint.send_unreliable(self.current, chunk)
                frame_id += 1
            time.sleep(VIDEO_INTERVAL)

    def _failover_monitor(self):
        while self.running:
            time.sleep(0.5)
            if not self._connect_started or len(self.relays) < 2:
                continue
            if time.time() - self.last_relay_seen > FAILOVER_TIMEOUT:
                self._failover()

    def _failover(self):
        old = self.current
        self.endpoint.remove_peer(old)
        self.idx = (self.idx + 1) % len(self.relays)
        self.current = self.relays[self.idx]
        self._log(f"relay {old[0]}:{old[1]} não responde — FAILOVER para "
                  f"{self.current[0]}:{self.current[1]}")
        self._emit({"kind": "conn", "relay": f"{self.current[0]}:{self.current[1]}",
                    "state": "failover"})
        self._register()

    def _switch_to(self, relay, reason):
        if relay == self.current or relay not in self.relays:
            return
        old = self.current
        self.endpoint.remove_peer(old)
        self.current = relay
        self.idx = self.relays.index(relay)
        self._log(f"{reason}: {old[0]}:{old[1]} -> {relay[0]}:{relay[1]}")
        self._register()


# ===========================================================================
# INTERFACE GRÁFICA
# ===========================================================================
def run_gui(node, corner):
    import queue
    import tkinter as tk
    from tkinter import ttk
    import gui_common as g

    ui_q = queue.Queue()
    node.on_event = ui_q.put

    root = g.make_root(f"ROV — {node.rov_id}", corner, 380, 520)

    conn_lbl = tk.Label(root, text="desconectado", font=("Segoe UI", 11, "bold"),
                        bg=g.BG, fg=g.MUTE, pady=6)
    conn_lbl.pack(fill="x")

    frame = tk.Frame(root, bg=g.BG)
    frame.pack(fill="x", padx=14, pady=6)

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("bat.Horizontal.TProgressbar", troughcolor="#11151c",
                    background=g.OKC)
    style.configure("dep.Horizontal.TProgressbar", troughcolor="#11151c",
                    background=g.ACCENT)

    def gauge(parent, name):
        row = tk.Frame(parent, bg=g.BG)
        row.pack(fill="x", pady=4)
        tk.Label(row, text=name, width=12, anchor="w", bg=g.BG, fg=g.FG,
                 font=("Segoe UI", 10)).pack(side="left")
        val = tk.Label(row, text="—", width=10, anchor="e", bg=g.BG, fg=g.ACCENT,
                       font=("Consolas", 11, "bold"))
        val.pack(side="right")
        return val

    bat_bar = ttk.Progressbar(frame, style="bat.Horizontal.TProgressbar",
                              maximum=100, length=340)
    bat_bar.pack(fill="x", pady=(2, 0))
    bat_val = gauge(frame, "Bateria")
    dep_bar = ttk.Progressbar(frame, style="dep.Horizontal.TProgressbar",
                              maximum=50, length=340)
    dep_bar.pack(fill="x", pady=(8, 0))
    dep_val = gauge(frame, "Profundidade")
    tmp_val = gauge(frame, "Temperatura")
    thr_val = gauge(frame, "Thruster")

    tk.Label(root, text="Registro de eventos", bg=g.BG, fg=g.ACCENT,
             font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(8, 0))
    log = g.make_log(root, height=10)
    log.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def handle(item):
        k = item["kind"]
        if k == "log":
            g.log_append(log, item["text"])
        elif k == "conn":
            txt = {"connecting": f"conectando a {item['relay']}…",
                   "connected": f"● online via {item['relay']}",
                   "failover": f"↻ failover → {item['relay']}"}.get(item["state"], "")
            color = {"connected": g.OKC, "failover": g.WARN}.get(item["state"], g.MUTE)
            conn_lbl.config(text=txt, fg=color)
        elif k == "telemetry":
            bat = item["battery"]
            bat_bar["value"] = bat
            bat_val.config(text=f"{bat:.1f} %",
                           fg=g.OKC if bat > 25 else g.BAD)
            dep_bar["value"] = min(item["depth"], 50)
            dep_val.config(text=f"{item['depth']:.2f} m")
            tmp_val.config(text=f"{item['temperature']:.1f} °C")
            thr_val.config(text=f"{item['thruster_power']}")

    g.start_pump(root, ui_q, handle)
    node.start()
    root.protocol("WM_DELETE_WINDOW", lambda: (node.stop(), root.destroy()))
    root.mainloop()


def parse_addr(s):
    host, port = s.split(":")
    return (host, int(port))


def main():
    ap = argparse.ArgumentParser(description="ROV simulado")
    ap.add_argument("--id", default="rov1")
    ap.add_argument("--relays", default="127.0.0.1:5000,127.0.0.1:5001",
                    help="lista de relays separados por vírgula (primário,backup)")
    ap.add_argument("--loss", type=float, default=0.0)
    ap.add_argument("--secret", default=None,
                    help="segredo de rede compartilhado (o mesmo em todos os nós)")
    ap.add_argument("--no-video", action="store_true")
    ap.add_argument("--corner", default="bl")
    ap.add_argument("--no-gui", action="store_true")
    args = ap.parse_args()

    relays = [parse_addr(s) for s in args.relays.split(",")]
    node = RovNode(args.id, relays, loss=args.loss,
                   secret=args.secret, video=not args.no_video)

    if args.no_gui:
        node.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            node.stop()
    else:
        run_gui(node, args.corner)


if __name__ == "__main__":
    main()
