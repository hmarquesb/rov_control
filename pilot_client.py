"""
pilot_client.py
----------------
O Host do PILOTO. Fluxo:

  1. Registra-se no relay dizendo qual ROV quer controlar.
  2. AUTENTICA-SE por SEGREDO compartilhado (HMAC) + Diffie-Hellman efêmero (o segredo nunca vai pela rede).
  3. Se autenticar, pede o controle do ROV (o relay garante exclusão mútua:
     só um piloto por ROV).
  4. Envia COMANDOS (canal confiável) e recebe TELEMETRIA (canal
     não-confiável) em tempo real.
  5. FAILOVER: se o relay atual cair, troca para o backup, re-autentica e
     retoma o controle automaticamente.

Separa a lógica (PilotNode) da interface (run_gui).
"""

import argparse
import threading
import time

import quiclite as q
from dh_exchange import (
    GROUP_ID, confirmation_transcript, decode_public, derive_session_key,
    encode_public, fingerprint, generate_keypair, transcript,
)
from identity_keys import load_network_key, sign_transcript, verify_transcript
from video_stream import FrameAssembler

HEARTBEAT_INTERVAL = 1.0
FAILOVER_TIMEOUT = 6.0  # maior que o PRIMARY_TIMEOUT do relay (backup assume antes)


class PilotNode:
    def __init__(self, pilot_id, secret, target, relays, loss=0.0, on_event=None):
        self.pilot_id = pilot_id
        self.secret = load_network_key(secret)
        self.target = target
        self.relays = relays
        self.idx = 0
        self.current = relays[0]
        self.loss = loss
        self.on_event = on_event

        self.endpoint = None
        self.running = False
        self.authed = False
        self.controlling = None
        self.token = None
        self.session_key = None
        self.auth_transcript = None
        self.auth_relay_identity = None
        self.lease_id = None
        self.term = 0
        self.command_seq = 0
        self.video = FrameAssembler()
        self.last_relay_seen = time.time()
        self._connect_started = False

    # -- infraestrutura -----------------------------------------------------
    def start(self, autoconnect=True):
        """
        Prepara o socket/transporte, mas só INICIA A CONVERSA com o relay se
        autoconnect=True. Na interface gráfica passamos autoconnect=False, para
        que a conexão (registro + autenticação + pedido de controle) só comece
        quando o usuário clicar em "Conectar" — assim dá para mostrar o
        processo ao vivo na apresentação.
        """
        sock = q.make_udp_socket(("0.0.0.0", 0))
        self.endpoint = q.Endpoint(sock, self._on_message, loss=self.loss,
                                   name=f"pilot-{self.pilot_id}")
        self.running = True
        if autoconnect:
            self.connect()
        else:
            self._emit({"kind": "conn", "state": "idle"})

    def connect(self):
        """Inicia de fato a comunicação: registro -> auth -> pedido de controle."""
        if self._connect_started:
            return
        self._connect_started = True
        self._register()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._failover_monitor, daemon=True).start()

    def stop(self):
        self.running = False
        if self.endpoint:
            self.endpoint.close()

    def disconnect(self):
        if self.endpoint:
            self.endpoint.send_reliable(self.current, {"type": "disconnect",
                                                       "token": self.token})
            time.sleep(0.5)
        self.authed = False
        self.controlling = None
        self.token = None
        self.session_key = None
        self.auth_transcript = None
        self.auth_relay_identity = None
        self.lease_id = None
        self._connect_started = False
        self.stop()

    def _emit(self, event):
        if self.on_event:
            self.on_event(event)

    def _log(self, text):
        print(f"[pilot-{self.pilot_id}] {text}")
        self._emit({"kind": "log", "text": text})

    def _register(self):
        self.authed = False
        self.controlling = None
        self.token = None
        self.session_key = None
        self.auth_transcript = None
        self.auth_relay_identity = None
        self.lease_id = None
        self.last_relay_seen = time.time()
        self.endpoint.send_reliable(self.current, {
            "type": "register", "role": "pilot",
            "id": self.pilot_id, "target": self.target,
        })
        self._emit({"kind": "conn", "relay": f"{self.current[0]}:{self.current[1]}",
                    "state": "connecting"})
        self._log(f"registrando em {self.current[0]}:{self.current[1]}…")

    # -- ações do piloto (chamadas pela interface) -------------------------
    def send_command(self, action, value):
        if not self.authed:
            self._log("ainda não autenticado — comando ignorado")
            return
        if not self.controlling:
            self._log("sem controle de nenhum ROV — comando ignorado")
            return
        self.endpoint.send_reliable(self.current,
                                    {"type": "command", "action": action, "value": value,
                                     "token": self.token,
                                     "command_seq": self.command_seq})
        self.command_seq += 1
        self._log(f"comando enviado: {action} = {value}")

    def release_control(self):
        if self.controlling:
            self.endpoint.send_reliable(
                self.current, {"type": "release_control", "token": self.token})
            self._log(f"controle de '{self.controlling}' liberado")
            self.controlling = None
            self._emit({"kind": "control", "state": "released"})

    def request_control(self, rov_id):
        """Escolhe um ROV e solicita seu controle depois da autenticação."""
        self.target = str(rov_id).strip()
        if not self.authed:
            self._log("autentique no relay antes de solicitar um ROV")
            return
        if self.controlling:
            self._log("libere o controle atual antes de escolher outro ROV")
            return
        self.endpoint.send_reliable(
            self.current, {"type": "request_control", "rov": self.target,
                           "token": self.token})
        self._log(f"solicitando controle de '{self.target}'")
    # -- recepção -----------------------------------------------------------
    def _on_message(self, addr, msg, reliable):
        if addr == self.current:
            self.last_relay_seen = time.time()
        mtype = msg.get("type")

        if mtype == "registered":
            self._emit({"kind": "conn", "relay": f"{self.current[0]}:{self.current[1]}",
                        "state": "connected"})
        elif mtype == "auth_challenge":
            nonce = msg.get("nonce")
            relay_identity = msg.get("relay_identity")
            try:
                relay_public = decode_public(msg.get("dh_public"))
                private, public = generate_keypair()
                hs = transcript("pilot", self.pilot_id, nonce, public, relay_public)
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
        elif mtype == "auth_ok":
            expected = fingerprint(self.session_key) if self.session_key else None
            relay_ok = bool(expected and self.auth_transcript and verify_transcript(
                self.secret,
                confirmation_transcript(self.auth_transcript, expected),
                msg.get("relay_signature", ""),
            ))
            if (not relay_ok or msg.get("relay_identity") != self.auth_relay_identity
                    or msg.get("key_fingerprint") != expected):
                self.authed = False
                self.session_key = None
                self.auth_transcript = None
                self.auth_relay_identity = None
                self._log("AUTENTICAÇÃO FALHOU: assinatura do relay ou chave DH divergiu")
                return
            self.authed = True
            self.token = msg.get("token")
            self._log(f"AUTENTICADO; chave de sessão DH {expected}")
            self._emit({"kind": "auth", "state": "ok"})
        elif mtype == "auth_fail":
            self.authed = False
            self._log(f"AUTENTICAÇÃO FALHOU: {msg.get('reason')}")
            self._emit({"kind": "auth", "state": "fail", "reason": msg.get("reason")})
        elif mtype == "control_granted":
            self.controlling = msg.get("rov")
            self.lease_id = msg.get("lease_id")
            self.term = max(self.term, int(msg.get("term", 0)))
            self.command_seq = 0
            self._log(f"controle CONCEDIDO sobre '{self.controlling}'")
            self._emit({"kind": "control", "state": "granted", "rov": self.controlling})
        elif mtype == "control_denied":
            self._log(f"controle NEGADO sobre '{msg.get('rov')}': {msg.get('reason')}")
            self._emit({"kind": "control", "state": "denied", "reason": msg.get("reason")})
        elif mtype == "telemetry":
            self._emit({"kind": "telemetry", "rov": msg.get("rov"),
                        "battery": msg.get("battery"), "depth": msg.get("depth"),
                        "temperature": msg.get("temperature"),
                        "thruster_power": msg.get("thruster_power")})
        elif mtype == "video_chunk":
            frame = self.video.add(msg)
            if frame:
                self._emit({"kind": "video", **frame})
        elif mtype == "rov_offline":
            self._log(f"AVISO: ROV '{msg.get('rov')}' ficou OFFLINE")
            self._emit({"kind": "control", "state": "rov_offline", "rov": msg.get("rov")})
            self.controlling = None
        elif mtype == "relay_heartbeat":
            self.term = max(self.term, int(msg.get("term", 0)))
        elif mtype == "not_leader":
            leader = msg.get("leader")
            if leader:
                self._switch_to(tuple(leader), reason="redirecionado pelo follower")
        elif mtype == "error":
            self._log(f"erro do relay: {msg.get('message')}")

    # -- laços periódicos ---------------------------------------------------
    def _heartbeat_loop(self):
        while self.running:
            self.endpoint.send_unreliable(self.current, {"type": "heartbeat"})
            time.sleep(HEARTBEAT_INTERVAL)

    def _failover_monitor(self):
        while self.running:
            time.sleep(0.5)
            if len(self.relays) < 2:
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
        self._register()  # re-registra, re-autentica e re-pede controle

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
    import gui_common as g

    ui_q = queue.Queue()
    node.on_event = ui_q.put

    root = g.make_root(f"PILOTO — {node.pilot_id}", corner, 400, 600)

    # Botão de conexão manual: a conversa com o relay só começa ao clicar aqui,
    # para dar para mostrar o processo (registro/auth/controle) ao vivo.
    def do_connect():
        conn_btn.config(state="disabled", text="conectando…")
        node.connect()

    conn_btn = tk.Button(root, text="🔌 Conectar ao relay", command=do_connect,
                         bg=g.ACCENT, fg="#0f1117", activebackground=g.ACCENT,
                         relief="flat", font=("Segoe UI", 11, "bold"), pady=8)
    conn_btn.pack(fill="x", padx=10, pady=(8, 4))

    conn_lbl = tk.Label(root, text="desconectado — clique em Conectar",
                        font=("Segoe UI", 10, "bold"), bg=g.BG, fg=g.MUTE)
    conn_lbl.pack(fill="x", pady=(6, 0))
    auth_lbl = tk.Label(root, text="não autenticado", font=("Segoe UI", 10, "bold"),
                        bg=g.BG, fg=g.MUTE)
    auth_lbl.pack(fill="x")
    ctrl_lbl = tk.Label(root, text=f"alvo: {node.target} (sem controle)",
                        font=("Segoe UI", 10, "bold"), bg=g.BG, fg=g.MUTE)
    ctrl_lbl.pack(fill="x", pady=(0, 6))

    # Painel de telemetria
    tele = tk.Frame(root, bg="#11151c")
    tele.pack(fill="x", padx=10, pady=4)
    tele_val = {}
    for name in ("battery", "depth", "temperature", "thruster_power"):
        row = tk.Frame(tele, bg="#11151c")
        row.pack(fill="x", padx=8, pady=2)
        label = {"battery": "Bateria", "depth": "Profundidade",
                 "temperature": "Temperatura", "thruster_power": "Thruster"}[name]
        tk.Label(row, text=label, width=12, anchor="w", bg="#11151c", fg=g.FG,
                 font=("Segoe UI", 10)).pack(side="left")
        v = tk.Label(row, text="—", anchor="e", bg="#11151c", fg=g.ACCENT,
                     font=("Consolas", 11, "bold"))
        v.pack(side="right")
        tele_val[name] = v

    # Controles
    ctl = tk.Frame(root, bg=g.BG)
    ctl.pack(fill="x", padx=10, pady=8)
    tk.Label(ctl, text="Potência", bg=g.BG, fg=g.FG,
             font=("Segoe UI", 9)).pack(anchor="w")
    power = tk.Scale(ctl, from_=0, to=100, orient="horizontal", bg=g.BG, fg=g.FG,
                     troughcolor="#11151c", highlightthickness=0, length=360)
    power.set(50)
    power.pack(fill="x")

    btns = tk.Frame(root, bg=g.BG)
    btns.pack(fill="x", padx=10)

    def cmd_descer():
        node.send_command("descer", int(power.get()))

    def cmd_subir():
        node.send_command("subir", int(power.get()))

    def cmd_parar():
        node.send_command("parar", 0)

    def mkbtn(parent, text, color, fn):
        b = tk.Button(parent, text=text, command=fn, bg=color, fg="#0f1117",
                      activebackground=color, relief="flat", font=("Segoe UI", 10, "bold"),
                      width=8, pady=6)
        return b

    mkbtn(btns, "▼ Descer", g.OKC, cmd_descer).pack(side="left", expand=True, fill="x", padx=2)
    mkbtn(btns, "▲ Subir", g.ACCENT, cmd_subir).pack(side="left", expand=True, fill="x", padx=2)
    mkbtn(btns, "■ Parar", g.WARN, cmd_parar).pack(side="left", expand=True, fill="x", padx=2)
    tk.Button(root, text="Soltar controle", command=node.release_control, bg="#37474f",
              fg=g.FG, relief="flat", font=("Segoe UI", 9)).pack(fill="x", padx=10, pady=(6, 0))

    tk.Label(root, text="Registro de eventos", bg=g.BG, fg=g.ACCENT,
             font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(8, 0))
    log = g.make_log(root, height=8)
    log.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def handle(item):
        k = item["kind"]
        if k == "log":
            g.log_append(log, item["text"])
        elif k == "conn":
            txt = {"idle": "desconectado — clique em Conectar",
                   "connecting": f"conectando a {item.get('relay','')}…",
                   "connected": f"● relay {item.get('relay','')}",
                   "failover": f"↻ failover → {item.get('relay','')}"}.get(item["state"], "")
            conn_lbl.config(text=txt,
                            fg={"connected": g.OKC, "failover": g.WARN}.get(item["state"], g.MUTE))
        elif k == "auth":
            if item["state"] == "ok":
                auth_lbl.config(text="autenticado ✓", fg=g.OKC)
            else:
                auth_lbl.config(text=f"autenticação falhou: {item.get('reason','')}", fg=g.BAD)
        elif k == "control":
            st = item["state"]
            if st == "granted":
                ctrl_lbl.config(text=f"controlando: {item['rov']} ✓", fg=g.OKC)
            elif st == "denied":
                ctrl_lbl.config(text=f"controle negado: {item.get('reason','')}", fg=g.BAD)
            elif st == "released":
                ctrl_lbl.config(text=f"alvo: {node.target} (controle liberado)", fg=g.MUTE)
            elif st == "rov_offline":
                ctrl_lbl.config(text=f"ROV '{item.get('rov')}' OFFLINE", fg=g.BAD)
        elif k == "telemetry":
            tele_val["battery"].config(text=f"{item['battery']} %")
            tele_val["depth"].config(text=f"{item['depth']} m")
            tele_val["temperature"].config(text=f"{item['temperature']} °C")
            tele_val["thruster_power"].config(text=f"{item['thruster_power']}")

    g.start_pump(root, ui_q, handle)
    node.start(autoconnect=False)  # só conecta quando clicar em "Conectar"
    root.protocol("WM_DELETE_WINDOW", lambda: (node.stop(), root.destroy()))
    root.mainloop()


def parse_addr(s):
    host, port = s.split(":")
    return (host, int(port))


def main():
    ap = argparse.ArgumentParser(description="Cliente do piloto")
    ap.add_argument("--id", default="pilotoA")
    ap.add_argument("--secret", default=None,
                    help="segredo de rede compartilhado (o mesmo em todos os nós)")
    ap.add_argument("--target", default="rov1")
    ap.add_argument("--relays", default="127.0.0.1:5000,127.0.0.1:5001")
    ap.add_argument("--loss", type=float, default=0.0)
    ap.add_argument("--corner", default="br")
    ap.add_argument("--no-gui", action="store_true")
    args = ap.parse_args()

    relays = [parse_addr(s) for s in args.relays.split(",")]
    node = PilotNode(args.id, args.secret, args.target, relays, loss=args.loss)

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
