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
import math
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
PHYSICS_INTERVAL = 0.1    # de quanto em quanto tempo a profundidade é atualizada
DEPTH_RATE = 0.5          # m/s de variação de profundidade com o thruster a 100%


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
            if action == "descer":
                self.thruster_power = value
            elif action == "subir":
                self.thruster_power = -value
            elif action == "parar":
                self.thruster_power = 0

    def apply_physics(self, dt):
        """Move a profundidade continuamente enquanto o thruster estiver ligado
        (chamado a cada PHYSICS_INTERVAL). 'parar' zera thruster_power, então
        essa chamada passa a não ter efeito nenhum — é o que faz 'parar' parar."""
        with self.lock:
            self.depth = max(0.0, self.depth + DEPTH_RATE * (self.thruster_power / 100) * dt)

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
        threading.Thread(target=self._physics_loop, daemon=True).start()
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
    def _physics_loop(self):
        """Atualiza a profundidade continuamente enquanto o thruster estiver
        ligado (descer/subir), até que 'parar' zere a potência. Roda separado
        do _telemetry_loop porque a física precisa de um passo fino (0.1s) para
        a animação ficar suave; a telemetria de rede continua no seu próprio
        intervalo, mais espaçado."""
        last = time.time()
        while self.running:
            time.sleep(PHYSICS_INTERVAL)
            now = time.time()
            self.state.apply_physics(now - last)
            last = now

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
def draw_rov_scene(canvas, node, width, height, now, g):
    """Desenha a cena submarina animada de UM ROV (a profundidade move o veículo,
    a potência controla bolhas e hélices). Portada do demo_dashboard para que o
    ROV avulso também tenha a animação, não só as barras."""
    c = canvas
    c.delete("all")
    rov = node
    x0, x1 = 0, width
    mid = width / 2
    snap = rov.state.snapshot()

    # Água em camadas, raios de luz e partículas suspensas.
    bands = ((0, 85, "#073d59"), (85, 175, "#06344d"),
             (175, 280, "#052b40"), (280, 390, "#042235"))
    for y0, y1, color in bands:
        c.create_rectangle(x0, y0, x1, y1, fill=color, outline="")
    c.create_polygon(x0 + 18, 0, x0 + 76, 0, x0 + 145, 350,
                     x0 + 105, 350, fill="#0b4962", outline="")
    c.create_polygon(x1 - 92, 0, x1 - 50, 0, x1 - 118, 330,
                     x1 - 145, 330, fill="#094158", outline="")
    for particle in range(18):
        px = x0 + 8 + ((particle * 47) % max(20, int(width - 16)))
        py = 58 + ((particle * 71 + int(now * 8)) % 300)
        size = 1 + particle % 2
        c.create_oval(px-size, py-size, px+size, py+size, fill="#4b8ba0", outline="")

    # Leito marinho irregular, pedras, coral e algas oscilantes.
    floor = [x0, 365, x0+35, 354, x0+74, 365, x0+118, 347,
             x0+166, 360, x0+220, 350, x1, 362, x1, 420, x0, 420]
    c.create_polygon(*floor, fill="#806849", outline="#aa8a5b", width=2)
    c.create_oval(x0+38, 350, x0+88, 382, fill="#344b50", outline="#647b78")
    c.create_oval(x1-82, 344, x1-29, 378, fill="#293f46", outline="#526b6c")
    for plant in range(4):
        bx = x0 + 28 + plant * max(42, (width-55)/4)
        sway = math.sin(now * 1.7 + plant) * 6
        c.create_line(bx, 365, bx+sway, 326-plant%2*8, fill="#24a47a", width=4, smooth=True)
        c.create_line(bx+5, 365, bx-8+sway, 337, fill="#17765f", width=3, smooth=True)
    coral_x = x1 - 105
    c.create_line(coral_x, 365, coral_x, 332, coral_x-12, 319, fill="#ef6f61", width=5, smooth=True)
    c.create_line(coral_x, 344, coral_x+14, 326, fill="#f08b72", width=4, smooth=True)

    # Peixes atravessam a cena em velocidades e alturas diferentes.
    for fish in range(5):
        direction = -1 if fish % 2 else 1
        travel = (now * (17 + fish * 3) + fish * 61) % (width + 50)
        fx = x0 - 25 + travel if direction > 0 else x1 + 25 - travel
        fy = 185 + fish * 28 + math.sin(now * 1.8 + fish) * 8
        color = ("#55c6c2", "#ffca62", "#d778b2", "#88bdeb", "#9ed36a")[fish]
        c.create_oval(fx-10, fy-5, fx+10, fy+5, fill=color, outline="#153b49")
        tail = (-16 if direction > 0 else 16)
        c.create_polygon(fx+tail/2, fy, fx+tail, fy-7, fx+tail, fy+7, fill=color, outline="#153b49")
        eye_x = fx + (6 if direction > 0 else -6)
        c.create_oval(eye_x-1, fy-2, eye_x+1, fy, fill="#071820", outline="")

    # Cabeçalho e painel de telemetria.
    c.create_rectangle(x0+8, 8, x1-8, 56, fill="#071923", outline="#27708c")
    c.create_text(mid, 20, text=f"ROV {rov.rov_id.upper()}", fill="#8de1ff",
                  font=("Segoe UI", 11, "bold"))
    state = "ONLINE / REGISTRADO" if rov.registered else "AGUARDANDO REGISTRO"
    c.create_text(mid, 42, text=state, fill=g.OKC if rov.registered else g.MUTE,
                  font=("Segoe UI", 8, "bold"))
    c.create_rectangle(x0+10, 68, x0+126, 144, fill="#071923", outline="#1f6079")
    c.create_text(x0+18, 76, anchor="nw", fill="#d2f3ff", font=("Consolas", 8),
                  text=f"BAT  {snap['battery']:5.1f}%\nDEP  {snap['depth']:5.2f} m\nTMP  {snap['temperature']:5.1f} C\nTHR  {snap['thruster_power']:+4d}")

    # Câmera (o ROV transmite vídeo; esta janela mostra só o status).
    c.create_rectangle(x1-116, 68, x1-8, 158, fill="#06151d",
                       outline="#54b5d4" if rov.registered else "#315767", width=2)
    c.create_text(x1-62, 113, text=("CÂMERA\nA BORDO" if rov.registered else "CÂMERA OFFLINE"),
                  fill=g.OKC if rov.registered else g.MUTE, font=("Segoe UI", 8), justify="center")

    # ROV: a profundidade anima a posição vertical; leve flutuação evita estático.
    cx = mid
    cy = min(322, 215 + min(snap["depth"], 14) * 6) + math.sin(now * 2) * 2
    power = snap["thruster_power"]

    # Fachos dos dois refletores atrás do veículo.
    beam = "#376a70" if rov.registered else "#243b42"
    c.create_polygon(cx+44, cy-13, x1-8, cy-38, x1-8, cy+7, fill=beam, outline="")
    c.create_polygon(cx+44, cy+9, x1-8, cy+18, x1-8, cy+52, fill="#2c5a61", outline="")

    # Estrutura externa, skids, braço e garra.
    c.create_line(cx-43, cy+21, cx-48, cy+36, cx+42, cy+36, cx+47, cy+21,
                  fill="#647985", width=5, joinstyle="round")
    c.create_line(cx+30, cy+22, cx+54, cy+36, cx+70, cy+31, fill="#8b99a0", width=5, smooth=True)
    c.create_line(cx+68, cy+31, cx+76, cy+24, fill="#c0c8ca", width=3)
    c.create_line(cx+68, cy+31, cx+77, cy+37, fill="#c0c8ca", width=3)

    # Thrusters laterais com hélices girando conforme a potência.
    for tx in (cx-50, cx+50):
        c.create_oval(tx-13, cy-13, tx+13, cy+13, fill="#152832", outline="#8da1aa", width=2)
        angle = now * (8 + abs(power)/18) + (0 if tx < cx else 1.5)
        for blade in range(3):
            a = angle + blade * 2.094
            c.create_line(tx, cy, tx+math.cos(a)*9, cy+math.sin(a)*9, fill="#7ed5dc", width=3)
        c.create_oval(tx-3, cy-3, tx+3, cy+3, fill="#d8ecee", outline="")

    # Casco com painéis, parafusos, câmera e luzes.
    c.create_polygon(cx-39, cy-23, cx+31, cy-23, cx+43, cy-12, cx+39, cy+22, cx-39, cy+22, cx-46, cy+8,
                     fill="#d58a12", outline="#ffd066", width=2)
    c.create_rectangle(cx-26, cy-18, cx+18, cy+17, fill="#243a44", outline="#101d23", width=2)
    c.create_line(cx-21, cy-11, cx+13, cy-11, fill="#55727d", width=2)
    c.create_line(cx-21, cy+9, cx+13, cy+9, fill="#55727d", width=2)
    for bolt_x in (cx-33, cx+29):
        c.create_oval(bolt_x-2, cy-2, bolt_x+2, cy+2, fill="#e9d39f", outline="")
    c.create_oval(cx+20, cy-12, cx+43, cy+11, fill="#082632", outline="#b5e6ed", width=2)
    c.create_oval(cx+27, cy-6, cx+37, cy+4, fill="#50c9e8", outline="#d5fbff")
    c.create_oval(cx+39, cy-18, cx+47, cy-10, fill="#fff5aa", outline="#fffbd7")
    c.create_oval(cx+39, cy+12, cx+47, cy+20, fill="#fff5aa", outline="#fffbd7")
    c.create_text(cx-4, cy, text=rov.rov_id.upper(), fill="#ffca4f", font=("Consolas", 7, "bold"))

    # Bolhas saem dos thrusters; intensidade acompanha a potência.
    bubble_count = 3 + int(abs(power) / 12)
    flow_dir = -1 if power >= 0 else 1
    source_x = cx-57 if flow_dir < 0 else cx+57
    for bubble in range(bubble_count):
        phase = (now * (22 + bubble % 3) + bubble * 17) % 80
        bx = source_x + flow_dir * phase
        by = cy + math.sin(now * 3 + bubble) * 7 - (bubble % 3) * 5
        if x0+4 < bx < x1-4:
            radius = 2 + bubble % 3
            c.create_oval(bx-radius, by-radius, bx+radius, by+radius, outline="#8de6f1", width=1)

    # Cabo umbilical sobe para fora da cena.
    c.create_line(cx-8, cy-23, cx-18+math.sin(now)*5, 160, fill="#334e59", width=2, smooth=True, dash=(4, 3))


def run_gui(node, corner):
    import queue
    import tkinter as tk
    import gui_common as g

    SCENE_W, SCENE_H, FPS_MS = 400, 420, 100
    ui_q = queue.Queue()
    node.on_event = ui_q.put

    root = g.make_root(f"ROV — {node.rov_id}", corner, SCENE_W + 24, SCENE_H + 200)

    conn_lbl = tk.Label(root, text="desconectado", font=("Segoe UI", 11, "bold"),
                        bg=g.BG, fg=g.MUTE, pady=6)
    conn_lbl.pack(fill="x")

    water = tk.Canvas(root, width=SCENE_W, height=SCENE_H, bg="#021018",
                      highlightthickness=0)
    water.pack(padx=12)

    tk.Label(root, text="Registro de eventos", bg=g.BG, fg=g.ACCENT,
             font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(6, 0))
    log = g.make_log(root, height=6)
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
        # A telemetria é lida direto do estado na animação (nada a fazer aqui).

    def animate():
        if not node.running:
            return
        try:
            draw_rov_scene(water, node, SCENE_W, SCENE_H, time.time(), g)
        except tk.TclError:
            return  # janela fechada durante o redraw
        root.after(FPS_MS, animate)

    g.start_pump(root, ui_q, handle)
    node.start()
    animate()
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
