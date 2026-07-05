"""Dashboard interativo para demonstrar registro, autenticação e exclusão mútua."""
import argparse
import queue
import tkinter as tk
from tkinter import ttk

import gui_common as g
from demo_config import load_config, relay_addresses
from pilot_client import PilotNode
from protocol import PILOT_CREDENTIALS
from quiclite import PKT_ACK, PKT_DATA_REL, PKT_DATA_UNREL
from relay_server import RelayNode
from rov_simulator import RovNode

PRIMARY = ("127.0.0.1", 5000)
BACKUP = ("127.0.0.1", 5001)
FPS_MS = 100
PKT_COLOR = {PKT_DATA_REL: "#42a5f5", PKT_DATA_UNREL: "#78909c", PKT_ACK: "#66bb6a"}


class Dashboard:
    def __init__(self, root, config):
        self.root, self.config = root, config
        self.evt_q, self.tap_q = queue.Queue(), queue.Queue()
        self.packets, self.logs = [], []
        self.primary_alive = True
        self.videos, self.video_photos = {}, {}
        self.port_name = {PRIMARY[1]: "relay-primary", BACKUP[1]: "relay-backup"}
        self.primary = RelayNode("primary", PRIMARY, BACKUP)
        self.backup = RelayNode("backup", BACKUP, PRIMARY)
        self.rovs = {s["id"]: RovNode(s["id"], [PRIMARY, BACKUP], video=s.get("video", True))
                     for s in config["rovs"]}
        self.pilots = {}
        for spec in config["pilots"]:
            pid = spec["id"]
            self.pilots[pid] = PilotNode(pid, PILOT_CREDENTIALS.get(pid, "senha-invalida"),
                                         None, [PRIMARY, BACKUP])
        self.pilot_ids, self.rov_ids = list(self.pilots), list(self.rovs)
        self.active_pilot = tk.StringVar(value=self.pilot_ids[0])
        self.target_vars = {pid: tk.StringVar(value=self.rov_ids[0]) for pid in self.pilot_ids}
        self.status_vars = {}
        self.rov_buttons, self.pilot_buttons = {}, {}
        self.pos = {"relay-primary": (145, 92), "relay-backup": (375, 92)}
        self._layout_positions()

        self._start(self.primary)
        self._start(self.backup)
        for rov in self.rovs.values():
            self._start(rov, autoconnect=False)
        for pilot in self.pilots.values():
            self._start(pilot, autoconnect=False)
        self._build_ui()
        g.start_pump(root, self.evt_q, self._on_event)
        self._tick()

    def _layout_positions(self):
        for i, rid in enumerate(self.rov_ids):
            self.pos[f"rov-{rid}"] = (90 + i * 150, 300)
        for i, pid in enumerate(self.pilot_ids):
            self.pos[f"pilot-{pid}"] = (360 + (i % 2) * 130, 300 + (i // 2) * 90)

    def _start(self, node, autoconnect=True):
        source = (f"pilot:{node.pilot_id}" if isinstance(node, PilotNode)
                  else f"rov:{node.rov_id}" if isinstance(node, RovNode) else f"relay:{node.role}")
        node.on_event = lambda ev, src=source: self.evt_q.put(dict(ev, source=src))
        if isinstance(node, (PilotNode, RovNode)):
            node.start(autoconnect=autoconnect)
        else:
            node.start()
        node.endpoint.on_tap = self.tap_q.put
        if isinstance(node, RovNode):
            self.port_name[node.endpoint.local_port] = f"rov-{node.rov_id}"
        elif isinstance(node, PilotNode):
            self.port_name[node.endpoint.local_port] = f"pilot-{node.pilot_id}"

    def _build_ui(self):
        top = tk.Frame(self.root, bg=g.BG)
        top.pack(fill="x", padx=8, pady=6)
        self.topo = tk.Canvas(top, width=520, height=420, bg="#0c0f16", highlightthickness=0)
        self.topo.pack(side="left")
        self.water = tk.Canvas(top, width=640, height=420, bg="#021018", highlightthickness=0)
        self.water.pack(side="left", padx=(8, 0))

        controls = tk.Frame(self.root, bg=g.BG)
        controls.pack(fill="x", padx=8)
        rov_frame = tk.LabelFrame(controls, text="1. Autenticação e registro dos ROVs",
                                  bg=g.BG, fg=g.ACCENT, padx=6, pady=4)
        rov_frame.pack(side="left", fill="both", padx=(0, 6))
        for rid in self.rov_ids:
            row = tk.Frame(rov_frame, bg=g.BG); row.pack(fill="x", pady=2)
            tk.Label(row, text=rid, width=8, bg=g.BG, fg=g.FG, anchor="w").pack(side="left")
            btn = self._button(row, "Registrar no relay", g.ACCENT,
                               lambda r=rid: self.register_rov(r))
            btn.pack(side="left")
            status = tk.StringVar(value="não registrado")
            tk.Label(row, textvariable=status, width=17, bg=g.BG, fg=g.MUTE).pack(side="left", padx=4)
            self.rov_buttons[rid], self.status_vars[f"rov:{rid}"] = btn, status

        pilots_frame = tk.LabelFrame(controls, text="2. Pilotos: autenticar, escolher ROV e solicitar controle",
                                     bg=g.BG, fg=g.ACCENT, padx=6, pady=4)
        pilots_frame.pack(side="left", fill="both", expand=True)
        for pid in self.pilot_ids:
            row = tk.Frame(pilots_frame, bg=g.BG); row.pack(fill="x", pady=2)
            tk.Radiobutton(row, text=pid, variable=self.active_pilot, value=pid,
                           bg=g.BG, fg=g.FG, selectcolor="#202735", activebackground=g.BG).pack(side="left")
            auth = self._button(row, "Autenticar", g.ACCENT, lambda p=pid: self.connect_pilot(p))
            auth.pack(side="left", padx=2)
            combo = ttk.Combobox(row, textvariable=self.target_vars[pid], values=self.rov_ids,
                                 state="readonly", width=8)
            combo.pack(side="left", padx=2)
            request = self._button(row, "Conectar ROV", g.OKC, lambda p=pid: self.request_control(p))
            request.pack(side="left", padx=2)
            release = self._button(row, "Liberar", g.WARN, lambda p=pid: self.pilots[p].release_control())
            release.pack(side="left", padx=2)
            status = tk.StringVar(value="desconectado")
            tk.Label(row, textvariable=status, width=24, bg=g.BG, fg=g.MUTE).pack(side="left", padx=3)
            self.pilot_buttons[pid] = (auth, request, release)
            self.status_vars[f"pilot:{pid}"] = status

        actions = tk.Frame(self.root, bg=g.BG); actions.pack(fill="x", padx=8, pady=5)
        tk.Label(actions, text="Piloto selecionado controla:", bg=g.BG, fg=g.FG).pack(side="left")
        self.power = tk.Scale(actions, from_=0, to=100, orient="horizontal", length=120,
                              bg=g.BG, fg=g.FG, troughcolor="#11151c", highlightthickness=0)
        self.power.set(60); self.power.pack(side="left", padx=4)
        self._button(actions, "Frente", g.OKC, lambda: self.command("thruster_frente")).pack(side="left", padx=2)
        self._button(actions, "Ré", g.ACCENT, lambda: self.command("thruster_re")).pack(side="left", padx=2)
        self._button(actions, "Parar", g.WARN, lambda: self.command("parar")).pack(side="left", padx=2)
        self.kill_btn = self._button(actions, "Derrubar primário", g.BAD, self.toggle_primary)
        self.kill_btn.pack(side="left", padx=10)
        tk.Label(actions, text="Perda %", bg=g.BG, fg=g.FG).pack(side="left")
        self.loss = tk.Scale(actions, from_=0, to=40, orient="horizontal", length=110,
                             bg=g.BG, fg=g.FG, troughcolor="#11151c", highlightthickness=0,
                             command=self.set_loss)
        self.loss.pack(side="left")

        self.log_box = g.make_log(self.root, height=8)
        self.log_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def _button(self, parent, text, color, command):
        return tk.Button(parent, text=text, command=command, bg=color, fg="#101319",
                         relief="flat", font=("Segoe UI", 8, "bold"), padx=6, pady=4)

    def register_rov(self, rid):
        self.rovs[rid].connect()
        self.status_vars[f"rov:{rid}"].set("autenticando...")
        self.rov_buttons[rid].config(state="disabled")

    def connect_pilot(self, pid):
        self.pilots[pid].connect()
        self.status_vars[f"pilot:{pid}"].set("autenticando...")
        self.pilot_buttons[pid][0].config(state="disabled")

    def request_control(self, pid):
        self.pilots[pid].request_control(self.target_vars[pid].get())

    def command(self, action):
        pilot = self.pilots[self.active_pilot.get()]
        pilot.send_command(action, 0 if action == "parar" else int(self.power.get()))

    def toggle_primary(self):
        if self.primary_alive:
            self.primary.stop(); self.primary_alive = False
            self.kill_btn.config(text="Reviver primário", bg=g.OKC)
        else:
            # O backup promove a si mesmo com um termo maior quando o primário
            # cai. Apenas recriar o primário faria com que ele voltasse como
            # follower ao receber esse termo. Para o botão executar um failback
            # de fato, reiniciamos o par de forma ordenada: primeiro encerramos
            # o líder atual, depois subimos um novo primário e um novo backup.
            next_term = max(self.primary.term, self.backup.term) + 1
            self.backup.stop()
            self.primary = RelayNode("primary", PRIMARY, BACKUP)
            self.primary.term = next_term
            self._start(self.primary)
            self.backup = RelayNode("backup", BACKUP, PRIMARY)
            self.backup.term = next_term
            self._start(self.backup)
            self.primary_alive = True
            self.set_loss()
            self.kill_btn.config(text="Derrubar primário", bg=g.BAD)

    def set_loss(self, _=None):
        value = self.loss.get() / 100.0
        for relay in (self.primary, self.backup):
            if relay.endpoint:
                relay.endpoint.loss = value

    def _on_event(self, ev):
        src, kind = ev.get("source", "?"), ev.get("kind")
        if kind == "log":
            text = f"[{src}] {ev['text']}"
            self.logs.append(text); self.logs = self.logs[-250:]
            g.log_append(self.log_box, text)
        if kind == "video":
            rid = ev["rov"]
            self.videos[rid] = ev
            try:
                self.video_photos[rid] = tk.PhotoImage(data=ev["ppm"], format="PPM")
            except tk.TclError as exc:
                self.video_photos.pop(rid, None)
                text = f"[dashboard] erro ao renderizar câmera de {rid}: {exc}"
                self.logs.append(text)
                self.logs = self.logs[-250:]
                g.log_append(self.log_box, text)

    def _tick(self):
        self._drain_taps(); self._refresh_status(); self._draw_topology(); self._draw_rovs()
        self.root.after(FPS_MS, self._tick)

    def _refresh_status(self):
        for rid, rov in self.rovs.items():
            if rov.registered:
                self.status_vars[f"rov:{rid}"].set("autenticado / online")
            elif rov._connect_started:
                self.status_vars[f"rov:{rid}"].set("autenticando...")
        for pid, p in self.pilots.items():
            if p.controlling:
                text = f"controla {p.controlling}"
            elif p.authed:
                text = "autenticado; escolha o ROV"
            elif p._connect_started:
                text = "autenticando..."
            else:
                text = "desconectado"
            self.status_vars[f"pilot:{pid}"].set(text)
            auth, request, release = self.pilot_buttons[pid]
            request.config(state="normal" if p.authed and not p.controlling else "disabled")
            release.config(state="normal" if p.controlling else "disabled")

    def _drain_taps(self):
        try:
            while True:
                tap = self.tap_q.get_nowait()
                dst = self.port_name.get(tap["dst_port"])
                if tap["src"] in self.pos and dst in self.pos:
                    self.packets.append({"src": tap["src"], "dst": dst, "life": 8,
                                         "color": "#ef5350" if tap["dropped"] else PKT_COLOR.get(tap["ptype"], "white")})
        except queue.Empty:
            pass
        self.packets = [{**p, "life": p["life"] - 1} for p in self.packets[-80:] if p["life"] > 1]

    def _draw_topology(self):
        c = self.topo; c.delete("all")
        c.create_text(260, 18, text="TOPOLOGIA DA REDE", fill=g.ACCENT, font=("Segoe UI", 11, "bold"))
        clients = [(rov, f"rov-{rid}") for rid, rov in self.rovs.items()]
        clients += [(p, f"pilot-{pid}") for pid, p in self.pilots.items()]
        for _, name in clients:
            for relay in ("relay-primary", "relay-backup"):
                c.create_line(*self.pos[name], *self.pos[relay], fill="#1e2836", width=2)
        c.create_line(*self.pos["relay-primary"], *self.pos["relay-backup"], fill="#263547", dash=(4, 3))
        for node, name in clients:
            connected = node.registered if isinstance(node, RovNode) else node.authed
            if connected:
                relay = "relay-primary" if node.current == PRIMARY else "relay-backup"
                c.create_line(*self.pos[name], *self.pos[relay], fill="#375f78", width=4)
        for packet in self.packets:
            a, b = self.pos[packet["src"]], self.pos[packet["dst"]]
            t = 1 - packet["life"] / 8
            x, y = a[0] + (b[0]-a[0])*t, a[1] + (b[1]-a[1])*t
            c.create_oval(x-4, y-4, x+4, y+4, fill=packet["color"], outline="")
        self._node(c, "relay-primary", "RELAY P", "ativo" if self.primary_alive and self.primary.active else "offline/follower",
                   g.OKC if self.primary_alive and self.primary.active else g.MUTE)
        self._node(c, "relay-backup", "RELAY B", "ativo" if self.backup.active else "em espera",
                   g.WARN if self.backup.active else g.MUTE)
        for rid, rov in self.rovs.items():
            state = "online" if rov.registered else "não registrado"
            self._node(c, f"rov-{rid}", f"ROV {rid}", state, g.OKC if rov.registered else g.MUTE)
        for pid, p in self.pilots.items():
            state = f"controla {p.controlling}" if p.controlling else "autenticado" if p.authed else "desconectado"
            self._node(c, f"pilot-{pid}", pid, state, g.OKC if p.controlling else g.ACCENT if p.authed else g.MUTE)

    def _node(self, canvas, name, title, status, color):
        x, y = self.pos[name]
        canvas.create_rectangle(x-58, y-25, x+58, y+25, fill="#161d29", outline=color, width=2)
        canvas.create_text(x, y-7, text=title, fill=g.FG, font=("Segoe UI", 9, "bold"))
        canvas.create_text(x, y+10, text=status, fill=color, font=("Segoe UI", 8))

    def _draw_rovs(self):
        c = self.water; c.delete("all")
        count = max(1, len(self.rov_ids)); width = 640 / count
        for i, rid in enumerate(self.rov_ids):
            rov, x0, x1 = self.rovs[rid], i*width, (i+1)*width
            c.create_rectangle(x0, 0, x1, 420, fill="#052538", outline="#1c6685")
            snap = rov.state.snapshot()
            c.create_text((x0+x1)/2, 20, text=f"ROV {rid}", fill="#7fd7ff", font=("Segoe UI", 11, "bold"))
            state = "ONLINE / REGISTRADO" if rov.registered else "AGUARDANDO REGISTRO"
            c.create_text((x0+x1)/2, 42, text=state, fill=g.OKC if rov.registered else g.MUTE, font=("Segoe UI", 8, "bold"))
            cx, cy = (x0+x1)/2, 200 + min(snap["depth"], 20)*7
            c.create_rectangle(cx-38, cy-14, cx+38, cy+14, fill="#ffb300", outline="#5b3d00", width=2)
            c.create_oval(cx+28, cy-8, cx+46, cy+8, fill="#fff59d", outline="#5b3d00")
            c.create_text(x0+12, 80, anchor="nw", fill=g.FG, font=("Consolas", 9),
                          text=f"bateria {snap['battery']:5.1f}%\nprof.   {snap['depth']:5.2f} m\ntemp.   {snap['temperature']:5.1f} C\nthr.    {snap['thruster_power']:+4d}")
            photo, video = self.video_photos.get(rid), self.videos.get(rid)
            if photo and video:
                c.create_image(x1-12, 78, image=photo, anchor="ne")
                c.create_text(x1-12, 155, anchor="ne", fill="#bfeaff", font=("Consolas", 8),
                              text=f"câmera {video['latency_ms']:.1f} ms | perdas {video['dropped']}")
            else:
                c.create_rectangle(x1-112, 78, x1-12, 153, outline="#416172")
                c.create_text(x1-62, 115, text="SEM VÍDEO\n(associe um piloto)", fill=g.MUTE, font=("Segoe UI", 8), justify="center")

    def stop_all(self):
        for node in [self.primary, self.backup, *self.rovs.values(), *self.pilots.values()]:
            try: node.stop()
            except Exception: pass


def main():
    global PRIMARY, BACKUP
    parser = argparse.ArgumentParser(description="Dashboard de controle distribuído de ROVs")
    parser.add_argument("--config", default="demo_config.json")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    PRIMARY, BACKUP = relay_addresses(config)[:2]
    root = g.make_root("ROV distribuído — Dashboard", "c", 1180, 850)
    dash = Dashboard(root, config)
    root.protocol("WM_DELETE_WINDOW", lambda: (dash.stop_all(), root.destroy()))
    if args.selftest:
        first_rov = dash.rov_ids[0]
        root.after(500, lambda: [dash.register_rov(r) for r in dash.rov_ids])
        root.after(1800, lambda: [dash.connect_pilot(p) for p in dash.pilot_ids])
        root.after(3200, lambda: [dash.target_vars[p].set(first_rov) for p in dash.pilot_ids])
        root.after(3400, lambda: [dash.request_control(p) for p in dash.pilot_ids])
        root.after(6500, lambda: (print("SELFTEST:", {p: dash.pilots[p].controlling for p in dash.pilot_ids}), dash.stop_all(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()