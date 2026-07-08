"""
run_demo.py
-----------
Sobe TODOS os hosts de uma vez, cada um em sua própria janela, posicionadas
nos quatro cantos da tela -- ideal para apresentar o trabalho em um PC só, sem
precisar abrir vários terminais nem digitar IPs.

  ┌────────────────────┬────────────────────┐
  │ RELAY primário (tl)│ RELAY backup  (tr) │
  ├────────────────────┼────────────────────┤
  │ ROV rov1      (bl) │ PILOTO pilotoA (br)│
  └────────────────────┴────────────────────┘

Uso:
    python run_demo.py                 # 2 relays + 1 ROV + 1 piloto
    python run_demo.py --two-pilots    # adiciona um 2º piloto (concorrência)
    python run_demo.py --loss 0.2      # 20% de perda de pacotes nos relays
                                       # (mostra a retransmissão do canal
                                       #  confiável funcionando ao vivo)

Como demonstrar o FAILOVER:
    Depois que tudo estiver rodando, FECHE a janela do RELAY primário
    (ou mate o processo). Em poucos segundos o backup vira ATIVO e o ROV e o
    piloto migram sozinhos para ele -- a telemetria volta a fluir.

Para encerrar tudo: volte a este terminal e tecle Enter (ou Ctrl+C).
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

from demo_config import load_config, relay_addresses

PRIMARY_PORT = 5000
BACKUP_PORT = 5001
RELAYS = f"127.0.0.1:{PRIMARY_PORT},127.0.0.1:{BACKUP_PORT}"
BASE_DIR = Path(__file__).resolve().parent


def spawn(args):
    """Abre um novo processo Python rodando um dos hosts."""
    script = str(BASE_DIR / args[0])
    return subprocess.Popen([sys.executable, script] + args[1:], cwd=str(BASE_DIR))


def main():
    ap = argparse.ArgumentParser(description="Sobe a demonstração completa")
    ap.add_argument("--loss", type=float, default=0.0,
                    help="fração de perda de pacotes nos relays (0..1)")
    ap.add_argument("--two-pilots", action="store_true",
                    help="também abre um segundo piloto (demonstra concorrência)")
    ap.add_argument("--config", help="arquivo JSON com relays, ROVs e pilotos")
    ap.add_argument("--secret", default=None,
                    help="segredo de rede compartilhado (repassado a todos os nós)")
    ap.add_argument("--scenario", choices=["manual", "failover"], default="manual")
    args = ap.parse_args()

    secret = ["--secret", args.secret] if args.secret else []
    config = load_config(args.config)
    configured_loss = float(config.get("network", {}).get("loss", 0.0))
    loss_value = args.loss if args.loss else configured_loss
    if not 0 <= loss_value <= 1:
        ap.error("--loss deve ficar entre 0 e 1")
    loss = ["--loss", str(loss_value)] if loss_value else []
    procs = []
    relay_addrs = relay_addresses(config)
    relay_text = ",".join(f"{host}:{port}" for host, port in relay_addrs)
    corners = ["bl", "br", "c"]

    print("Subindo RELAY primário (canto superior esquerdo)…")
    procs.append(spawn(["relay_server.py", "--role", "primary",
                        "--host", relay_addrs[0][0], "--port", str(relay_addrs[0][1]),
                        "--peer", f"{relay_addrs[1][0]}:{relay_addrs[1][1]}",
                        "--corner", "tl"] + loss + secret))
    time.sleep(0.6)

    print("Subindo RELAY backup (canto superior direito)…")
    procs.append(spawn(["relay_server.py", "--role", "backup",
                        "--host", relay_addrs[1][0], "--port", str(relay_addrs[1][1]),
                        "--peer", f"{relay_addrs[0][0]}:{relay_addrs[0][1]}",
                        "--corner", "tr"] + loss + secret))
    time.sleep(0.6)

    for index, rov in enumerate(config.get("rovs", [])):
        print(f"Subindo ROV {rov['id']}…")
        procs.append(spawn(["rov_simulator.py", "--id", rov["id"],
                            "--relays", relay_text,
                            "--corner", corners[index % len(corners)]] + secret))
        time.sleep(0.6)

    pilots = list(config.get("pilots", []))
    if args.two_pilots and len(pilots) == 1:
        pilots.append({"id": "pilotoB", "target": pilots[0]["target"]})
    for index, pilot in enumerate(pilots):
        print(f"Subindo PILOTO {pilot['id']} -> {pilot['target']}…")
        procs.append(spawn(["pilot_client.py", "--id", pilot["id"],
                            "--target", pilot["target"], "--relays", relay_text,
                            "--corner", corners[(index + 1) % len(corners)]] + secret))
        time.sleep(0.4)

    if args.scenario == "failover":
        print("Cenário failover: primário será encerrado em 8 segundos.")
        time.sleep(8)
        procs[0].terminate()

    print("\nTudo no ar! Dica de demonstração:")
    print("  • Feche a janela do RELAY primário para ver o FAILOVER.")
    print("  • Use os botões do piloto (Frente/Ré/Parar) e veja a telemetria.")
    print("\nTecle Enter (ou Ctrl+C) aqui para encerrar tudo.")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
            except OSError:
                pass
        print("Encerrado.")


if __name__ == "__main__":
    main()
