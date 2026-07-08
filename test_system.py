"""
test_system.py
--------------
Teste de integração HEADLESS (sem interface gráfica): sobe dois relays, um
ROV e dois pilotos no mesmo processo e verifica, com asserções, cada conceito
de Sistemas Distribuídos que o projeto demonstra:

  1. Autenticação (segredo compartilhado via HMAC + Diffie-Hellman efêmero) — segredo certo entra, segredo errado não.
  2. Controle de concorrência (exclusão mútua) — só um piloto por ROV.
  3. Roteamento de comando (canal confiável) — o ROV reage ao comando.
  4. Replicação — o backup espelha o estado do primário.
  5. Failover — mata-se o primário e o backup assume; ROV e piloto migram
     sozinhos e o controle é preservado ao dono anterior.

Rode com:  python test_system.py
"""

import time

from relay_server import RelayNode
from rov_simulator import RovNode
from pilot_client import PilotNode

PRIMARY = ("127.0.0.1", 5100)
BACKUP = ("127.0.0.1", 5101)

ok_count = 0
fail_count = 0


def check(label, cond):
    global ok_count, fail_count
    mark = "PASS" if cond else "FALHOU"
    if cond:
        ok_count += 1
    else:
        fail_count += 1
    print(f"  [{mark}] {label}")


def main():
    print("== Subindo os dois relays (primário + backup) ==")
    primary = RelayNode("primary", PRIMARY, BACKUP)
    backup = RelayNode("backup", BACKUP, PRIMARY)
    primary.start()
    backup.start()
    time.sleep(1.5)

    print("== Subindo ROV e piloto A (segredo de rede correto) ==")
    rov = RovNode("rov1", [PRIMARY, BACKUP])
    rov.start()
    pilotA = PilotNode("pilotoA", None, "rov1", [PRIMARY, BACKUP])
    pilotA.start()
    time.sleep(2.5)

    print("\n-- 1) Autenticação e concessão de controle --")
    check("piloto A autenticou", pilotA.authed)
    check("piloto A recebeu controle de rov1", pilotA.controlling == "rov1")

    print("\n-- 2) Comando confiável chega ao ROV --")
    depth_before = rov.state.snapshot()["depth"]
    pilotA.send_command("thruster_frente", 80)
    time.sleep(1.5)
    depth_after = rov.state.snapshot()["depth"]
    check(f"profundidade aumentou após comando ({depth_before} -> {depth_after})",
          depth_after > depth_before)

    print("\n-- 3) Autenticação com SEGREDO ERRADO é recusada --")
    pilotBad = PilotNode("pilotoB", "segredo-errado", "rov1", [PRIMARY, BACKUP])
    pilotBad.start()
    time.sleep(2.5)
    check("piloto com segredo errado NÃO autenticou", not pilotBad.authed)
    pilotBad.stop()
    time.sleep(0.5)

    print("\n-- 4) Concorrência: piloto B (segredo correto) tenta o mesmo ROV --")
    pilotB = PilotNode("pilotoB", None, "rov1", [PRIMARY, BACKUP])
    pilotB.start()
    time.sleep(2.5)
    check("piloto B autenticou", pilotB.authed)
    check("piloto B foi NEGADO (rov1 já é do piloto A)", pilotB.controlling is None)

    print("\n-- 5) Replicação: backup espelha o estado do primário --")
    check("backup replicou rov1", "rov1" in backup.mirror_rovs)
    check("backup replicou dono do controle (rov1 <- pilotoA)",
          backup.mirror_control.get("rov1") == "pilotoA")

    print("\n-- 6) FAILOVER: matando o primário… --")
    primary.stop()
    print("   (aguardando backup assumir e clientes migrarem ~11s)")
    time.sleep(11.0)

    check("backup assumiu como ATIVO", backup.active)
    check("ROV migrou para o backup", rov.current == BACKUP)
    check("piloto A migrou para o backup", pilotA.current == BACKUP)
    check("piloto A continua autenticado no backup", pilotA.authed)
    check("controle de rov1 preservado para o piloto A (reserva via replicação)",
          pilotA.controlling == "rov1")
    check("piloto B continua SEM controle após failover", pilotB.controlling is None)

    print("\n-- 7) Comando ainda funciona após o failover --")
    depth_before = rov.state.snapshot()["depth"]
    pilotA.send_command("thruster_frente", 90)
    time.sleep(1.5)
    depth_after = rov.state.snapshot()["depth"]
    check(f"profundidade aumentou no backup ({depth_before} -> {depth_after})",
          depth_after > depth_before)

    for n in (backup, rov, pilotA, pilotB):
        n.stop()

    print(f"\n== RESULTADO: {ok_count} passaram, {fail_count} falharam ==")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
