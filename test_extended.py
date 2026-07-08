"""Testes de segurança, multi-ROV, vídeo e recuperação de liderança."""
import time

from demo_config import validate_config
from pilot_client import PilotNode
from relay_server import RelayNode
from rov_simulator import RovNode
from video_stream import FrameAssembler, fragment_frame, generate_ppm

PRIMARY = ("127.0.0.1", 5200)
BACKUP = ("127.0.0.1", 5201)


def wait_until(predicate, timeout=12.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def check(label, condition):
    print(f"  [{'PASS' if condition else 'FALHOU'}] {label}")
    if not condition:
        raise AssertionError(label)


def test_video_codec():
    ppm = generate_ppm(7, 24, 18)
    chunks = list(fragment_frame("rov1", 7, ppm))
    assembler = FrameAssembler()
    frame = None
    for chunk in reversed(chunks):
        frame = assembler.add(chunk) or frame
    check("vídeo reagrupa chunks fora de ordem", frame is not None and frame["ppm"] == ppm)


def test_config_validation():
    invalid = {
        "relays": [{"port": 1}, {"port": 1}],
        "rovs": [{"id": "rov1"}],
        "pilots": [],
        "network": {"loss": 0},
    }
    try:
        validate_config(invalid)
    except ValueError:
        check("configuração rejeita portas duplicadas", True)
    else:
        check("configuração rejeita portas duplicadas", False)


def main():
    test_video_codec()
    test_config_validation()
    nodes = []
    primary = RelayNode("primary", PRIMARY, BACKUP)
    backup = RelayNode("backup", BACKUP, PRIMARY)
    nodes += [primary, backup]
    primary.start()
    backup.start()

    video_events = []
    rov1 = RovNode("rov1", [PRIMARY, BACKUP], video=True)
    rov2 = RovNode("rov2", [PRIMARY, BACKUP], video=False)
    bad_rov = RovNode("rov3", [PRIMARY, BACKUP], secret="segredo-errado", video=False)
    pilot_a = PilotNode("pilotoA", None, "rov1",
                        [PRIMARY, BACKUP], on_event=lambda e: video_events.append(e))
    pilot_b = PilotNode("pilotoB", None, "rov2",
                        [PRIMARY, BACKUP])
    nodes += [rov1, rov2, bad_rov, pilot_a, pilot_b]
    for node in (rov1, rov2, bad_rov, pilot_a, pilot_b):
        node.start()

    try:
        check("dois ROVs autenticam", wait_until(
            lambda: rov1.registered and rov2.registered))
        check("ROV com segredo errado é recusado", wait_until(
            lambda: not bad_rov.registered and "rov3" not in primary.rovs, timeout=3))
        check("pilotos controlam ROVs independentes", wait_until(
            lambda: pilot_a.controlling == "rov1" and pilot_b.controlling == "rov2"))
        check("stream de vídeo chega ao piloto", wait_until(
            lambda: any(e.get("kind") == "video" for e in video_events), timeout=6))

        depth = rov1.state.snapshot()["depth"]
        pilot_a.endpoint.send_reliable(
            PRIMARY, {"type": "command", "action": "thruster_frente",
                      "value": 100, "command_seq": 999})
        time.sleep(0.8)
        check("comando sem token é rejeitado",
              rov1.state.snapshot()["depth"] == depth)
        pilot_a.send_command("thruster_frente", 60)
        check("comando autenticado funciona", wait_until(
            lambda: rov1.state.snapshot()["depth"] > depth, timeout=2))

        follower_client = RovNode("rov3", [BACKUP, PRIMARY], video=False)
        nodes.append(follower_client)
        follower_client.start()
        check("follower redireciona cliente ao líder", wait_until(
            lambda: follower_client.current == PRIMARY and follower_client.registered))

        primary.stop()
        check("backup assume em termo superior", wait_until(
            lambda: backup.active and backup.term >= 2, timeout=5))
        # Espera o ROV concluir o re-registro no backup E adotar o novo termo:
        # só então faz sentido testar a rejeição de um comando de termo OBSOLETO
        # (antes disso o ROV ainda nem sabe qual é o termo atual).
        check("clientes migram ao novo líder", wait_until(
            lambda: pilot_a.current == BACKUP and rov1.current == BACKUP
                    and rov1.registered and rov1.highest_term >= backup.term, timeout=9))

        depth = rov1.state.snapshot()["depth"]
        target = backup.rovs["rov1"]["addr"]
        backup.endpoint.send_reliable(
            target, {"type": "command", "from": "stale", "action": "thruster_frente",
                     "value": 100, "term": backup.term - 1,
                     "lease_id": "stale", "command_seq": 500})
        time.sleep(0.8)
        check("ROV rejeita comando de termo obsoleto",
              rov1.state.snapshot()["depth"] == depth)

        recovered = RelayNode("primary", PRIMARY, BACKUP)
        nodes.append(recovered)
        recovered.start()
        check("primário recuperado não cria split-brain", wait_until(
            lambda: not (recovered.active and backup.active), timeout=4))
    finally:
        for node in reversed(nodes):
            try:
                node.stop()
            except Exception:
                pass

    print("\nRESULTADO ESTENDIDO: todos os cenários passaram")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
