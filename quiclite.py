"""
quiclite.py
-----------
Uma camada de transporte "inspirada no QUIC", construída em cima de UDP.

POR QUE ISSO EXISTE (a ideia de Sistemas Distribuídos por trás):
O QUIC roda sobre UDP e implementa, na aplicação, as garantias que
tradicionalmente vinham do TCP. A grande sacada dele é oferecer VÁRIOS
"canais" independentes sobre a mesma conexão, de modo que a perda de um
pacote em um canal não trava os outros (o famoso problema de
"head-of-line blocking" do TCP).

Aqui reproduzimos, de forma simplificada e didática, duas ideias centrais:

  1. CANAL CONFIÁVEL E ORDENADO (send_reliable):
     Para mensagens que NÃO PODEM se perder e precisam chegar em ordem
     (ex.: comandos do piloto, registro, autenticação). Implementamos por
     conta própria número de sequência + ACK + retransmissão + reordenação.
     É, na prática, uma reimplementação didática do que o TCP faz.

  2. CANAL NÃO-CONFIÁVEL (send_unreliable):
     Para mensagens periódicas em que só interessa o dado MAIS RECENTE
     (ex.: telemetria). Se um pacote se perde, tudo bem: o próximo já traz
     um estado mais novo. Não há ACK nem retransmissão — é "dispare e
     esqueça", como um datagrama puro.

Como comandos (confiável) e telemetria (não-confiável) trafegam por
mecanismos independentes, um pacote de telemetria perdido NÃO atrasa a
entrega de um comando. Esse é exatamente o argumento a favor do QUIC.

Também dá para LIGAR uma simulação de perda de pacotes (loss=0.2 => 20%
dos pacotes enviados são descartados de propósito), para mostrar ao vivo
a retransmissão do canal confiável funcionando.

FORMATO DO PACOTE (cabeçalho binário de 5 bytes + payload JSON):
    byte 0      -> tipo do pacote (0=DADO_CONF, 1=DADO_NAOCONF, 2=ACK)
    bytes 1..4  -> número de sequência (uint32, big-endian)
    bytes 5..   -> payload (JSON em UTF-8); vazio quando é ACK
"""

import json
import random
import socket
import struct
import threading
import time

# --- Tipos de pacote -------------------------------------------------------
PKT_DATA_REL = 0    # dado no canal CONFIÁVEL (precisa de ACK)
PKT_DATA_UNREL = 1  # dado no canal NÃO-CONFIÁVEL (dispare e esqueça)
PKT_ACK = 2         # confirmação de recebimento de um pacote confiável

# Cabeçalho: 1 byte de tipo + 4 bytes de sequência (big-endian).
HEADER = struct.Struct("!BI")

# Parâmetros de retransmissão (em segundos).
RTO = 0.4              # "Retransmission TimeOut": espera antes de reenviar
RETRANSMIT_TICK = 0.15  # de quanto em quanto tempo o verificador roda

ENCODING = "utf-8"


class Peer:
    """
    Estado da conversa com UM endpoint remoto (identificado pelo endereço
    UDP (ip, porta)). Como UDP não tem "conexão", nós mantemos manualmente,
    por endereço, os números de sequência e os buffers.
    """

    def __init__(self, addr):
        self.addr = addr
        # --- lado de ENVIO (canal confiável) ---
        self.send_seq = 0            # próximo número de sequência a usar
        self.unacked = {}            # seq -> [pacote_bytes, instante_do_ultimo_envio]
        # --- lado de RECEPÇÃO (canal confiável) ---
        self.recv_expected = 0       # próximo seq que esperamos entregar
        self.recv_buffer = {}        # seq -> msg (chegou fora de ordem, guardado)
        # --- liveness ---
        self.last_recv = time.time()  # último instante em que ouvimos algo dele
        self.lock = threading.Lock()


class Endpoint:
    """
    Dono de UM socket UDP. Consegue falar com vários peers ao mesmo tempo
    (o relay fala com vários clientes; um cliente fala com 1 ou 2 relays).

    on_message(addr, msg, reliable) é chamado (em uma thread de rede) para
    cada mensagem JÁ ENTREGUE (ordenada, no caso confiável). 'reliable' diz
    por qual canal ela veio.
    """

    def __init__(self, sock, on_message, loss=0.0, name="", on_tap=None):
        self.sock = sock
        self.on_message = on_message
        self.loss = loss          # probabilidade de descartar cada pacote enviado
        self.name = name
        # "Grampo" opcional para visualização: chamado a cada pacote enviado,
        # inclusive quando ele é descartado pela simulação de perda. Permite ao
        # painel (demo_dashboard) animar os pacotes reais na tela.
        self.on_tap = on_tap
        self.local_port = sock.getsockname()[1]
        # Destinos de infraestrutura que não devem sofrer a perda artificial.
        self.loss_exempt_addrs = set()
        self.peers = {}           # addr -> Peer
        self.lock = threading.Lock()
        self.running = True
        threading.Thread(target=self._recv_loop, daemon=True).start()
        threading.Thread(target=self._retransmit_loop, daemon=True).start()

    # -- gestão de peers ----------------------------------------------------
    def _peer(self, addr):
        with self.lock:
            peer = self.peers.get(addr)
            if peer is None:
                peer = Peer(addr)
                self.peers[addr] = peer
            return peer

    def remove_peer(self, addr):
        """Esquece um peer (ex.: relay que caiu). Para de retransmitir p/ ele."""
        with self.lock:
            self.peers.pop(addr, None)

    def last_seen(self, addr):
        """Há quanto tempo (s) ouvimos algo desse peer; inf se desconhecido."""
        with self.lock:
            peer = self.peers.get(addr)
        if peer is None:
            return float("inf")
        return time.time() - peer.last_recv

    # -- envio --------------------------------------------------------------
    def send_reliable(self, addr, msg):
        """Envia pelo canal CONFIÁVEL: numera, guarda p/ retransmitir e dispara."""
        peer = self._peer(addr)
        payload = json.dumps(msg, ensure_ascii=False).encode(ENCODING)
        with peer.lock:
            seq = peer.send_seq
            peer.send_seq += 1
            pkt = HEADER.pack(PKT_DATA_REL, seq) + payload
            peer.unacked[seq] = [pkt, time.time()]
        self._raw_send(pkt, addr)

    def send_unreliable(self, addr, msg):
        """Envia pelo canal NÃO-CONFIÁVEL: um tiro só, sem ACK, sem reenvio."""
        payload = json.dumps(msg, ensure_ascii=False).encode(ENCODING)
        pkt = HEADER.pack(PKT_DATA_UNREL, 0) + payload
        self._raw_send(pkt, addr)

    def _send_ack(self, addr, seq):
        # ACKs também estão sujeitos à perda simulada -- realista: um ACK
        # perdido faz o remetente retransmitir, e nós re-confirmamos.
        self._raw_send(HEADER.pack(PKT_ACK, seq), addr)

    def _raw_send(self, pkt, addr):
        # Aqui é onde a "perda de pacotes" é simulada: com probabilidade
        # self.loss, simplesmente NÃO enviamos o pacote.
        dropped = bool(addr not in self.loss_exempt_addrs
                       and self.loss and random.random() < self.loss)
        if self.on_tap:
            # Reporta o pacote (tipo no 1º byte do cabeçalho) para a visualização.
            self.on_tap({"src": self.name, "dst_port": addr[1],
                         "ptype": pkt[0], "dropped": dropped})
        if dropped:
            return
        try:
            self.sock.sendto(pkt, addr)
        except OSError:
            pass

    # -- recepção -----------------------------------------------------------
    def _recv_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                # No Windows, enviar a uma porta fechada pode fazer o recvfrom
                # seguinte lançar WSAECONNRESET (ICMP "port unreachable"). Isso
                # NÃO é a nossa conexão caindo -- é justamente um relay que
                # morreu. Ignoramos e seguimos, para não matar a recepção (o
                # que quebraria o failover). Só encerramos se fomos fechados.
                if not self.running:
                    break
                continue
            if len(data) < HEADER.size:
                continue
            ptype, seq = HEADER.unpack(data[:HEADER.size])
            payload = data[HEADER.size:]

            peer = self._peer(addr)
            peer.last_recv = time.time()

            if ptype == PKT_ACK:
                # O outro lado confirmou o recebimento do pacote 'seq'.
                with peer.lock:
                    peer.unacked.pop(seq, None)

            elif ptype == PKT_DATA_UNREL:
                # Canal não-confiável: entrega direto, sem ordenar nem ACK.
                msg = self._decode(payload)
                if msg is not None:
                    self.on_message(addr, msg, False)

            elif ptype == PKT_DATA_REL:
                # Canal confiável: SEMPRE confirmamos (mesmo duplicatas), e
                # entregamos em ordem, guardando o que chegar adiantado.
                self._send_ack(addr, seq)
                to_deliver = []
                with peer.lock:
                    if seq == peer.recv_expected:
                        msg = self._decode(payload)
                        if msg is not None:
                            to_deliver.append(msg)
                        peer.recv_expected += 1
                        # "drena" pacotes que já tinham chegado fora de ordem
                        while peer.recv_expected in peer.recv_buffer:
                            to_deliver.append(peer.recv_buffer.pop(peer.recv_expected))
                            peer.recv_expected += 1
                    elif seq > peer.recv_expected:
                        # chegou adiantado: guarda para entregar depois, em ordem
                        msg = self._decode(payload)
                        if msg is not None:
                            peer.recv_buffer[seq] = msg
                    # seq < recv_expected: é duplicata de algo já entregue;
                    # não faz nada além do ACK que já mandamos acima.
                for msg in to_deliver:
                    self.on_message(addr, msg, True)

    @staticmethod
    def _decode(payload):
        try:
            return json.loads(payload.decode(ENCODING))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None  # pacote corrompido: ignora (robustez simples)

    # -- retransmissão ------------------------------------------------------
    def _retransmit_loop(self):
        """
        Periodicamente reenvia pacotes confiáveis que ainda não foram
        confirmados dentro do prazo RTO. É isso que garante a entrega mesmo
        com perda de pacotes.
        """
        while self.running:
            time.sleep(RETRANSMIT_TICK)
            now = time.time()
            with self.lock:
                peers = list(self.peers.values())
            for peer in peers:
                resend = []
                with peer.lock:
                    for seq, entry in peer.unacked.items():
                        pkt, last = entry
                        if now - last > RTO:
                            entry[1] = now
                            resend.append(pkt)
                for pkt in resend:
                    self._raw_send(pkt, peer.addr)

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


def make_udp_socket(bind_addr=None):
    """Cria um socket UDP. Se bind_addr for dado, faz bind (uso do servidor)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Observação (Windows): mandar para uma porta fechada (um relay morto) pode
    # fazer o recvfrom seguinte lançar WSAECONNRESET. O ideal seria desligar
    # isso com o ioctl SIO_UDP_CONNRESET, mas o socket.ioctl do Python não
    # aceita esse código. Em vez disso, o _recv_loop trata esse OSError como
    # transitório e continua (ver quiclite._recv_loop), o que é suficiente.
    if bind_addr is not None:
        sock.bind(bind_addr)
    return sock
