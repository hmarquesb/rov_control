# Sistema de Controle de ROV Distribuído

Trabalho final de **Sistemas Distribuídos**: controle remoto de um ROV
(veículo submarino, aqui simulado) por um piloto, passando por um servidor
**Relay**. O sistema demonstra, em código, os principais temas da disciplina:
travessia de NAT, exclusão mútua, detecção de falhas, **um protocolo de
transporte próprio (inspirado no QUIC)**, **autenticação por segredo
compartilhado** e **replicação com failover** do servidor.

Requer apenas **Python 3** (a interface usa Tkinter, que já vem no Python).
Nenhuma biblioteca externa, nenhuma internet — roda inteiro em um PC só.

---

## Arquitetura

O sistema tem cinco nós lógicos — dois relays, o ROV e os pilotos:

```
  ┌─────────────────────────┬─────────────────────────┐
  │  RELAY PRIMÁRIO          │  RELAY BACKUP           │
  │  (porta 5000)            │  (porta 5001)           │
  │      ▲   │  replicação →  │   (espelha o primário)  │
  └──────│───│───────────────┴─────────────────────────┘
         │   │ comandos (confiável) / telemetria (não-confiável)
  ┌──────│───▼───────────────┬─────────────────────────┐
  │  ROV rov1                │  PILOTO pilotoA         │
  │  (sensores + thrusters)  │  (autentica + comanda)  │
  └─────────────────────────┴─────────────────────────┘
```

Todos os nós **saem** em direção ao relay (resolve NAT/firewall) usando a camada
de transporte `quiclite` sobre **UDP**.

Há **dois modos de execução** dos mesmos nós, e em ambos a comunicação é por
**UDP real** (a rede é idêntica; muda só o empacotamento):

- **Multi-janela** (`run_demo.py` ou execução manual): cada nó é um **processo
  independente** com sua própria janela — reforça o argumento "são hosts
  separados". É o modelo ilustrado no diagrama acima.
- **Painel único** (`demo_dashboard.py`): os mesmos nós rodam como **threads no
  mesmo processo**, ainda conversando por sockets UDP no loopback — apenas
  co-localizados para visualizar tudo (topologia + ROV) em uma tela só.

### Arquivos

| Arquivo | Papel |
|---|---|
| `quiclite.py` | **Transporte inspirado no QUIC**: sobre UDP, com um canal confiável e ordenado (seq/ACK/retransmissão) e um canal não-confiável, + simulação de perda de pacotes. |
| `protocol.py`, `dh_exchange.py`, `identity_keys.py` | Nonces, DH efêmero, HKDF e autenticação mútua por **segredo compartilhado (HMAC-SHA256)**. |
| `relay_server.py` | Relay (primário/backup): registro, exclusão mútua, heartbeat, auth, **replicação e failover**. Lógica (`RelayNode`) separada da GUI. |
| `rov_simulator.py` | ROV simulado: telemetria, aplica comandos, **failover** automático. |
| `pilot_client.py` | Piloto: autentica, pede controle, envia comandos, recebe telemetria, **failover**. |
| `gui_common.py` | Utilidades de interface Tkinter (posiciona janelas, ponte thread→UI). |
| `demo_dashboard.py` | **Painel showpiece**: uma janela só com a topologia da rede (pacotes animados + failover visual) e a cena submarina 2D do ROV. |
| `run_demo.py` | Sobe tudo de uma vez, cada host em um canto da tela (mostra que são hosts separados). |
| `test_system.py` | Teste de integração **headless** (sem GUI) que verifica todos os conceitos. |

---

## Como rodar

### Painel de demonstração (o mais impactante) ⭐

```bash
python demo_dashboard.py
```

Abre **uma janela** com tudo: à esquerda a **topologia da rede** com os pacotes
reais voando entre os nós (azul = comando confiável, cinza = telemetria, verde =
ACK, ✕ vermelho = perdido), e à direita a **cena submarina 2D** do ROV, que
desce/sobe, solta bolhas e apaga a luz conforme o piloto age e a bateria cai.

Botões ao vivo: **Conectar Piloto A**, **Frente/Ré/Parar**, **＋ Piloto B**
(concorrência), **☠ Derrubar primário** (veja a topologia se curar no failover)
e um slider de **perda de pacotes** (veja a retransmissão acontecer). Tudo roda
em um processo só, mas os nós conversam por **UDP real** no loopback.

> Verificação automática do painel: `python demo_dashboard.py --selftest`.

### Jeito multi-janela (mostra hosts separados)

```bash
python run_demo.py
```

Abre 4 janelas nos quatro cantos da tela. Variações:

```bash
python run_demo.py --two-pilots   # 2 pilotos disputando o mesmo ROV
python run_demo.py --loss 0.2      # 20% de perda de pacotes nos relays
```

Para encerrar tudo: volte ao terminal do `run_demo.py` e tecle Enter.

### Jeito manual (mostra que são processos/hosts separados)

Cada comando em um terminal (ou máquina) diferente:

```bash
# Relay primário
python relay_server.py --role primary --port 5000 --peer 127.0.0.1:5001 --corner tl

# Relay backup
python relay_server.py --role backup  --port 5001 --peer 127.0.0.1:5000 --corner tr

# ROV
python rov_simulator.py --id rov1 --relays 127.0.0.1:5000,127.0.0.1:5001 --corner bl

# Piloto (usa o segredo de rede padrão; veja abaixo como trocar)
python pilot_client.py --id pilotoA --target rov1 --relays 127.0.0.1:5000,127.0.0.1:5001 --corner br
```

> Para rodar em **máquinas diferentes** na mesma rede, troque `127.0.0.1`
> pelos IPs reais e use `--host 0.0.0.0` nos relays.

### Autenticação por segredo compartilhado

Todos os nós (relays, ROVs e pilotos) compartilham **um mesmo segredo de rede** —
o modelo do WireGuard/TLS-PSK. A prova de identidade é um **HMAC-SHA256** desse
segredo sobre o transcript Diffie-Hellman: o segredo **nunca trafega**, o DH dá
uma chave de sessão efêmera (forward secrecy) e o nonce impede replay. Quem
conhece o segredo entra — com o **id que quiser**, sem copiar nenhum arquivo de
chave.

O segredo padrão é `rov-lab-2026`. Para trocar, passe `--secret NOSSA_SENHA` em
**todos** os processos (ou defina a variável de ambiente `ROV_NETWORK_KEY`):

```bash
python relay_server.py   --role primary --secret NOSSA_SENHA ...
python pilot_client.py   --id quemquiser --secret NOSSA_SENHA ...
```

> Trade-off honesto: com segredo compartilhado, todos que o conhecem são
> igualmente confiáveis — a identidade é um "nome reivindicado", não uma chave
> por pessoa. É o preço de não ter que distribuir chaves.

---

## Rodando distribuído de verdade (2 relays em IP público)

Só os **dois relays** precisam de IP público — ROVs e pilotos sempre *saem* em
direção a eles, então **funcionam atrás de NAT** (PCs do lab, seu PC, celular)
sem configuração de rede. Recomendado: **duas VMs** (ex.: Oracle Cloud Always
Free), uma para cada relay, para demonstrar o failover entre hosts reais.

**1. Nas VMs** — abra a porta **UDP** (não TCP!) no firewall/security group e rode:

```bash
# VM1 (IP público IP1) — relay primário
python relay_server.py --role primary --host 0.0.0.0 --port 5000 \
    --peer IP2:5001 --secret NOSSA_SENHA --no-gui

# VM2 (IP público IP2) — relay backup
python relay_server.py --role backup  --host 0.0.0.0 --port 5001 \
    --peer IP1:5000 --secret NOSSA_SENHA --no-gui
```

**2. Em qualquer PC do lab / seu PC** — aponte os clientes para os IPs públicos:

```bash
python rov_simulator.py --id rov1     --secret NOSSA_SENHA --relays IP1:5000,IP2:5001
python pilot_client.py  --id pilotoA  --secret NOSSA_SENHA --relays IP1:5000,IP2:5001 --target rov1
```

**3. Celular / navegador** — rode o piloto web em algum PC que alcance os relays
(inclusive uma das VMs, se quiser acesso pela internet) e abra o endereço dele no
celular:

```bash
python web_pilot.py --id pilotoCel --secret NOSSA_SENHA \
    --relays IP1:5000,IP2:5001 --target rov1 --port 8080
# no celular: http://<ip-de-quem-roda-o-web_pilot>:8080
```

**Criar novos ROVs/pilotos** é só escolher um `--id` diferente e usar o mesmo
`--secret` — não há lista fixa nem arquivos para copiar.

---

## Roteiro sugerido para a demonstração ao vivo

### Com o painel (`python demo_dashboard.py`) — recomendado

1. **Abertura:** uma janela só. Explique os dois lados — **topologia** (esq.) e
   **ROV na água** (dir.). Os relays e o ROV já estão no ar; **o piloto começa
   desconectado** de propósito.
2. **Conexão + autenticação ao vivo:** clique **"Conectar Piloto A"**. Veja os
   pacotes azuis (registro → DH efêmero → prova HMAC do segredo) voando até o RELAY P, o nó
   do piloto virar "autenticado" e depois "controla ✓". O log embaixo mostra o
   processo; explique que **o segredo e a chave de sessão nunca trafegam**.
3. **Controle + telemetria:** use **Frente/Ré/Parar** com o slider de potência.
   O ROV **desce/sobe** na água, solta bolhas e a bateria cai — e os pacotes de
   comando (azul) e telemetria (cinza) aparecem na topologia.
4. **Protocolo (QUIC-lite):** arraste o slider **"Perda de pacotes"** para ~25%.
   Surgem os **✕ vermelhos**; os comandos (azul, confiável) são **retransmitidos**
   até chegar, enquanto a telemetria (cinza, não-confiável) só **pisca**. Esse é
   o gancho para explicar *head-of-line blocking*.
5. **Concorrência (exclusão mútua):** clique **"＋ Piloto B"**. Ele entra na
   topologia e o log mostra **"controle negado"** — só um piloto por ROV.
6. **Failover / tolerância a falhas:** clique **"☠ Derrubar primário"**. O
   RELAY P fica vermelho **"CAIU"**, o RELAY B vira dourado **"ATIVO (assumiu)"**,
   as arestas ativas religam nele e a telemetria volta a fluir — o **Piloto A
   continua no controle** (posse **preservada via replicação**). Depois, se
   quiser repetir, clique **"♻ Reviver primário"**.

### Alternativa multi-janela (`python run_demo.py --two-pilots`)

Útil para reforçar o argumento **"são hosts separados"** (cada um em sua janela):

1. Relays e ROV sobem conectados; os pilotos começam desconectados.
2. Clique **"Conectar ao relay"** na janela do `pilotoA` e acompanhe o handshake
   de autenticação no log dele e no do relay.
3. Use **Frente/Ré/Parar** e veja a telemetria mudar na janela do ROV e do piloto.
4. A janela do `pilotoB` mostra **"controle negado"** (exclusão mútua).
5. Rode com `--loss 0.2` para ver comandos retransmitindo e telemetria piscando.
6. **Feche a janela do RELAY primário**: em poucos segundos o backup vira ATIVO e
   o ROV e o piloto migram sozinhos, preservando o controle.

---

## Conceitos de Sistemas Distribuídos → onde estão no código

| Conceito | Onde |
|---|---|
| Travessia de NAT/firewall | Clientes sempre iniciam a conexão para o relay (`quiclite`, `RovNode`, `PilotNode`). |
| Protocolo de transporte próprio | `quiclite.py`: numeração, ACK, retransmissão e reordenação sobre UDP. |
| Canais independentes / *head-of-line blocking* | `send_reliable` (comandos) vs `send_unreliable` (telemetria): a perda em um não trava o outro. |
| Detecção de falhas / heartbeat | `heartbeat` + `RelayNode._liveness_monitor` (clientes) e `relay_heartbeat` (relay↔cliente). |
| Exclusão mútua / concorrência | `RelayNode._try_grant_control` — um piloto por ROV. |
| Autenticação (segurança) | Segredo compartilhado (HMAC-SHA256) mútuo + DH efêmero + HKDF em `identity_keys.py`, `dh_exchange.py` e `RelayNode._handle_auth`. |
| Registro distribuído de sessões | Dicionários `rovs`/`pilots` no relay. |
| **Replicação** | `RelayNode._replicate` (primário → backup) e `_apply_replication` (espelho). |
| **Tolerância a falhas do servidor / failover** | Promoção do backup (`_heartbeat_loop`), migração dos clientes (`_failover`) e **preservação de posse** via reserva a partir do estado replicado (`_reservation_blocks`). |

### Sobre o "QUIC-lite" (seja honesto na banca)

Isto **não** é o QUIC de verdade (que tem TLS 1.3 embutido, controle de
congestionamento, migração de conexão, 0-RTT…). É uma reimplementação
**didática** das duas ideias centrais que motivam o QUIC: rodar sobre **UDP** e
oferecer **canais independentes** (um confiável, um não-confiável) para evitar o
*head-of-line blocking* do TCP. O que foi deixado de fora foi deixado de fora de
propósito, para manter o foco nos conceitos.

---

## Testes

Teste de integração automatizado, sem interface, que sobe dois relays, um ROV e
dois pilotos e verifica autenticação, concorrência, replicação e failover:

```bash
python test_system.py
```

Deve terminar com `RESULTADO: 15 passaram, 0 falharam`.
