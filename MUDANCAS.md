# O que mudou no ROV Control — e por quê

> Registro para a equipe de apresentação (Sistemas Distribuídos).
> Passamos o projeto de uma demo em `localhost` para um sistema rodando de verdade
> entre máquinas: dois relays em nuvem, autenticação mais simples de operar, e um
> failover mais robusto.

**Dados do deploy atual:**

| | |
|---|---|
| Relay primário | `137.131.252.187:5000` |
| Relay backup | `147.15.40.53:5001` |
| Segredo de rede | `rov-sd-helena` |
| Dependências | só Python 3 (nenhuma externa) |

---

## Visão geral: as três frentes

Nada da lógica central de Sistemas Distribuídos foi removido — NAT traversal, transporte
próprio (QUIC-lite), exclusão mútua, detecção de falhas, replicação e failover continuam.
O que fizemos foi **tornar o sistema operável fora do localhost** e **corrigir arestas do
failover** que só aparecem com máquinas reais.

| Frente | Em uma frase | Motivação |
|---|---|---|
| **Autenticação** | Trocamos um par de chaves RSA por identidade por um único *segredo de rede* (HMAC). | Rodar entre máquinas sem copiar arquivos de chave; e ficou sem dependência externa. |
| **Deploy** | Dois relays em VMs da Oracle Cloud, como serviços que sobem sozinhos. | Provar o failover entre *hosts reais*, com clientes vindos de qualquer rede. |
| **Failover** | Corrigimos um impasse de liderança e reforçamos a preservação de posse. | Reinícios/reboots expunham dois bugs que travavam o sistema. |

---

## 1. Autenticação: de chaves RSA para um segredo compartilhado

Esta é a mudança de conceito mais visível. O *fluxo* do handshake continua igual (desafio →
Diffie-Hellman efêmero → prova → chave de sessão). O que mudou foi **como a identidade é
provada**.

**Antes — RSA por identidade**
- Um par de chaves RSA-2048 por piloto/ROV/relay, em arquivos `.pem`.
- Prova por assinatura **RSA-PSS** do transcript DH.
- Lista fixa de identidades (`pilotoA/B`, `rov1/2/3`…).
- Pasta `identity_keys/` no `.gitignore` → **cada máquina gerava chaves diferentes**.
- Dependia da biblioteca `cryptography`.

**Depois — segredo compartilhado (PSK)**
- Um único **segredo de rede**, o mesmo em todos os nós (modelo WireGuard/TLS-PSK).
- Prova por **HMAC-SHA256** sobre o mesmo transcript DH.
- Qualquer `--id` que você quiser — sem lista fixa.
- Nenhum arquivo de chave para copiar entre máquinas.
- **Só Python 3** (stdlib `hmac`/`hashlib`).

O que **permanece** (e continua defensável): a **chave de sessão efêmera** por Diffie-Hellman
(forward secrecy), o **nonce** contra replay, a **autenticação mútua** (cliente e relay provam
o segredo) — e o segredo **nunca trafega** na rede, só o HMAC dele.

> **Por que trocamos:** para rodar distribuído, o relay em uma máquina precisa reconhecer
> clientes de outras. Com RSA por arquivo, cada máquina gerava suas próprias chaves e a
> autenticação falhava entre hosts. O segredo compartilhado resolve isso com uma string, sem
> distribuir arquivos — e, de bônus, elimina a dependência `cryptography`, deixando o projeto
> de novo "só Python 3".

**Criar um piloto ou ROV novo** é só escolher um `--id` diferente com o mesmo `--secret`:

```bash
python3 pilot_client.py --id pilotoQualquerNome --secret rov-sd-helena \
    --relays 137.131.252.187:5000,147.15.40.53:5001 --target rov1 --no-gui
```

> **Honestidade para a banca:** com segredo compartilhado, **todos que o conhecem são
> igualmente confiáveis** — a identidade vira um "nome reivindicado", não uma chave
> criptográfica por pessoa. É o preço de não precisar distribuir chaves. Se a banca quiser
> identidade forte por pessoa, o caminho seria voltar ao RSA por identidade (com a dor de
> distribuir chaves).

**Arquivos tocados:** `identity_keys.py` (reescrito: `load_network_key`, `sign_transcript`,
`verify_transcript` com HMAC) · `relay_server.py`, `pilot_client.py`, `rov_simulator.py`,
`web_pilot.py` (usam o segredo + flag `--secret`) · `run_demo.py` (repassa o segredo) ·
`requirements.txt` (esvaziado) · `.gitignore` (ignora `.venv/`) · `README.md` · testes (o caso
negativo agora usa "segredo errado").

---

## 2. Deploy: dois relays em nuvem (Oracle)

Subimos **dois relays em VMs da Oracle Cloud (nível Always Free, Ubuntu)**: um primário na
porta 5000, um backup na 5001, cada um com IP público. Os clientes (ROV, piloto, celular)
rodam em qualquer lugar e apontam para esses dois IPs.

> **A sacada de rede:** **só os relays precisam de IP público.** ROV e piloto sempre *saem* em
> direção ao relay, então funcionam atrás de NAT (PCs do lab, o Mac, o celular) sem configurar
> nada na rede deles. É a própria travessia de NAT do projeto, agora demonstrada de verdade.

| Peça | O que é / por que |
|---|---|
| **Portas UDP (2 camadas)** | Abrir a porta tem *duas* barreiras: a **Security List** da Oracle (ingress UDP 5000/5001) *e* o firewall do Ubuntu (`iptables`), que bloqueia tudo menos SSH por padrão. |
| **Código via GitHub** | Repositório público → `git clone` nas VMs e `git pull` para atualizar. |
| **systemd** | Cada relay virou um serviço (`rov-relay`) que **sobe sozinho no boot**, reinicia se travar e liga/desliga com um comando — ideal para demonstrar failover. |
| **Cloud Shell** | Terminal no navegador da Oracle, usado como "ponte" para entrar nas VMs (a rede do lab bloqueava SSH direto). |
| **Celular** | `web_pilot.py` serve uma página; o celular abre no navegador e controla o ROV por baixo via UDP. |

Como os clientes só precisam dos dois IPs públicos e do segredo, rodar de um PC do lab é
literalmente o mesmo comando do Mac.

---

## 3. Failover mais robusto: dois consertos

Rodando em máquinas reais (com reinícios e reboots), apareceram dois problemas no failover que
o localhost nunca expôs. Ambos foram corrigidos e testados.

### Conserto A — o impasse dos "dois seguidores"

- **Sintoma:** depois de reinícios, os clientes ficavam quicando entre os relays sem nunca
  conectar (`VM1 → redireciona pra VM2`, `VM2 → redireciona pra VM1`).
- **Causa:** os dois relays acabavam *passivos*, cada um apontando o outro como líder. A
  promoção do backup só dispara por *silêncio* do par — mas aqui os dois estavam vivos e
  conversando, então ninguém se promovia. Deadlock, sem líder.
- **Correção:** o **primário reassume a liderança sempre que não há um backup ativo no ar**
  (par caiu, ou os dois passivos). Ele **não** derruba um backup genuinamente ativo — mantém a
  propriedade tipo-Raft de "não preemptar o líder atual". O impasse se cura sozinho em ~2–3s.
  *Bônus:* também corrige um caso latente — se o backup assume e *depois* cai, agora o primário
  volta a liderar (antes, ficava todo mundo sem líder).

### Conserto B — a posse não podia ser "roubada"

- **Sintoma:** num failover seguido da volta do primário, um piloto que estava esperando
  (pilotoB) às vezes ganhava o controle antes do dono original (pilotoA).
- **Causa:** quando o primário reassumia, ele *não recriava a reserva* que protege o dono
  anterior — e nem tinha como, porque só o primário replicava (ele não recebia replicação de
  volta).
- **Correção (duas partes):**
  1. **Replicação bidirecional:** agora **quem está ativo replica para o par passivo** (antes,
     só o primário replicava). Assim o primário passivo tem o estado atual. Isso também
     consertou um bug latente: um primário rebaixado podia "sujar" o espelho do backup.
  2. **Reserva ao reassumir:** ao voltar a liderar, o primário **reserva cada ROV ao dono
     anterior** (a partir do estado replicado) por uma janela de tempo (`RESERVE_WINDOW = 12s`)
     — exatamente como o backup já fazia. Um piloto que espera não rouba o controle na reconexão.

> **Honestidade para a banca:** a reserva usa o **estado replicado**. Se um relay ficou
> **totalmente offline** durante o failover, ele perdeu os eventos daquele período — então, se
> *esse* relay reassumir depois, não terá o que reservar. Cobrir 100% exigiria **transferência
> de estado (snapshot) na reentrada** do relay, deixada como trabalho futuro. Os casos comuns
> (deadlock, relay que ficou só passivo, backup que cai com o primário no ar) já estão cobertos.

Todas as mudanças de failover estão em `relay_server.py` — na eleição de líder
(`_on_relay_message`, `_heartbeat_loop`) e na replicação (`_replicate`).

---

## 4. Testes e verificação

Tudo roda com o **Python do sistema, sem instalar nada** (a dependência `cryptography` saiu
junto com o RSA).

| Teste | O que verifica | Resultado |
|---|---|---|
| `test_system.py` | Autenticação (segredo certo entra, errado não), exclusão mútua, comando confiável, replicação, failover com posse preservada — 15 checagens. | 15/15 |
| `test_extended.py` | Segurança, multi-ROV, vídeo e recuperação de liderança. (obs.: corrigimos uma corrida pré-existente na sincronização do próprio teste.) | todos |
| Cenários novos | Reprodução do *deadlock* (primário reassume sozinho) e da *reserva ao reassumir* (dono conectado não é roubado; outro piloto é bloqueado). | ok |

**Como demonstrar ao vivo (resumo):**
1. Suba ROV + pilotoA no Mac → veja auth e replicação nos logs dos dois relays.
2. Suba pilotoB no mesmo ROV → **controle negado** (exclusão mútua).
3. `systemctl stop rov-relay` no primário → backup assume, pilotoA **mantém o controle**
   (failover + posse preservada).
4. Religue o primário → ele reentra como **standby**, sem flapping.

---

## 5. Pontos honestos para a banca

Três "verdades" que é bom a equipe ter na ponta da língua — mostram maturidade, não fraqueza.

- **QUIC-lite não é o QUIC real:** é uma reimplementação didática das duas ideias centrais
  (rodar sobre UDP + canais independentes confiável/não-confiável para evitar *head-of-line
  blocking*). TLS 1.3, controle de congestionamento e 0-RTT ficaram de fora de propósito.
- **Segredo compartilhado:** quem tem o segredo é igualmente confiável; a identidade é um nome
  reivindicado, não uma chave por pessoa (modelo WireGuard).
- **Failover:** demonstramos um ciclo completo com preservação de posse e auto-recuperação de
  liderança nos dois sentidos; a *transferência de estado na reentrada* de um relay que ficou
  totalmente offline seria o próximo passo.

---

## 6. Referência rápida de comandos

**Nas VMs (via Cloud Shell → SSH):**

```bash
# ver o relay ao vivo
journalctl -u rov-relay -f
# parar (para demonstrar failover) / religar / status
sudo systemctl stop rov-relay
sudo systemctl start rov-relay
sudo systemctl status rov-relay --no-pager
# atualizar o código depois de um git push
cd ~/rov_control && git pull && sudo systemctl restart rov-relay
```

**Nos clientes (Mac, PC do lab):**

```bash
# ROV
python3 rov_simulator.py --id rov1 --secret rov-sd-helena \
    --relays 137.131.252.187:5000,147.15.40.53:5001 --no-gui --no-video
# Piloto (tire --no-gui para abrir a janela com botões)
python3 pilot_client.py --id pilotoA --secret rov-sd-helena \
    --relays 137.131.252.187:5000,147.15.40.53:5001 --target rov1 --no-gui
```

**Rearmar o cenário (voltar o primário a líder):**

```bash
# reinicie os dois; o primário nasce líder de novo
sudo systemctl restart rov-relay   # na VM1 e na VM2
```

**Demo local (sem nuvem, uma tela só):**

```bash
python3 demo_dashboard.py
```

---

## Commits principais desta fase

```
d478463  Autenticação por segredo compartilhado + deploy em VMs
7b7ae9e  Failover: primário reassume quando não há líder ativo (corrige deadlock)
(último) Failover: replicação bidirecional + reserva de posse ao primário reassumir
```
