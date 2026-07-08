"""
protocol.py
-----------
Define o "idioma" que Piloto, Relay e ROV usam para se falar, MAIS o esquema
de autenticação do piloto.

As mensagens continuam sendo dicionários (JSON) com um campo "type". O que
mudou em relação à versão anterior é COMO elas viajam: agora vão pela camada
quiclite (UDP), escolhendo o canal certo para cada uma:

  CANAL CONFIÁVEL (não pode perder, tem que chegar em ordem):
    register, registered, auth_challenge, auth_response, auth_ok, auth_fail,
    control_granted, control_denied, command, release_control, rov_offline,
    error, replicate

  CANAL NÃO-CONFIÁVEL (periódico, "último vence", pode perder):
    heartbeat, telemetry, relay_heartbeat, relay_ping


AUTENTICAÇÃO MÚTUA + ACORDO DE CHAVE:
--------------------------------------
Todos os nós (pilotos, ROVs e relays) compartilham um mesmo SEGREDO DE REDE.
Cliente e relay geram chaves Diffie-Hellman efêmeras e autenticam a negociação
com um HMAC-SHA256 desse segredo sobre o transcript DH (o segredo nunca trafega).
A chave de sessão é derivada com HKDF-SHA256. Nonces impedem replay e uma nova
sessão é negociada após cada conexão ou failover. Ver dh_exchange.py e
identity_keys.py."""

import secrets

def gen_nonce() -> str:
    """Gera um desafio aleatório de uso único (32 hex = 128 bits)."""
    return secrets.token_hex(16)


def new_session_token() -> str:
    """Token opaco entregue ao piloto após autenticar com sucesso."""
    return secrets.token_hex(16)
