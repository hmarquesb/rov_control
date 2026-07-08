"""Autenticação por SEGREDO COMPARTILHADO (pre-shared key) para o handshake.

Antes o projeto usava um par de chaves RSA por identidade, guardado em arquivos
`.pem`. Isso obrigava a COPIAR chaves entre as máquinas para rodar distribuído.
Agora usamos um único SEGREDO DE REDE (o mesmo em todos os nós) — o modelo do
WireGuard / TLS-PSK: quem conhece o segredo entra, com o nome (id) que quiser.

A prova de identidade é um HMAC-SHA256 sobre o mesmo transcript Diffie-Hellman
que já existia (ver dh_exchange.py). Assim continuamos tendo:

  * chave de sessão efêmera via DH (forward secrecy);
  * nonce no transcript (anti-replay);
  * autenticação MÚTUA (cliente e relay provam que conhecem o segredo);
  * o segredo NUNCA trafega na rede — só o HMAC dele viaja.

Trade-off (seja honesto na banca): com um segredo compartilhado, todos que o
conhecem são igualmente confiáveis; a identidade é um "nome reivindicado", não
uma chave criptográfica por pessoa. É o preço de não precisar distribuir chaves.

Só depende da biblioteca padrão do Python (hmac/hashlib) — nenhuma dependência
externa.
"""

import hashlib
import hmac
import os

# Segredo padrão da demonstração. Pode ser sobrescrito por --secret na linha de
# comando ou pela variável de ambiente ROV_NETWORK_KEY. Em um deploy real, todos
# os relays e clientes precisam usar EXATAMENTE o mesmo valor.
DEFAULT_SECRET = "rov-lab-2026"


def load_network_key(secret=None):
    """Resolve o segredo de rede e o devolve como bytes.

    Precedência: argumento explícito > variável de ambiente ROV_NETWORK_KEY >
    DEFAULT_SECRET. Aceita str ou bytes.
    """
    value = secret or os.getenv("ROV_NETWORK_KEY") or DEFAULT_SECRET
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def sign_transcript(secret, handshake_transcript):
    """Autentica o transcript com HMAC-SHA256; devolve a tag em hexadecimal."""
    key = secret if isinstance(secret, (bytes, bytearray)) else load_network_key(secret)
    return hmac.new(bytes(key), handshake_transcript, hashlib.sha256).hexdigest()


def verify_transcript(secret, handshake_transcript, tag):
    """Confere a tag HMAC em tempo constante. True se o segredo bate."""
    expected = sign_transcript(secret, handshake_transcript)
    try:
        return hmac.compare_digest(expected, str(tag))
    except (TypeError, ValueError):
        return False
