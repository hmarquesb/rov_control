"""Diffie-Hellman efêmero autenticado para o handshake didático.

Usa o grupo MODP 14 (2048 bits) do RFC 3526. A troca DH cria um segredo
temporário; um HMAC do segredo de rede compartilhado autentica o transcript.
"""
import hashlib
import hmac
import secrets

GROUP_ID = 14
GENERATOR = 2
PRIME = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
PRIME_BYTES = (PRIME.bit_length() + 7) // 8


def generate_keypair():
    """Gera um expoente efêmero com 320 bits e sua chave pública."""
    private = (1 << 319) | secrets.randbits(319)
    return private, pow(GENERATOR, private, PRIME)


def encode_public(public):
    return format(public, "x")


def decode_public(encoded):
    try:
        public = int(str(encoded), 16)
    except (TypeError, ValueError):
        raise ValueError("chave pública DH inválida")
    if not 2 <= public <= PRIME - 2:
        raise ValueError("chave pública DH fora do grupo")
    return public


def transcript(role, identity, nonce, client_public, relay_public):
    fields = ("rov-control-dh-v1", str(role), str(identity), str(nonce),
              encode_public(client_public), encode_public(relay_public))
    return "|".join(fields).encode("ascii")


def confirmation_transcript(handshake_transcript, key_fingerprint):
    return (handshake_transcript + b"|server-finished|"
            + str(key_fingerprint).encode("ascii"))


def derive_session_key(private, peer_public, nonce, handshake_transcript):
    """Calcula DH e aplica HKDF-SHA256 (extract + expand) para 32 bytes."""
    if not 2 <= peer_public <= PRIME - 2:
        raise ValueError("chave pública DH fora do grupo")
    shared = pow(peer_public, private, PRIME).to_bytes(PRIME_BYTES, "big")
    salt = hashlib.sha256(str(nonce).encode("utf-8")).digest()
    prk = hmac.new(salt, shared, hashlib.sha256).digest()
    info = b"rov-control/session/v1|" + hashlib.sha256(handshake_transcript).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def fingerprint(session_key):
    return hashlib.sha256(session_key).hexdigest()[:12]