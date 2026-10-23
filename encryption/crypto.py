# encryption/crypto.py
# Cryptographic utilities: base64, random IDs/keys, MAC, sign, wrap.
#
# Every keyed or hashed value here is Ascon (NIST SP 800-232), via
# encryption/ascon.py. BLAKE3 is gone: it was never named in the
# specification, and the data-plane MAC it used to compute is Ascon-Mac.

import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)


# ======================================================
# Base64 utilities
# ======================================================

def _add_b64_padding(s: str) -> str:
    if not isinstance(s, str):
        raise TypeError("Expected str for base64 input")
    s = s.strip()
    return s + ("=" * (-len(s) % 4))

def b64u_to_bytes(s: str) -> bytes:
    """
    Decode Base64-URL (no/with padding) -> bytes.
    Raises TypeError on non-str input and binascii.Error on malformed input.
    """
    return base64.urlsafe_b64decode(_add_b64_padding(s))

def _b64_any_to_bytes(s: str) -> bytes:
    """
    Decode either urlsafe or standard Base64 (no/with padding) -> bytes.
    Tries urlsafe first, then standard.
    """
    s_padded = _add_b64_padding(s)
    try:
        return base64.urlsafe_b64decode(s_padded)
    except Exception:
        return base64.b64decode(s_padded)

def bytes_to_b64u(b: bytes) -> str:
    """
    Encode bytes -> Base64-URL string without padding.
    """
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise TypeError("Expected bytes-like object")
    return base64.urlsafe_b64encode(bytes(b)).decode("ascii").rstrip("=")

# ======================================================
# Random IDs / keys
# ======================================================

def random_session_id_b64u(length: int = 16) -> str:
    """
    Random session ID (default 16 bytes → ~22 chars base64url, no padding).
    """
    raw = secrets.token_bytes(length)
    return bytes_to_b64u(raw)

def random_session_key(length: int = 32) -> bytes:
    """
    Fresh symmetric session key (default 32 bytes).
    """
    return secrets.token_bytes(length)

# ======================================================
# Data-plane MAC: Ascon-Mac
# ======================================================

def compute_mac(key: bytes, data: bytes) -> bytes:
    """
    Ascon-Mac tag (16 bytes) over `data` under `key`.

    The message body travels in clear and this value protects it: an
    authenticator nobody without the key can produce, computed in one pass
    over the message rather than by hashing and then encrypting the hash.
    Ascon-Mac takes a 16-byte key; the session key is longer, so the first
    16 bytes are used, which carry the protocol's full 128-bit security.
    """
    from encryption.ascon import ascon_mac
    return ascon_mac(key[:16], data)

def compute_mac_b64u(key: bytes, data: bytes) -> str:
    return bytes_to_b64u(compute_mac(key, data))

def verify_mac(key: bytes, data: bytes, tag: bytes) -> bool:
    """Constant-time verification of an Ascon-Mac tag."""
    return secrets.compare_digest(compute_mac(key, data), tag)

# ======================================================
# Ed25519 sign / verify
# ======================================================

def sign_detached_b64u(priv_key_bytes: bytes, payload: bytes) -> str:
    """
    Detached Ed25519 signature → base64url.
    priv_key_bytes: 32 bytes (raw private key).
    """
    sk = Ed25519PrivateKey.from_private_bytes(priv_key_bytes)
    sig = sk.sign(payload)
    return bytes_to_b64u(sig)

def verify_detached(pub_key_bytes: bytes, payload: bytes, sig_b64u: str) -> bool:
    """
    Verify detached Ed25519 signature. Returns True/False.
    pub_key_bytes: 32 raw public key bytes
    payload: bytes
    sig_b64u: base64url-encoded signature (no/with padding accepted)
    """
    try:
        pk = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        sig = b64u_to_bytes(sig_b64u)
        pk.verify(sig, payload)
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------
# Ed25519 verify helper (used by demo_subscriber.py and others)
# ---------------------------------------------------------------------

def ed25519_verify(public_key_b64u: str, message, signature_b64u: str) -> bool:
    """
    Verify an Ed25519 signature (Base64URL inputs).
    :param public_key_b64u: base64url-encoded Ed25519 public key (32 bytes)
    :param message: str or bytes message that was signed (publisher used pipe-joined 5-field core)
    :param signature_b64u: base64url-encoded signature (64 bytes)
    :return: True if valid, False otherwise
    """
    try:
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        pub_bytes = b64u_to_bytes(public_key_b64u)
        sig_bytes = b64u_to_bytes(signature_b64u)

        pk = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pk.verify(sig_bytes, msg_bytes)
        return True
    except Exception:
        return False


# ======================================================
# X25519 ECDH session-key wrap/unwrap (with AEAD)
# ======================================================

def _kdf_wrap_key(shared_secret: bytes) -> bytes:
    """
    Derive a 32-byte AEAD key from an ECDH shared secret, with Ascon-CXOF128
    under a customisation string for domain separation.
    """
    from encryption.ascon import ascon_hash
    return ascon_hash(shared_secret, "Ascon-CXOF128", hashlength=32,
                      customization=b"WRAP-V1")

def wrap_session_key(sender_x25519_priv: bytes, recipient_x25519_pub: bytes, session_key: bytes) -> str:
    """
    Wrap (encrypt) the session_key to the recipient using X25519 ECDH + ChaCha20-Poly1305.
    Returns base64url(wrap_bytes) with layout: nonce(12) || ciphertext+tag.
    Keys are raw 32-byte values (NOT base64 strings).
    """
    sk = X25519PrivateKey.from_private_bytes(sender_x25519_priv)
    pk = X25519PublicKey.from_public_bytes(recipient_x25519_pub)

    # ECDH
    shared = sk.exchange(pk)  # 32 bytes

    # Derive AEAD key
    aead_key = _kdf_wrap_key(shared)
    aead = ChaCha20Poly1305(aead_key)

    # Nonce + encrypt (no AAD)
    nonce = secrets.token_bytes(12)
    ct = aead.encrypt(nonce, session_key, None)

    wrapped = nonce + ct
    return bytes_to_b64u(wrapped)

def unwrap_session_key(receiver_x25519_priv: bytes, sender_x25519_pub: bytes, wrapped_b64u: str) -> bytes:
    """
    Unwrap (decrypt) the session key using receiver's X25519 private key and sender's X25519 public key.
    Accepts base64url input produced by wrap_session_key().
    Keys are raw 32-byte values (NOT base64 strings).
    """
    sk = X25519PrivateKey.from_private_bytes(receiver_x25519_priv)
    pk = X25519PublicKey.from_public_bytes(sender_x25519_pub)

    shared = sk.exchange(pk)
    aead_key = _kdf_wrap_key(shared)
    aead = ChaCha20Poly1305(aead_key)

    blob = b64u_to_bytes(wrapped_b64u)
    if len(blob) < 12 + 16:
        raise ValueError("wrapped blob too short")
    nonce, ct = blob[:12], blob[12:]

    return aead.decrypt(nonce, ct, None)

# ---------------------------------------------------------------------
# X25519 unwrap helper (derive shared secret from base64url keys)
# ---------------------------------------------------------------------

def x25519_unwrap(private_key_b64u: str, peer_pub_b64u: str) -> bytes:
    """
    Derive a shared secret using X25519 (used to unwrap session keys).
    :param private_key_b64u: base64url-encoded X25519 private key (32 bytes)
    :param peer_pub_b64u:    base64url-encoded X25519 public key (32 bytes)
    :return: shared secret bytes (32)
    """
    try:
        priv_bytes = b64u_to_bytes(private_key_b64u)
        peer_bytes = b64u_to_bytes(peer_pub_b64u)
        priv = X25519PrivateKey.from_private_bytes(priv_bytes)
        peer_pub = X25519PublicKey.from_public_bytes(peer_bytes)
        shared_secret = priv.exchange(peer_pub)
        return shared_secret
    except Exception as e:
        print(f"[ERROR] x25519_unwrap failed: {e}")
        return b""
