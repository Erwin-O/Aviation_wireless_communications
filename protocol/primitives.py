"""
Cryptographic primitives, bound to the equations of the paper.

Every function here corresponds to a numbered equation or a named construction
in Sections 3.3.1 to 3.3.3, and says which. Nothing in this module makes a
protocol decision; it is the layer the handshake and the operational messages
are written against.

Primitives (Section 3.3.1, Table 2):
    Ed25519         long-term signatures
    X25519          ephemeral key agreement
    Ascon-Mac       operational message authentication, 128-bit tag
    Ascon-Hash256   ephemeral derivation, challenge, transcript, ACK digest
    Ascon-CXOF128   session key derivation

Domain separation: every use of Ascon-Hash256 prefixes a fixed label, so that
the same function applied to two purposes cannot produce a value valid in
both (Section 3.3.2). The labels share a prefix and end with a NUL, and no
label contains a NUL, so the set is prefix-free: no label followed by one
input can equal another label followed by a different input.

Signatures and key agreement use `cryptography` (PyCA), which is what the
repository has always used and what Section 5.1 names.
"""

from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from encryption.ascon import ascon_hash, ascon_mac

# ---------------------------------------------------------------------------
# Domain-separation labels and sizes
# ---------------------------------------------------------------------------

#: L_eph, equation (1): ephemeral scalar derivation.
L_EPH = b"AGCP-v1:ephemeral\x00"
#: L_ch, equation (6): challenge derivation.
L_CH = b"AGCP-v1:challenge\x00"
#: L_tr, equation (5): handshake transcript hash.
L_TR = b"AGCP-v1:transcript\x00"
#: The label under which an ACK digests the body it acknowledges (Section 3.3.3).
L_ACK = b"AGCP-v1:ackhash\x00"
#: Ascon-CXOF128 customisation string for the session key, equation (4).
C_SESSION = b"AGCP-v1:session-key"

#: Reserved byte separating the two bodies in the transcript hash, equation
#: (5). A message body is printable ASCII with CRLF terminators, so a zero
#: byte cannot occur inside one and the boundary is unambiguous.
SEPARATOR = b"\x00"

#: Bytes of key material derived from the shared value. The Ascon-Mac key is
#: the first 16 of these; the remainder is reserve. Ascon-Mac takes a 16-byte
#: key and 16 bytes is the protocol's 128-bit security level.
SESSION_KEY_BYTES = 32
MAC_KEY_BYTES = 16

#: Ascon-Mac tag length in bytes (128-bit).
TAG_BYTES = 16

#: Challenge length in bytes: the full Ascon-Hash256 digest, untruncated.
CHALLENGE_BYTES = 32

#: LAST_EXEC before any command has been acted upon (Section 3.3.3).
ZERO_CHALLENGE = b"\x00" * CHALLENGE_BYTES


# ---------------------------------------------------------------------------
# Base64url, as the encoding requires (Section 3.3.1)
# ---------------------------------------------------------------------------

def b64u(raw: bytes) -> str:
    """Encode bytes as URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(text: str) -> bytes:
    """
    Decode URL-safe Base64 without padding.

    Strict: rejects anything that is not canonical, because a field that
    admits two encodings of the same value would break the one-parse rule.
    """
    if not isinstance(text, str):
        raise ValueError("expected str")
    padded = text + "=" * (-len(text) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if b64u(raw) != text:
        raise ValueError("non-canonical Base64")
    return raw


# ---------------------------------------------------------------------------
# Signatures (Ed25519)
# ---------------------------------------------------------------------------

def generate_signing_key() -> tuple[bytes, bytes]:
    """Return (private, public) raw 32-byte Ed25519 keys."""
    sk = Ed25519PrivateKey.generate()
    return (
        sk.private_bytes_raw(),
        sk.public_key().public_bytes_raw(),
    )


def sign(private_key: bytes, message: bytes) -> bytes:
    """Ed25519 signature over exactly `message`."""
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(message)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False rather than raising."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Key agreement (X25519) and the derivations of Section 3.3.2
# ---------------------------------------------------------------------------

def generate_kex_key() -> tuple[bytes, bytes]:
    """
    Return (private, public) raw 32-byte X25519 keys for a long-term key
    exchange pair.

    Only the private half is ever used, as an input to equations (1) and (6);
    it never appears in a credential and needs no certification
    (Section 3.3.2).
    """
    sk = X25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()


def derive_ephemeral_scalar(r: bytes, kex_secret: bytes) -> bytes:
    """
    Equation (1): sk_eph = Ascon-Hash256(L_eph || r || sk^kex).

    `r` is what the platform's random number generator supplied. The point of
    the construction is that an adversary who predicts `r` in full still
    cannot predict the scalar without the long-term secret, which is what
    makes G9 attainable. X25519 accepts any 32-byte string as a scalar, so
    the digest needs no further treatment.
    """
    if len(r) != 32:
        raise ValueError("r must be 32 bytes")
    return ascon_hash(L_EPH + r + kex_secret, "Ascon-Hash256")


def random_r() -> bytes:
    """Draw r <- {0,1}^256, the generator input to equations (1) and (6)."""
    return secrets.token_bytes(32)


def public_from_scalar(scalar: bytes) -> bytes:
    """The X25519 public value for an ephemeral scalar."""
    return X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes_raw()


def dh(scalar: bytes, peer_public: bytes) -> bytes:
    """Equation (2): the shared value Z from own scalar and peer public value."""
    return X25519PrivateKey.from_private_bytes(scalar).exchange(
        X25519PublicKey.from_public_bytes(peer_public)
    )


def session_key(shared: bytes) -> bytes:
    """
    Equation (3): K_sess = KDF(Z), with Ascon-CXOF128 under a customisation
    string particular to this use.

    No session identifier enters the derivation (Section 3.3.2): Z depends on
    ephemeral scalars generated for this session alone, so a tag under one
    session's key does not verify under another's.
    """
    return ascon_hash(
        shared,
        "Ascon-CXOF128",
        hashlength=SESSION_KEY_BYTES,
        customization=C_SESSION,
    )


def transcript_hash(m_key: bytes, m_keyack: bytes) -> bytes:
    """
    Equation (5): h = Ascon-Hash256(L_tr || m_KEY || 0x00 || m_KEYACK), over
    the two preceding message bodies with their signatures excluded.

    The reserved byte fixes the boundary between the bodies. Without it the
    concatenation alone would not determine the split, and the confirmation
    is meant to tie both parties to the whole exchange, not to a byte string
    that two different exchanges could produce.
    """
    return ascon_hash(L_TR + m_key + SEPARATOR + m_keyack, "Ascon-Hash256")


# ---------------------------------------------------------------------------
# Operational protection (Section 3.3.3)
# ---------------------------------------------------------------------------

def mac(key: bytes, data: bytes) -> bytes:
    """Ascon-Mac tag over `data` under the session key."""
    return ascon_mac(key[:MAC_KEY_BYTES], data, "Ascon-Mac", TAG_BYTES)


def verify_mac(key: bytes, data: bytes, tag: bytes) -> bool:
    """Constant-time verification of an Ascon-Mac tag."""
    return secrets.compare_digest(mac(key, data), tag)


def derive_challenge(r: bytes, kex_secret: bytes) -> bytes:
    """
    Equation (6): c = Ascon-Hash256(L_ch || r || sk^kex), truncated to
    CHALLENGE_BYTES.

    Drawn as the ephemeral scalars are drawn, so that a platform whose random
    source is predictable still issues challenges an adversary cannot
    anticipate.
    """
    if len(r) != 32:
        raise ValueError("r must be 32 bytes")
    return ascon_hash(L_CH + r + kex_secret, "Ascon-Hash256")[:CHALLENGE_BYTES]


def new_challenge(kex_secret: bytes) -> bytes:
    """Draw a fresh r and derive a challenge from it."""
    return derive_challenge(random_r(), kex_secret)


def ack_hash(body: bytes) -> bytes:
    """
    The ACK digest of the acknowledged body, under a label of its own
    (Section 3.3.3), identifying that message unambiguously when several are
    outstanding.

    One input, so there is no boundary to fix: the label ends with the
    reserved byte and no label contains one, which already separates it from
    the body.
    """
    return ascon_hash(L_ACK + body, "Ascon-Hash256")
