"""
Key material and credentials on disk.

The shape of this module is the architectural point of the protocol. The old
registry held a directory of principals: every actor's public key, shared by
everyone, and a receiver could only verify a party listed in it. Here a
receiver holds **issuer** keys, and a credential travels with the message that
uses it, so a station can verify an aircraft it has never heard of
(Section 3.3.2).

    config/trust_anchors.json       issuer name -> Ed25519 public key.
                                    The only shared file, and it names
                                    authorities, not principals.

    ~/AviationLocalKeys/<ACTOR>/    ed25519_private.key   signing key
                                    x25519_private.key    kex secret, eq. (1)
                                    credential            the signed record

The private key file names are the ones the previous implementation used, so
existing key material is picked up as it stands and only the credential is
new.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from protocol import credentials, primitives

REPO_ROOT = Path(__file__).resolve().parents[1]
ANCHORS_PATH = REPO_ROOT / "config" / "trust_anchors.json"
LOCAL_DIR = Path.home() / "AviationLocalKeys"

SIGNING_KEY_FILE = "ed25519_private.key"
KEX_KEY_FILE = "x25519_private.key"
CREDENTIAL_FILE = "credential"


def norm(actor_id: str) -> str:
    """Normalise an actor id for use as a directory name."""
    return re.sub(r"[\s/]+", "_", (actor_id or "").strip().upper())


@dataclass(frozen=True)
class Identity:
    """Everything an endpoint needs to be itself."""

    name: str
    credential: bytes
    signing_key: bytes
    kex_secret: bytes

    def endpoint_kwargs(self, trust_anchors: dict[str, bytes]) -> dict:
        """Spread straight into handshake.Initiator or handshake.Responder."""
        return dict(
            identity=self.name,
            credential=self.credential,
            signing_key=self.signing_key,
            kex_secret=self.kex_secret,
            trust_anchors=trust_anchors,
        )


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------

def load_trust_anchors(path: Path | None = None) -> dict[str, bytes]:
    """Issuer name -> Ed25519 public key."""
    path = path or ANCHORS_PATH
    if not path.exists():
        raise FileNotFoundError(
            f"No trust anchors at {path}. Run scripts/provision.py first.")
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: primitives.unb64u(v) for k, v in data.get("issuers", {}).items()}


def add_trust_anchor(issuer: str, public_key: bytes, path: Path | None = None) -> None:
    path = path or ANCHORS_PATH
    data = {"schema_version": 1, "issuers": {}}
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        data.setdefault("issuers", {})
    data["issuers"][issuer] = primitives.b64u(public_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Per-actor key material
# ---------------------------------------------------------------------------

def actor_dir(actor: str, base: Path | None = None) -> Path:
    return (base or LOCAL_DIR) / norm(actor)


def ensure_keys(actor: str, base: Path | None = None) -> tuple[bytes, bytes]:
    """
    Return (signing_key, kex_secret), generating and storing them if absent.

    Existing key files are reused rather than replaced: the keys the previous
    implementation generated are the keys this one needs.
    """
    d = actor_dir(actor, base)
    d.mkdir(parents=True, exist_ok=True)
    sk_path, kex_path = d / SIGNING_KEY_FILE, d / KEX_KEY_FILE

    if sk_path.exists():
        signing = primitives.unb64u(sk_path.read_text(encoding="utf-8").strip())
    else:
        signing, _ = primitives.generate_signing_key()
        _write_private(sk_path, signing)

    if kex_path.exists():
        kex = primitives.unb64u(kex_path.read_text(encoding="utf-8").strip())
    else:
        kex, _ = primitives.generate_kex_key()
        _write_private(kex_path, kex)

    return signing, kex


def store_credential(actor: str, credential: bytes, base: Path | None = None) -> Path:
    path = actor_dir(actor, base) / CREDENTIAL_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(credential)
    return path


def load_identity(actor: str, base: Path | None = None) -> Identity:
    d = actor_dir(actor, base)
    cred_path = d / CREDENTIAL_FILE
    if not cred_path.exists():
        raise FileNotFoundError(
            f"No credential for {actor} at {cred_path}. "
            f"Run scripts/provision.py to issue one.")
    signing, kex = ensure_keys(actor, base)
    return Identity(name=actor, credential=cred_path.read_bytes(),
                    signing_key=signing, kex_secret=kex)


def issue_for(actor: str, *, issuer: str, issuer_signing_key: bytes,
              roles, not_before: datetime, not_after: datetime,
              sector: str | None = None, base: Path | None = None) -> bytes:
    """Generate or reuse the actor's keys, then issue and store a credential."""
    signing, _ = ensure_keys(actor, base)
    verify_key = primitives.public_signing_key(signing)
    credential = credentials.issue(
        issuer=issuer, subject=actor, verify_key=verify_key,
        not_before=not_before, not_after=not_after,
        permitted_roles=tuple(roles), issuer_signing_key=issuer_signing_key,
        sector=sector,
    )
    store_credential(actor, credential, base)
    return credential


def _write_private(path: Path, raw: bytes) -> None:
    path.write_text(primitives.b64u(raw) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
