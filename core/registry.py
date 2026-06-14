# core/registry.py
"""
Public and private key lookup for all actors (aircraft and ATC stations).

Public keys are read from config/publicKeys.json.
Private keys are read from ~/AviationLocalKeys/<ACTOR_ID>/.
"""
import json
import re
from pathlib import Path
from typing import Tuple

from encryption.crypto import b64u_to_bytes, bytes_to_b64u

REPO_ROOT = Path(__file__).resolve().parents[1]
REG_PATH  = REPO_ROOT / "config" / "publicKeys.json"
LOCAL_DIR = Path.home() / "AviationLocalKeys"


def _norm(actor_id: str) -> str:
    """Normalise an actor ID for registry lookups and local key paths."""
    return re.sub(r"[\s/]+", "_", (actor_id or "").strip().upper())


def _load_registry() -> dict:
    if not REG_PATH.exists():
        raise FileNotFoundError(f"Public key registry not found: {REG_PATH}")
    with REG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_pubkeys(actor_id: str) -> Tuple[bytes, bytes]:
    """Return (ed25519_pub, x25519_pub) as raw 32-byte values for the actor."""
    actor_id = _norm(actor_id)
    reg = _load_registry()
    meta = reg.get("actors", {}).get(actor_id)
    if not meta:
        raise KeyError(f"Actor '{actor_id}' not found in {REG_PATH}")
    return b64u_to_bytes(meta["pubkey_ed25519"]), b64u_to_bytes(meta["pubkey_x25519"])


def load_private_keys(actor_id: str) -> Tuple[bytes, bytes]:
    """Return (ed25519_priv, x25519_priv) as raw 32-byte values for the actor."""
    actor_id = _norm(actor_id)
    base = LOCAL_DIR / actor_id
    ed_path = base / "ed25519_private.key"
    x2_path = base / "x25519_private.key"
    if not ed_path.exists() or not x2_path.exists():
        raise FileNotFoundError(f"Missing private keys under {base}")

    def _read(p: Path) -> bytes:
        s = p.read_text(encoding="utf-8").strip()
        return b64u_to_bytes(s)

    return _read(ed_path), _read(x2_path)
