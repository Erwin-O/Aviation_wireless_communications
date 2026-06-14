#!/usr/bin/env python3
"""
Add or update an actor (aircraft / tower / etc.) with fresh keypairs.

Private keys are stored locally under ~/AviationLocalKeys/<ACTOR_ID>/
  * ed25519_private.key   (URL-safe Base64, raw 32-byte secret key)
  * x25519_private.key    (URL-safe Base64, raw 32-byte secret key)

Public keys are written to config/publicKeys.json:
  {
    "schema_version": 1,
    "actors": {
      "<ACTOR_ID>": {
        "type": "<actor_type>",
        "pubkey_ed25519": "<base64url 32 bytes>",
        "pubkey_x25519":  "<base64url 32 bytes>"
      }
    }
  }

Examples:
  python3 scripts/add_actor.py add PHAEX   aircraft
  python3 scripts/add_actor.py add EHAM_TWR tower
  python3 scripts/add_actor.py add EHAA_CTR enroute
  python3 scripts/add_actor.py list
"""
import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from encryption.crypto import bytes_to_b64u

REPO_ROOT   = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPO_ROOT / "config" / "publicKeys.json"
LOCAL_KEY_DIR = Path.home() / "AviationLocalKeys"

VALID_TYPES = {"aircraft", "tower", "atc", "enroute", "uav", "ground", "test"}

_RAW     = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRV = serialization.PrivateFormat.Raw
_NO_ENC  = serialization.NoEncryption()


def _generate_keys() -> tuple[bytes, bytes, bytes, bytes]:
    """Return (ed25519_priv, ed25519_pub, x25519_priv, x25519_pub) as raw 32-byte values."""
    ed = Ed25519PrivateKey.generate()
    x  = X25519PrivateKey.generate()
    return (
        ed.private_bytes(_RAW, _RAW_PRV, _NO_ENC),
        ed.public_key().public_bytes(_RAW, _RAW_PUB),
        x.private_bytes(_RAW, _RAW_PRV, _NO_ENC),
        x.public_key().public_bytes(_RAW, _RAW_PUB),
    )


def _save_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent)) as tmp:
        tmp.write(text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def _save_private_key(path: Path, raw_bytes: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _save_text_atomic(path, bytes_to_b64u(raw_bytes))
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                print(f"[ERROR] {CONFIG_PATH} is not valid JSON: {e}", file=sys.stderr)
                sys.exit(2)
    return {"schema_version": 1, "actors": {}}


def _write_config(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        shutil.copy2(CONFIG_PATH, CONFIG_PATH.with_suffix(".json.bak"))
    _save_text_atomic(CONFIG_PATH, json.dumps(cfg, indent=2, ensure_ascii=False))


def _validate_actor_id(actor_id: str) -> str:
    if not actor_id or not actor_id.strip():
        raise ValueError("actor_id must be non-empty")
    cleaned = actor_id.strip().upper()
    for ch in cleaned:
        if not (ch.isalnum() or ch in "-_"):
            raise ValueError("actor_id may only contain A–Z, 0–9, '-' or '_'")
    return cleaned


def _validate_type(actor_type: str) -> str:
    t = actor_type.strip().lower()
    if t not in VALID_TYPES:
        raise ValueError(f"actor_type must be one of: {', '.join(sorted(VALID_TYPES))}")
    return t


def add_or_update_actor(actor_id: str, actor_type: str, overwrite: bool) -> None:
    actor_id   = _validate_actor_id(actor_id)
    actor_type = _validate_type(actor_type)

    cfg    = _load_config()
    actors = cfg.setdefault("actors", {})

    if actor_id in actors and not overwrite:
        print(f"[ERROR] Actor '{actor_id}' already exists. Use --overwrite to replace.", file=sys.stderr)
        sys.exit(3)

    ed_priv, ed_pub, x_priv, x_pub = _generate_keys()

    base = LOCAL_KEY_DIR / actor_id
    _save_private_key(base / "ed25519_private.key", ed_priv)
    _save_private_key(base / "x25519_private.key",  x_priv)

    actors[actor_id] = {
        "type":           actor_type,
        "pubkey_ed25519": bytes_to_b64u(ed_pub),
        "pubkey_x25519":  bytes_to_b64u(x_pub),
    }

    _write_config(cfg)
    print(f"[OK] Added/updated actor '{actor_id}' (type={actor_type})")
    print(f"  Private keys : {base}")
    print(f"  Public keys  : {CONFIG_PATH}")


def list_actors() -> None:
    actors = _load_config().get("actors", {})
    if not actors:
        print("(no actors registered)")
        return
    print(f"{'ID':<12} {'TYPE':<10} {'ED25519 (pub)':<48} {'X25519 (pub)':<48}")
    print("-" * 124)
    for aid, meta in sorted(actors.items()):
        print(f"{aid:<12} {meta.get('type','?'):<10} "
              f"{meta.get('pubkey_ed25519',''):<48} "
              f"{meta.get('pubkey_x25519',''):<48}")


def main() -> None:
    ap  = argparse.ArgumentParser(description="Add/update an actor and manage the public key registry.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_add = sub.add_parser("add", help="Add or update an actor")
    ap_add.add_argument("actor_id",   help="Actor ID (e.g. OOABC, EHAM_TWR)")
    ap_add.add_argument("actor_type", help=f"Actor type: {', '.join(sorted(VALID_TYPES))}")
    ap_add.add_argument("--overwrite", action="store_true", help="Overwrite existing entry")

    sub.add_parser("list", help="List all actors in the registry")

    args = ap.parse_args()
    if args.cmd == "add":
        add_or_update_actor(args.actor_id, args.actor_type, args.overwrite)
    elif args.cmd == "list":
        list_actors()


if __name__ == "__main__":
    main()
