# station_keys.py
"""
Load station private keys (Ed25519 + X25519) with maximum compatibility.

Search order (first hit wins):
1) Explicit env dir:
   $AVIATION_KEYS_DIR/<STATION>/ed25519_private.key
   $AVIATION_KEYS_DIR/<STATION>/x25519_private.key

2) Default local dir:
   ~/AviationLocalKeys/<STATION>/ed25519_private.key
   ~/AviationLocalKeys/<STATION>/x25519_private.key

3) Project local dir (repo-relative):
   <REPO>/AviationLocalKeys/<STATION>/ed25519_private.key
   <REPO>/AviationLocalKeys/<STATION>/x25519_private.key

4) Legacy flat filenames (if someone previously used these):
   <dir>/ed25519_<STATION>.b64
   <dir>/x25519_<STATION>.b64

5) Very old CSV fallbacks (NOT recommended, but kept for continuity):
   <dir>/privateKeys.csv  # expects station_id, ed25519_priv_b64, x25519_priv_b64
   <dir>/private_keys.csv

All files are assumed to contain a single line of URL-safe Base64 for a 32-byte private key.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Optional, Tuple

from encryption.crypto import b64u_to_bytes as _b64u_to_bytes


def _read_key_file(path: Path, *, expect_len: int = 32) -> Optional[bytes]:
    if not path.exists():
        return None
    data = path.read_text(encoding="utf-8").strip()
    if not data:
        return None
    try:
        raw = _b64u_to_bytes(data)
    except Exception:
        return None
    if expect_len and len(raw) != expect_len:
        # Some generators export 64-byte Ed25519 "expanded" keys. We only accept 32.
        return None
    return raw


def _candidate_dirs(repo_root: Path) -> list[Path]:
    dirs = []
    # 1) Env override
    env_dir = os.environ.get("AVIATION_KEYS_DIR")
    if env_dir:
        dirs.append(Path(env_dir).expanduser())

    # 2) Default user dir
    dirs.append(Path("~").expanduser() / "AviationLocalKeys")

    # 3) Project dir
    dirs.append(repo_root / "AviationLocalKeys")

    # 4) config (for legacy CSV)
    dirs.append(repo_root / "config")

    # de-duplicate while preserving order
    seen: set = set()
    unique = []
    for d in dirs:
        p = d.resolve()
        if p not in seen:
            seen.add(p)
            unique.append(d)
    return unique


def _normalise_station_id(station_id: str) -> str:
    """Accept both 'EBBR GND' and 'EBBR_GND' and map to the directory name form."""
    sid = station_id.strip()
    if " " in sid and "_" not in sid:
        sid = sid.replace(" ", "_")
    return sid


# ---------- main API ----------

def get_priv_for_station(station_id: str) -> Tuple[bytes, bytes]:
    """
    Return (ed25519_priv, x25519_priv) as raw 32-byte values for the station.

    Raises FileNotFoundError with a diagnostic message if no keys are found.
    """
    repo_root = Path(__file__).resolve().parent
    sid = _normalise_station_id(station_id)

    tried_paths: list[Path] = []

    # 1–3) Modern per-station directory layouts
    for base in _candidate_dirs(repo_root):
        station_dir = base / sid
        ed_path = station_dir / "ed25519_private.key"
        x_path = station_dir / "x25519_private.key"

        tried_paths += [ed_path, x_path]

        ed = _read_key_file(ed_path)
        xk = _read_key_file(x_path)
        if ed is not None and xk is not None:
            return ed, xk

    # 4) Legacy flat .b64 files
    for base in _candidate_dirs(repo_root):
        ed_path = base / f"ed25519_{sid}.b64"
        x_path = base / f"x25519_{sid}.b64"
        tried_paths += [ed_path, x_path]

        ed = _read_key_file(ed_path)
        xk = _read_key_file(x_path)
        if ed is not None and xk is not None:
            return ed, xk

    # 5) Very old CSV fallback (3-column: station_id, ed25519_priv_b64, x25519_priv_b64)
    for base in _candidate_dirs(repo_root):
        for csv_name in ("privateKeys.csv", "private_keys.csv"):
            csv_path = base / csv_name
            tried_paths.append(csv_path)
            if not csv_path.exists():
                continue
            try:
                with csv_path.open("r", encoding="utf-8") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        row = [c.strip() for c in row]
                        if not row or row[0].startswith("#") or len(row) < 3:
                            continue
                        sid_csv, ed_b64, x_b64 = row[0], row[1], row[2]
                        if _normalise_station_id(sid_csv) != sid:
                            continue
                        ed = _b64u_to_bytes(ed_b64)
                        xk = _b64u_to_bytes(x_b64)
                        if len(ed) == 32 and len(xk) == 32:
                            return ed, xk
            except Exception:
                pass

    msg_lines = [
        f"Private keys not found for '{sid}'.",
        "Tried the following paths:",
    ] + [f"  - {p}" for p in tried_paths] + [
        "Expected files with URL-safe Base64 (no newlines), 32 bytes after decoding.",
        "Preferred layout: <AviationLocalKeys>/<STATION>/ed25519_private.key and x25519_private.key",
    ]
    raise FileNotFoundError("\n".join(msg_lines))


if __name__ == "__main__":
    import sys
    st = sys.argv[1] if len(sys.argv) > 1 else "EBBR_GND"
    try:
        ed, xk = get_priv_for_station(st)
        print(f"[OK] Loaded keys for {st}: ed25519={len(ed)} bytes, x25519={len(xk)} bytes")
    except Exception as e:
        print(f"[FAIL] {e}")
