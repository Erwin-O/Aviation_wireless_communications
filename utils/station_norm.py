# utils/station_norm.py
from __future__ import annotations
from typing import Dict, Tuple
from .registry import load_airports_db, _norm_space

_SUFFIX_CANON = {
    "GND": "GND", "GROUND": "GND",
    "TWR": "TWR", "TOWER": "TWR",
    "APP": "APP", "APPR": "APP", "APPROACH": "APP",
    "ACC": "ACC", "CONTROL": "ACC",
    "DEL": "DEL", "DELIVERY": "DEL",
    "ATIS": "ATIS",
}

def _build_enroute_index(db) -> Dict[str, str]:
    idx: Dict[str, str] = {}
    for u in db.get("enroute_units", []):
        name = _norm_space(u.get("name", ""))
        cs   = _norm_space(u.get("callsign", ""))
        if "MAASTRICHT" in name or "MUAC" in name or "MAASTRICHT" in cs or "MUAC" in cs:
            canon = "MUAC"
        elif "LANGEN" in name or "LANGEN" in cs:
            canon = "LANGEN"
        elif "BRUSSELS" in name or "BRUSSELS" in cs:
            canon = "BRUACC"
        else:
            base = (cs or name).split(" ")[0]
            canon = f"{base}_ACC" if base else "ACC"
        if name: idx[name] = canon
        if cs:   idx[cs]   = canon
    return idx

def _extract_airport_and_suffix(tokens: Tuple[str, ...]) -> Tuple[str, str]:
    db = load_airports_db()
    icaos = {a["icao"].upper(): True for a in db.get("airports", [])}
    seen_icao, seen_sfx = "", ""
    for t in tokens:
        if t in _SUFFIX_CANON:
            seen_sfx = _SUFFIX_CANON[t]
        if len(t) == 4 and t.isalpha() and t in icaos:
            seen_icao = t
    return seen_icao, seen_sfx

def pretty_station(name: str) -> str:
    """Human-readable station label for display only. Never use for internal addressing."""
    return name.replace("_", " ")


def normalise_station(name: str) -> str:
    """DB-backed normaliser, no hard-coded aliases."""
    if not name:
        return ""

    raw = _norm_space(name)
    tokens = tuple(raw.split())
    en_idx = _build_enroute_index(load_airports_db())
    if raw in en_idx:
        return en_idx[raw]

    icao, sfx = _extract_airport_and_suffix(tokens)
    if icao and sfx:
        return f"{icao}_{sfx}"

    db = load_airports_db()
    for ap in db.get("airports", []):
        ap_name = _norm_space(ap.get("name", ""))
        if raw.startswith(ap_name + " "):
            rest = raw[len(ap_name):].strip().split()
            maybe_sfx = rest[-1] if rest else ""
            if maybe_sfx in _SUFFIX_CANON:
                return f"{ap['icao'].upper()}_{_SUFFIX_CANON[maybe_sfx]}"

    if icao:
        return icao

    return raw.replace(" ", "_")

# --- CLI tester (append at the very end of utils/station_norm.py) ---
if __name__ == "__main__":
    import argparse
    from .registry import CONFIG_DIR, load_airports_db  # reuse cache to ensure file is readable

    parser = argparse.ArgumentParser(
        description="Normalize ATC station names using DB-backed logic."
    )
    parser.add_argument(
        "names",
        nargs="+",
        help='Station names to normalize, e.g. "EBBR GND", "Brussels Ground", "Langen Radar"',
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Print the config directory used (for quick sanity checking).",
    )
    parser.add_argument(
        "--echo-raw",
        action="store_true",
        help="Also print the raw input alongside the normalized value.",
    )
    args = parser.parse_args()

    # Force-load once to surface path issues early
    try:
        _ = load_airports_db()
    except Exception as e:
        print(f"[ERROR] Could not load airports_db.json from {CONFIG_DIR}: {e}")
        raise SystemExit(2)

    if args.show_config:
        print(f"[INFO] Using config dir: {CONFIG_DIR}")

    for name in args.names:
        norm = normalise_station(name)
        if args.echo_raw:
            print(f"{name!r} -> {norm}")
        else:
            print(norm)