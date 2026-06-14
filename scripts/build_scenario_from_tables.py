#!/usr/bin/env python3
"""
build_scenario_from_tables.py

Build a scenario JSON (used by scripts/scenario_player.py) from two CSV files:
  - a Situational Awareness (SA) table (position reports)
  - a Command & Control (CC) table (ATC instructions/requests/acks/etc.)

This script is designed to be run from the repo root like:

  python3 scripts/build_scenario_from_tables.py \
    --sa scenarios/commercial_flight_EBBR-EDDF_SA.csv \
    --cc scenarios/commercial_flight_EBBR-EDDF_CC.csv \
    --out scenarios/commercial_flight_EBBR-EDDF.json \
    --aircraft OOABC \
    --station "EBBR GND"

Notes:
- Your SA CSV commonly uses delimiter ';' and CC uses delimiter ','.
  The script auto-detects delimiters, but you can force them via:
      --sa-delim ';'  --cc-delim ','
- Column name matching is flexible. Examples it accepts:

  SA columns (typical):
    Time ; Lat ; Long ; Speed ; Heading ; Altitude ; On ground ; To(optional)
    e.g. "10:39:54" or "2026-02-19T10:39:54+00:00" in Time

  CC columns (typical):
    Time,From,To,Type,Body
    e.g. "10:43:10","LANGEN","OOABC","INSTRUCTION","CONTACT EDDF APPR"

- Output JSON format matches scenario_player.py expectations:
    {
      "flight": { "aircraft_id": "...", "initial_station": "...", ... },
      "events": [
        {"t":"10:39:54","type":"SA", ...},
        {"t":"10:43:10","type":"CC", ...},
        ...
      ]
    }

If scenario_player.py throws KeyError: 'flight', it means the JSON does not contain
the expected top-level "flight" object. This script always writes it.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ----------------------------
# Helpers: delimiter detection
# ----------------------------
def detect_delimiter(path: Path, fallback: str = ",") -> str:
    try:
        sample = path.read_text(encoding="utf-8-sig", errors="replace")[:4096]
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        return fallback


# ----------------------------
# Helpers: normalisation
# ----------------------------
def norm_key(k: str) -> str:
    """
    Normalise header keys so we can match columns reliably:
      - strips whitespace
      - strips UTF-8 BOM if present
      - lowercases
      - replaces spaces with underscores
    """
    if k is None:
        return ""
    k = k.replace("\ufeff", "")  # BOM-safe
    k = k.strip().lower()
    k = re.sub(r"\s+", "_", k)
    return k


def norm_val(v: Any) -> str:
    """
    DictReader can return a list for "restkey" extra columns.
    Convert everything to a clean string.
    """
    if v is None:
        return ""
    if isinstance(v, list):
        # Join extra columns safely
        return " ".join(str(x) for x in v if x is not None).strip()
    return str(v).strip()


def extract_hhmmss(s: str) -> str:
    """
    Accept:
      - "HH:MM:SS"
      - "HH:MM"
      - ISO timestamps like "2026-02-19T10:39:54+00:00"
    Return: "HH:MM:SS"
    """
    s = (s or "").strip()
    if not s:
        return ""

    # ISO: grab time after 'T'
    if "T" in s:
        # 2026-02-19T10:39:54+00:00
        t = s.split("T", 1)[1]
        # remove timezone suffix if present
        t = re.split(r"[Z\+\-]", t, maxsplit=1)[0]
        s = t.strip()

    # HH:MM:SS
    m = re.match(r"^(\d{1,2}):(\d{2})(?::(\d{2}))?$", s)
    if not m:
        return ""

    hh = int(m.group(1))
    mm = int(m.group(2))
    ss = int(m.group(3) or 0)
    return f"{hh:02d}:{mm:02d}:{ss:02d}"


def to_float(s: str) -> Optional[float]:
    s = (s or "").strip()
    if not s:
        return None
    # tolerate comma decimals just in case
    s = s.replace(",", ".")
    try:
        return float(s)
    except Exception:
        return None


def to_int(s: str) -> Optional[int]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def to_bool01(s: str) -> Optional[int]:
    s = (s or "").strip().lower()
    if s == "":
        return None
    if s in ("1", "true", "yes", "y"):
        return 1
    if s in ("0", "false", "no", "n"):
        return 0
    # Some SA tables say "on ground" / "airborne" etc.
    if "ground" in s:
        return 1
    if "air" in s:
        return 0
    return None


# ----------------------------
# CSV reading (robust)
# ----------------------------
def read_csv_rows(path: Path, delimiter: Optional[str] = None) -> List[Dict[str, str]]:
    if delimiter is None:
        delimiter = detect_delimiter(path)

    rows: List[Dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.DictReader(f, delimiter=delimiter, restkey="_extra")
        for r in reader:
            out: Dict[str, str] = {}
            for k, v in (r or {}).items():
                nk = norm_key(k or "")
                out[nk] = norm_val(v)
            rows.append(out)
    return rows


def pick(row: Dict[str, str], *keys: str) -> str:
    for k in keys:
        kk = norm_key(k)
        if kk in row and row[kk] != "":
            return row[kk]
    return ""


# ----------------------------
# Scenario building
# ----------------------------
def build_sa_events(sa_rows: List[Dict[str, str]], aircraft_id: str, default_to: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for i, r in enumerate(sa_rows, start=1):
        ts_raw = pick(r, "timestamp", "time", "ts", "t", "datetime")
        ts = extract_hhmmss(ts_raw)
        if not ts:
            # Fail fast with helpful info
            raise ValueError(
                f"SA row {i} missing usable time column. "
                f"Looked for: timestamp/time/ts/t/datetime. "
                f"Row keys: {sorted(r.keys())[:25]}"
            )

        lat = to_float(pick(r, "lat", "latitude"))
        lon = to_float(pick(r, "lon", "long", "longitude"))
        gs = to_float(pick(r, "speed", "gs", "groundspeed", "gs_kt", "spd"))
        hdg = to_float(pick(r, "heading", "hdg", "track"))
        alt = to_float(pick(r, "altitude", "alt", "alt_ft", "altitude_ft"))
        on_ground = to_bool01(pick(r, "on_ground", "onground", "on_ground_flag", "on_ground?", "on_ground_1_0", "on_ground_01", "on_ground_bool", "on_ground_value", "on_ground_status", "on_ground_state", "on_ground_ind", "on_ground_indicator", "on_ground_column", "on_ground_field", "on_ground_val", "on_ground_str", "on_ground_text", "on_ground_int", "on_ground_num", "on_ground_number", "on_ground_binary", "on_ground_bit", "on_ground_bool01", "on_ground_bool_01", "on_ground_0_1", "on_ground_0or1", "on_ground_0_1_flag", "on_ground_0_1_value", "on_ground_0_1_status", "on_ground_0_1_state", "on_ground_0_1_ind", "on_ground_0_1_indicator", "on_ground_0_1_column", "on_ground_0_1_field", "on_ground_0_1_val", "on_ground_0_1_str", "on_ground_0_1_text", "on_ground_0_1_int", "on_ground_0_1_num", "on_ground_0_1_number", "on_ground_0_1_binary", "on_ground_0_1_bit", "on_ground_0_1_bool01"))

        # Some tables store "On ground" as "on ground"
        if on_ground is None:
            on_ground = to_bool01(pick(r, "on_ground", "on_ground", "on_ground", "on_ground", "on_ground", "on_ground", "on_ground", "on_ground", "on_ground"))
        if on_ground is None:
            on_ground = to_bool01(pick(r, "on_ground", "on_ground", "on_ground"))

        # More likely your column is literally "on_ground" after normalisation of "On ground"
        if on_ground is None:
            on_ground = to_bool01(pick(r, "on_ground", "on_ground", "on_ground", "on_ground"))

        # Final: handle your exact header "On ground" -> "on_ground"
        if on_ground is None:
            on_ground = to_bool01(pick(r, "on_ground", "on_ground"))

        e: Dict[str, Any] = {
            "type": "SA",
            "t": ts,
            "frm": aircraft_id,
        }
        if alt is not None:
            e["alt_ft"] = alt
        if lat is not None:
            e["lat"] = lat
        if lon is not None:
            e["lon"] = lon
        if gs is not None:
            e["gs_kt"] = gs
        if hdg is not None:
            e["hdg_deg"] = hdg
        if on_ground is not None:
            e["on_ground"] = int(on_ground)

        events.append(e)

    return events


def build_cc_events(cc_rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for i, r in enumerate(cc_rows, start=1):
        ts_raw = pick(r, "timestamp", "time", "ts", "t", "datetime")
        ts = extract_hhmmss(ts_raw)
        if not ts:
            raise ValueError(
                f"CC row {i} missing usable time column. "
                f"Looked for: timestamp/time/ts/t/datetime. "
                f"Row keys: {sorted(r.keys())[:25]}"
            )

        frm = pick(r, "from", "frm", "sender")
        to = pick(r, "to", "dest", "receiver")
        ctype = pick(r, "type", "cc_type", "msg_type", "category")
        body = pick(r, "body", "text", "message", "content")

        if not frm or not to:
            raise ValueError(f"CC row {i} missing from/to. Row={r}")

        events.append(
            {
                "type": "CC",
                "t": ts,
                "frm": frm,
                "to": to,
                "cc_type": ctype or "UNKNOWN",
                "body": body or "",
            }
        )

    return events


def parse_ts_to_seconds(ts: str) -> int:
    # ts is "HH:MM:SS"
    hh, mm, ss = ts.split(":")
    return int(hh) * 3600 + int(mm) * 60 + int(ss)


def build_scenario(
    sa_csv: Path,
    cc_csv: Path,
    out_json: Path,
    aircraft_id: str,
    initial_station_human: str,
    sa_delim: Optional[str] = None,
    cc_delim: Optional[str] = None,
) -> Tuple[Dict[str, Any], int, int, int]:
    sa_rows = read_csv_rows(sa_csv, delimiter=sa_delim)
    cc_rows = read_csv_rows(cc_csv, delimiter=cc_delim)

    sa_events = build_sa_events(sa_rows, aircraft_id=aircraft_id, default_to=initial_station_human)
    cc_events = build_cc_events(cc_rows)

    events = sa_events + cc_events
    # Sort by time-of-day
    events.sort(key=lambda e: parse_ts_to_seconds(e["t"]))

    scenario: Dict[str, Any] = {
        "schema_version": 1,
        "flight": {
            "aircraft_id": aircraft_id,
            "initial_station": initial_station_human,
            # Optional fields that help humans/debuggers
            "sa_rows": len(sa_rows),
            "cc_rows": len(cc_rows),
        },
        "events": events,
    }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(scenario, indent=2), encoding="utf-8")
    return scenario, len(sa_rows), len(cc_rows), len(events)


# ----------------------------
# CLI
# ----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Build scenario JSON from SA/CC CSV tables.")
    ap.add_argument("--sa", required=True, help="Path to SA CSV (e.g., scenarios/..._SA.csv)")
    ap.add_argument("--cc", required=True, help="Path to CC CSV (e.g., scenarios/..._CC.csv)")
    ap.add_argument("--out", required=True, help="Output JSON path (e.g., scenarios/...json)")
    ap.add_argument("--aircraft", required=True, help="Aircraft ID (e.g., OOABC)")
    ap.add_argument("--station", required=True, help='Initial station (human format, e.g. "EBBR GND")')
    ap.add_argument("--sa-delim", default=None, help="Force SA delimiter (e.g. ';')")
    ap.add_argument("--cc-delim", default=None, help="Force CC delimiter (e.g. ',')")

    args = ap.parse_args()

    sa_path = Path(args.sa)
    cc_path = Path(args.cc)
    out_path = Path(args.out)

    scenario, n_sa, n_cc, n_events = build_scenario(
        sa_csv=sa_path,
        cc_csv=cc_path,
        out_json=out_path,
        aircraft_id=args.aircraft,
        initial_station_human=args.station,
        sa_delim=args.sa_delim,
        cc_delim=args.cc_delim,
    )

    print(f"[OK] SA rows: {n_sa}")
    print(f"[OK] CC rows: {n_cc}")
    print(f"[OK] Events written: {n_events}")
    print(f"[OK] Output: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
