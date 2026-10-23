"""
Reading the scenario files, which predate this protocol.

A scenario is a flight: a list of SA rows and a list of CC rows on a clock
starting at 00:00:00. The rows were written for the earlier design, where one
process published both sides of every exchange, so a little translation is
needed:

  * KEY rows are dropped. Session establishment is the protocol's business
    now, and happens when the aircraft decides to talk to a station.
  * ACK rows are dropped. An acknowledgement is produced by the aircraft on
    acting, and carries the next challenge; a scripted one would be a second,
    unbound copy.
  * CONTACT rows become nominations issued by the station the aircraft is
    with, which is where a transfer of control starts (Section 3.3.4). The
    first one has no incumbent and is simply where the flight begins.
  * everything else is routed by its `frm`: what the aircraft says it sends,
    the aircraft sends; what a station sends, that station sends.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Scenario cc_type -> protocol role, for messages a ground station sends.
GROUND_ROLE = {
    "CLEARANCE": "CC:CLEARANCE",
    "INSTRUCTION": "CC:INSTRUCTION",
    "REPORT": "CC:INSTRUCTION",
    "CONTACT": "CC:CONTACT",
    "EMERGENCY": "CC:EMERGENCY",
    "SYSTEM": "CC:SYSTEM",
}

#: ... and for messages an aircraft sends.
AIRCRAFT_ROLE = {
    "REQUEST": "CC:REQUEST",
    "REPORT": "CC:REQUEST",
    "EMERGENCY": "CC:EMERGENCY",
    "SYSTEM": "CC:SYSTEM",
}

DROP = {"KEY", "ACK"}


def canonical(name: str) -> str:
    """Scenario names use underscores; credentials use spaces."""
    return (name or "").replace("_", " ").strip()


def _seconds(hhmmss: str) -> float:
    h, m, s = (hhmmss or "00:00:00").split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def aircraft_id(scenario: dict) -> str:
    return canonical(scenario.get("flight", {}).get("aircraft_id", ""))


def stations_in_order(scenario: dict) -> list[tuple[float, str]]:
    """
    (time, station) for each CONTACT row: the sequence of controlling
    stations the flight passes through.
    """
    out = []
    for e in scenario.get("events", []):
        if e.get("type") == "CC" and e.get("cc_type") == "CONTACT":
            out.append((_seconds(e.get("t")), canonical(e.get("to"))))
    return out


def load_aircraft_script(path: str | Path) -> tuple[str, list, list[tuple[float, str]]]:
    """
    Return (aircraft_id, events, handovers).

    `events` are (time, kind, payload): ("SA", state dict) or ("CC", role,
    instruction) for the messages the aircraft itself originates.
    """
    sc = load(path)
    me = aircraft_id(sc)
    events: list[tuple] = []
    for e in sc.get("events", []):
        t = _seconds(e.get("t"))
        if e.get("type") == "SA":
            events.append((t, "SA", {
                "altitude": _fmt(e.get("alt_ft")),
                "alt_ref": "BARO_QNH",
                "position": f"{e.get('lat')} LAT {e.get('lon')} LONG",
                "speed": _fmt(e.get("gs_kt")),
                "heading": _fmt(e.get("hdg_deg")),
                "on_ground": str(int(e.get("on_ground") or 0)),
            }))
            continue
        if e.get("type") != "CC":
            continue
        kind = (e.get("cc_type") or "").upper()
        if kind in DROP or kind == "CONTACT":
            continue
        if canonical(e.get("frm")) != me:
            continue
        role = AIRCRAFT_ROLE.get(kind)
        if role:
            events.append((t, "CC", role, e.get("body") or ""))
    events.sort(key=lambda r: r[0])
    return me, events, stations_in_order(sc)


def load_station_script(path: str | Path, station: str) -> list[tuple]:
    """
    Return (time, role, instruction, aircraft) for this station.

    A CONTACT row becomes the pseudo-role NOMINATE for the station the
    aircraft is leaving, since a nomination is issued by the incumbent.
    """
    sc = load(path)
    me = canonical(station)
    aircraft = aircraft_id(sc)
    sequence = stations_in_order(sc)
    out: list[tuple] = []

    for e in sc.get("events", []):
        if e.get("type") != "CC":
            continue
        kind = (e.get("cc_type") or "").upper()
        t = _seconds(e.get("t"))

        if kind == "CONTACT":
            successor = canonical(e.get("to"))
            incumbent = _incumbent_before(sequence, t)
            if incumbent == me and successor != me:
                out.append((t, "NOMINATE", successor, aircraft))
            continue

        if kind in DROP:
            continue
        if canonical(e.get("frm")) != me:
            continue
        role = GROUND_ROLE.get(kind)
        if role:
            out.append((t, role, e.get("body") or "", aircraft))

    out.sort(key=lambda r: r[0])
    return out


def _incumbent_before(sequence: list[tuple[float, str]], t: float) -> str | None:
    """Which station held the aircraft immediately before time `t`."""
    held = None
    for when, station in sequence:
        if when >= t:
            break
        held = station
    return held


def _fmt(value) -> str:
    if value is None:
        return "0"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)
