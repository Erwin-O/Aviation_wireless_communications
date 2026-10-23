#!/usr/bin/env python3
"""
Issue credentials for the demo population.

Creates an issuing authority if there is none, then issues one credential per
principal: the aircraft of the scenarios and the ground stations the listeners
run for. Existing key material under ~/AviationLocalKeys is reused, so this is
safe to re-run and does not invalidate anything already provisioned.

What ends up shared is config/trust_anchors.json, which names issuers and
their public keys. No principal's key is published anywhere: a credential
travels with the messages that use it.

    python3 scripts/provision.py                 # issue everything
    python3 scripts/provision.py --days 30       # a longer validity window
    python3 scripts/provision.py --list          # show what exists
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import credentials, identity, primitives  # noqa: E402

ISSUER = "BE CAA"

#: What an aircraft may send. Handshake roles are not operational acts and are
#: not subject to role admission, but a credential still has to list what the
#: holder does once a session exists.
AIRCRAFT_ROLES = (
    "KEY", "KEYCONFIRM", "SA", "ACK",
    "CC:REQUEST", "CC:EMERGENCY", "CC:SYSTEM",
)

#: What a controlling station may send. CC:CONTACT is here because a station
#: nominates its successor; a station that should not hand over would not
#: carry it.
GROUND_ROLES = (
    "KEYACK",
    "CC:CLEARANCE", "CC:INSTRUCTION", "CC:CONTACT",
    "CC:EMERGENCY", "CC:SYSTEM",
)

#: The stations the listeners run for, with the airspace each is authorised to
#: control. The sector is what Section 5.3 calls a ground-side obligation: a
#: station admits an aircraft only where its own credential covers the
#: airspace the aircraft reports.
STATIONS = {
    "EBBR GND": "EBBU.EBBR",
    "EBBR TWR": "EBBU.EBBR",
    "BRUACC": "EBBU",
    "LANGEN": "EDGG",
    "EDDF APP": "EDGG.EDDF",
    "EDDF TWR": "EDGG.EDDF",
    "EDDF GND": "EDGG.EDDF",
    "EHAM TWR": "EHAA.EHAM",
    "EHAM APP": "EHAA.EHAM",
    "EHAA CTR": "EHAA",
    "EDGG CTR": "EDGG",
    "EDMM CTR": "EDMM",
    "EDDM APP": "EDMM.EDDM",
    "EDDM TWR": "EDMM.EDDM",
}

AIRCRAFT = ("OOABC", "PHAEX")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=7,
                    help="validity window in days (default: 7)")
    ap.add_argument("--issuer", default=ISSUER, help=f"issuer name (default: {ISSUER})")
    ap.add_argument("--list", action="store_true",
                    help="show what is provisioned and exit")
    args = ap.parse_args()

    if args.list:
        return _show()

    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=5)   # tolerate a little clock skew
    not_after = now + timedelta(days=args.days)

    # The authority. Its signing key lives beside everyone else's, which is a
    # convenience of the demo and not a property of the design.
    ca_signing, _ = identity.ensure_keys(args.issuer)
    ca_public = primitives.public_signing_key(ca_signing)
    identity.add_trust_anchor(args.issuer, ca_public)
    print(f"issuer   {args.issuer}  anchor {primitives.b64u(ca_public)[:16]}…")
    print(f"          -> {identity.ANCHORS_PATH}")

    issued = 0
    for name in AIRCRAFT:
        identity.issue_for(name, issuer=args.issuer, issuer_signing_key=ca_signing,
                           roles=AIRCRAFT_ROLES, not_before=not_before,
                           not_after=not_after)
        print(f"aircraft {name}")
        issued += 1

    for name, sector in STATIONS.items():
        identity.issue_for(name, issuer=args.issuer, issuer_signing_key=ca_signing,
                           roles=GROUND_ROLES, not_before=not_before,
                           not_after=not_after, sector=sector)
        print(f"station  {name:10s} sector {sector}")
        issued += 1

    print(f"\n{issued} credentials, valid until {not_after:%Y-%m-%d %H:%M} UTC")
    print(f"keys and credentials under {identity.LOCAL_DIR}")
    return 0


def _show() -> int:
    try:
        anchors = identity.load_trust_anchors()
    except FileNotFoundError as exc:
        print(exc)
        return 1
    print(f"trust anchors ({identity.ANCHORS_PATH}):")
    for name, key in anchors.items():
        print(f"  {name:12s} {primitives.b64u(key)[:16]}…")

    print(f"\ncredentials ({identity.LOCAL_DIR}):")
    base = identity.LOCAL_DIR
    if not base.exists():
        print("  none")
        return 0
    now = datetime.now(timezone.utc)
    for d in sorted(base.iterdir()):
        path = d / identity.CREDENTIAL_FILE
        if not path.exists():
            continue
        try:
            cred = credentials.parse(path.read_bytes())
        except Exception as exc:                      # noqa: BLE001
            print(f"  {d.name:14s} unreadable: {exc}")
            continue
        state = "valid" if cred.not_before <= now <= cred.not_after else "EXPIRED"
        sector = f" sector {cred.sector}" if cred.sector else ""
        print(f"  {cred.subject:12s} {state:7s} until {cred.not_after:%Y-%m-%d %H:%M}"
              f"{sector}  roles: {','.join(cred.permitted_roles)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
