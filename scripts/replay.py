#!/usr/bin/env python3
"""
Play a whole scenario through the protocol with no broker and no sockets.

Every message is built, published and verified exactly as it would be over
MQTT; only the transport is absent, so what this exercises is the protocol.
It is the quickest way to see a complete flight, and it produces the counts
the paper's Section 5.1 reports.

    python3 scripts/replay.py scenarios/commercial_flight_EBBR-EDDF.json
    python3 scripts/replay.py <scenario> --verbose
"""

from __future__ import annotations

import argparse
import collections
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import credentials, identity, mqtt_binding as B     # noqa: E402
from protocol import node as N, operational as O, session as S    # noqa: E402
from protocol.rejection import Rejected                           # noqa: E402
from scripts._scenario import (load_aircraft_script,              # noqa: E402
                               load_station_script)

#: The scenario clock starts now, not at some fixed date: credentials have a
#: validity window and messages have an acceptance window, and both are
#: measured against the real clock.
START = datetime.now(timezone.utc)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    me, events, handovers = load_aircraft_script(args.scenario)
    anchors = identity.load_trust_anchors()
    aircraft = N.Aircraft(identity.load_identity(me), anchors)

    stations: dict[str, N.Station] = {}
    scripts: dict[str, list] = {}
    for _, name in handovers:
        if name in stations:
            continue
        ident = identity.load_identity(name)
        sector = credentials.parse(ident.credential).sector
        stations[name] = N.Station(ident, anchors, sector=sector)
        scripts[name] = load_station_script(args.scenario, name)

    nodes: dict[str, object] = {me: aircraft, **stations}
    sent = collections.Counter()
    discarded = collections.Counter()
    bytes_on_wire = 0
    handovers_done = 0

    def deliver(outbound, now):
        nonlocal bytes_on_wire, handovers_done
        queue = list(outbound)
        while queue:
            m = queue.pop(0)
            topic = B.topic_for(m.role, m.to, "aviation")
            sent[m.role] += 1
            bytes_on_wire += len(m.raw)
            if args.verbose:
                print(f"    {topic:34s} {len(m.raw):4d}B")
            node = nodes.get(m.to)
            if node is None:
                discarded["no such node"] += 1
                continue
            try:
                B.check_topic(topic, m.raw)
                queue += node.handle(m.raw, now)
            except Rejected as exc:
                discarded[exc.step.value] += 1
                if args.verbose:
                    print(f"      xx {exc.step.value}: {exc.detail}")
            if m.role == "KEYCONFIRM":
                handovers_done += 1

    now = START
    print(f"{me}: {len(events)} events over "
          f"{', '.join(n for _, n in handovers)}\n")

    first = handovers[0][1]
    print(f"-- establishing with {first}")
    deliver(aircraft.connect(first, now), now)

    queues = {name: list(rows) for name, rows in scripts.items()}
    for t, *row in events:
        now = START + timedelta(seconds=t)
        # anything the stations were scripted to do by now
        for name, pending in queues.items():
            while pending and pending[0][0] <= t:
                _, role, instruction, target = pending.pop(0)
                station = stations[name]
                if role == "NOMINATE":
                    print(f"-- {name} nominates {instruction} at {int(t)}s")
                    deliver(station.nominate(target, instruction, now), now)
                else:
                    station.enqueue(target, role, instruction)
        deliver(aircraft.tick(now), now)
        for st in stations.values():
            st.tick(now)
        if row[0] == "SA":
            deliver(aircraft.report(now, **row[1]), now)
        else:
            role, instruction = row[1], row[2]
            out = []
            for peer in aircraft.table.peers():
                sess = aircraft.table.get(peer)
                if sess and sess.state is S.State.ESTABLISHED:
                    out.append(N.Outbound(peer, role, O.build_aircraft_cc(
                        sess, aircraft.identity.kex_secret, now,
                        sender=me, role=role, instruction=instruction)))
            deliver(out, now)

    print("\n--- messages sent ---")
    for role, n in sorted(sent.items(), key=lambda kv: -kv[1]):
        print(f"  {role:16s} {n:5d}")
    total = sum(sent.values())
    print(f"  {'total':16s} {total:5d}   {bytes_on_wire/1024:.1f} KiB, "
          f"{bytes_on_wire // max(total, 1)} B/message average")

    print("\n--- sessions ---")
    print(f"  established       {handovers_done}")
    for name, st in stations.items():
        row = st.table.get(me)
        state = row.state.value if row else "none"
        print(f"  {name:16s} {state}")
    print(f"  aircraft holds    {', '.join(aircraft.table.peers()) or 'none'}")

    print("\n--- discarded ---")
    if not discarded:
        print("  nothing")
    for step, n in sorted(discarded.items(), key=lambda kv: -kv[1]):
        print(f"  {step:20s} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
