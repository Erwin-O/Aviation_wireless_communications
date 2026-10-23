#!/usr/bin/env python3
"""
The aircraft, flying a scenario and speaking the protocol of Section 3.3.

Establishes a session with the station the flight begins under, reports on the
scenario's clock, acts on commands that quote its outstanding challenge,
acknowledges them, and follows nominations to each successor station in turn.

    python3 scripts/aircraft.py --scenario scenarios/commercial_flight_EBBR-EDDF.json
    python3 scripts/aircraft.py --scenario ... --speed 20

Credentials come from scripts/provision.py; this script issues none.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import settings                                                   # noqa: E402
from mqtt_client import MQTTClient                                # noqa: E402
from protocol import identity, mqtt_binding as B, node as N       # noqa: E402
from protocol import operational as O, session as S               # noqa: E402
from protocol.rejection import Rejected                           # noqa: E402
from scripts._scenario import load_aircraft_script                # noqa: E402

TICK_SECONDS = 0.2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--host", default=settings.BROKER_HOST)
    ap.add_argument("--port", type=int, default=settings.BROKER_PORT)
    ap.add_argument("--base", default=settings.TOPIC_BASE)
    ap.add_argument("--speed", type=float, default=1.0,
                    help="scenario speed multiplier (default: 1.0)")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    me, events, handovers = load_aircraft_script(args.scenario)
    anchors = identity.load_trust_anchors()
    aircraft = N.Aircraft(identity.load_identity(me), anchors)

    first_station = handovers[0][1] if handovers else None
    if first_station is None:
        print("scenario names no station to begin with")
        return 1

    counts = {"sent": 0, "received": 0, "discarded": 0}
    print(f"[{me}] {len(events)} scenario events, "
          f"{len(handovers)} station(s): {', '.join(s for _, s in handovers)}")

    client = MQTTClient(client_id=f"aircraft-{B.slug(me)}")

    def send(out):
        for m in out:
            client.publish(B.topic_for(m.role, m.to, args.base), m.raw)
            counts["sent"] += 1
            print(f"  -> {m.role:14s} {m.to}")

    def on_message(topic: str, payload: bytes):
        now = datetime.now(timezone.utc)
        try:
            role = B.check_topic(topic, payload)
        except Rejected as exc:
            counts["discarded"] += 1
            print(f"  xx DISCARDED at {exc.step.value}: {exc.detail}")
            return
        try:
            out = aircraft.handle(payload, now)
        except Rejected as exc:
            counts["discarded"] += 1
            print(f"  xx {role:14s} DISCARDED at {exc.step.value}: {exc.detail}")
            return
        except Exception as exc:                                   # noqa: BLE001
            print(f"  !! {role:14s} error: {exc}")
            if args.debug:
                import traceback
                traceback.print_exc()
            return
        counts["received"] += 1
        print(f"  <- {role:14s} accepted")
        send(out)

    sub = B.subscription_for(me, args.base)
    # Subscribe from on_connect: a subscribe issued before the CONNACK is
    # dropped rather than queued.
    client.set_handlers(
        on_message=lambda _c, _u, msg: on_message(msg.topic, _as_bytes(msg.payload)),
        on_connect=lambda *_a: (client.subscribe(sub),
                                print(f"[{me}] subscribed to {sub}")))
    client.connect(args.host, args.port, settings.CLIENT_KEEPALIVE)
    client.loop_start()
    if not _await_connection(client):
        print(f"[{me}] no broker at {args.host}:{args.port}")
        return 1

    time.sleep(1.0)                      # let the stations' subscriptions settle
    print(f"[{me}] establishing with {first_station}")
    send(aircraft.connect(first_station, datetime.now(timezone.utc)))

    # Wait for the handshake before starting the scenario clock: reports sent
    # into a session that does not exist yet would simply not be built.
    for _ in range(50):
        row = aircraft.table.get(first_station)
        if row is not None and row.state is S.State.ESTABLISHED:
            break
        time.sleep(0.1)
    else:
        print(f"[{me}] no session with {first_station}; flying anyway")

    started = time.monotonic()
    pending = list(events)
    try:
        while pending:
            time.sleep(TICK_SECONDS)
            now = datetime.now(timezone.utc)
            send(aircraft.tick(now))
            elapsed = (time.monotonic() - started) * args.speed
            while pending and pending[0][0] <= elapsed:
                row = pending.pop(0)
                send(_play(aircraft, row, now))
        print(f"\n[{me}] scenario complete: "
              f"{counts['sent']} sent, {counts['received']} accepted, "
              f"{counts['discarded']} discarded")
        time.sleep(2.0)
    except KeyboardInterrupt:
        print(f"\n[{me}] stopping")
    finally:
        client.loop_stop()
        client.disconnect()
    return 0


def _await_connection(client, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if client.is_connected():
            return True
        time.sleep(0.05)
    return False


def _play(aircraft: N.Aircraft, row, now) -> list:
    """One scenario event."""
    if row[1] == "SA":
        return aircraft.report(now, **row[2])

    role, instruction = row[2], row[3]
    out = []
    for peer in aircraft.table.peers():
        sess = aircraft.table.get(peer)
        if sess is None or sess.state is not S.State.ESTABLISHED:
            continue
        out.append(N.Outbound(peer, role, O.build_aircraft_cc(
            sess, aircraft.identity.kex_secret, now,
            sender=aircraft.name, role=role, instruction=instruction)))
    return out


def _as_bytes(payload) -> bytes:
    return payload if isinstance(payload, bytes) else str(payload).encode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
