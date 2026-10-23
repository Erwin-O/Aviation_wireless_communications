#!/usr/bin/env python3
"""
A ground station, speaking the protocol of Section 3.3.

Answers handshakes, verifies every message it receives and says which check
refused the ones it discards. With a scenario it also plays the controller's
part: each instruction the scenario gives this station is enqueued at its
scheduled time and issued when the aircraft's next report supplies a challenge
to bind it to.

    python3 scripts/station.py --station "EBBR GND"
    python3 scripts/station.py --station "EBBR GND" --scenario scenarios/x.json

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
from protocol import credentials, identity, mqtt_binding as B     # noqa: E402
from protocol import node as N                                    # noqa: E402
from protocol.rejection import Rejected                           # noqa: E402
from scripts._scenario import load_station_script                 # noqa: E402

TICK_SECONDS = 1.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--station", required=True, help='e.g. "EBBR GND"')
    ap.add_argument("--host", default=settings.BROKER_HOST)
    ap.add_argument("--port", type=int, default=settings.BROKER_PORT)
    ap.add_argument("--base", default=settings.TOPIC_BASE)
    ap.add_argument("--scenario", help="enqueue this station's instructions")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="scenario speed multiplier (default: 1.0)")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    anchors = identity.load_trust_anchors()
    me = identity.load_identity(args.station)
    sector = credentials.parse(me.credential).sector
    station = N.Station(me, anchors, sector=sector)

    script = load_station_script(args.scenario, args.station) if args.scenario else []
    print(f"[{args.station}] sector {sector}  "
          f"{len(anchors)} trust anchor(s)  {len(script)} scripted instruction(s)")

    client = MQTTClient(client_id=f"station-{B.slug(args.station)}")
    sub = B.subscription_for(args.station, args.base)

    def send(out):
        for m in out:
            topic = B.topic_for(m.role, m.to, args.base)
            client.publish(topic, m.raw)
            print(f"  -> {m.role:14s} {m.to}")

    def on_message(topic: str, payload: bytes):
        now = datetime.now(timezone.utc)
        try:
            role = B.check_topic(topic, payload)
        except Rejected as exc:
            print(f"  xx DISCARDED at {exc.step.value}: {exc.detail}")
            return
        try:
            out = station.handle(payload, now)
        except Rejected as exc:
            print(f"  xx {role:14s} DISCARDED at {exc.step.value}: {exc.detail}")
            return
        except Exception as exc:                                   # noqa: BLE001
            print(f"  !! {role:14s} error: {exc}")
            if args.debug:
                import traceback
                traceback.print_exc()
            return
        print(f"  <- {role:14s} accepted")
        send(out)

    # mqtt_client passes paho's own callback signatures through. Subscribing
    # from on_connect rather than after connect() matters: a subscribe issued
    # before the CONNACK is not queued, it is dropped, and the station then
    # sits there having heard nothing. It also re-subscribes on a reconnect.
    client.set_handlers(
        on_message=lambda _c, _u, msg: on_message(msg.topic, _as_bytes(msg.payload)),
        on_connect=lambda *_a: (client.subscribe(sub),
                                print(f"[{args.station}] subscribed to {sub}")))
    client.connect(args.host, args.port, settings.CLIENT_KEEPALIVE)
    client.loop_start()
    if not _await_connection(client):
        print(f"[{args.station}] no broker at {args.host}:{args.port}")
        return 1

    started = time.monotonic()
    pending = list(script)
    try:
        while True:
            time.sleep(TICK_SECONDS)
            elapsed = (time.monotonic() - started) * args.speed
            while pending and pending[0][0] <= elapsed:
                _, role, instruction, aircraft = pending.pop(0)
                if role == "NOMINATE":
                    print(f"  == nominating {instruction} for {aircraft}")
                    send(station.nominate(aircraft, instruction,
                                          datetime.now(timezone.utc)))
                else:
                    station.enqueue(aircraft, role, instruction)
                    print(f"  == queued {role} {instruction[:40]}")
            station.tick(datetime.now(timezone.utc))
    except KeyboardInterrupt:
        print(f"\n[{args.station}] stopping")
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


def _as_bytes(payload) -> bytes:
    return payload if isinstance(payload, bytes) else str(payload).encode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
