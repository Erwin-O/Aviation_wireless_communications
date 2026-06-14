
import os
import sys
import argparse
import json
import random
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mqtt_client import MQTTClient
from core.registry import get_pubkeys, load_private_keys
from encryption.crypto import (
    random_session_id_b64u,
    random_session_key,
    wrap_session_key,
    sign_detached_b64u,
    compute_mac_b64u,
    ed25519_verify,
)
from utils.station_norm import normalise_station
from core.comm_state import AircraftSessionBook, SessionEntry
from core.messages import ascii_key, ascii_sa, ascii_cc, ascii_ack, serialize, build_key_core
from core.logger import get_logger
from settings import BROKER_HOST, BROKER_PORT, TOPIC_BASE


# ------------------------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------------------------

def _norm_space(s: str) -> str:
    """Normalise whitespace (mainly for safety in future parsing)."""
    return re.sub(r"\s+", " ", (s or "").strip())

def detect_contact_target(text: str) -> Optional[str]:
    text = _norm_space(text)
    if not text:
        return None

    m = re.search(r"(?i)\bCONTACT\b\s+(.+)$", text)
    if m:
        return normalise_station(m.group(1))

    return normalise_station(text)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario_json", help="Scenario JSON produced by build_scenario_from_tables.py")
    ap.add_argument("--publish", action="store_true", help="Publish to MQTT; otherwise dry-run (print only)")
    ap.add_argument("--mqtt-host", default=BROKER_HOST, help=f"MQTT broker host (default: {BROKER_HOST})")
    ap.add_argument("--mqtt-port", type=int, default=BROKER_PORT, help=f"MQTT broker port (default: {BROKER_PORT})")
    ap.add_argument("--topic-base", default=TOPIC_BASE, help=f"Base topic prefix (default: '{TOPIC_BASE}')")
    ap.add_argument("--debug", action="store_true", help="Verbose scheduling / debug output")
    return ap.parse_args()


def sleep_until(target_epoch: float):
    """Sleep until the given epoch time (seconds)."""
    now = time.time()
    if target_epoch > now:
       #HERE DEVIDED BY 1000 TO SPEED UP THE DEMO - SHOULD BE REMOVED AT SOME POINT
       #ORIGINAL:time.sleep(target_epoch - now) 
       time.sleep((target_epoch - now)/1000)
    ##time.sleep(2) 


def _draw_cc_jitter(sigma: float = 5.0, clamp: float = 15.0) -> float:
    """
    Return jitter (seconds) ~ N(0, sigma), clamped to ±clamp.

    Used only for CC events so you get:
      - mean timing = scenario 't' value
      - random spread ~ N(0, 5s) in your config
    """
    j = random.gauss(0.0, sigma)
    if j > clamp:
        j = clamp
    if j < -clamp:
        j = -clamp
    return j


# ------------------------------------------------------------------------------
# Core publish helpers
# ------------------------------------------------------------------------------

def ensure_key_for_station(
    book: AircraftSessionBook,
    t_s: int,
    aircraft_id: str,
    station: str,
    ed25519_priv: bytes,
    x25519_priv: bytes,
    topic_base: str,
    client: Optional[MQTTClient],
    logger: Any,
    do_publish: bool,
):
    """
    Ensure we have a session for 'station'. If not, create one and publish a KEY.

    - Uses station's public X25519 key from key_registry.
    - Builds a fresh session_id + random symmetric session key.
    - Wraps session key for the station.
    - Signs (ts|frm|to|sid|wrapped) with aircraft Ed25519 private key.
    - Publishes ASCII KEY on topic: {topic_base}/sec/key/{aircraft_id}
    - Stores session in AircraftSessionBook and sets current station.
    """
    import base64

    def _to_b64u(v):
        if isinstance(v, (bytes, bytearray)):
            return base64.urlsafe_b64encode(v).decode("ascii").rstrip("=")
        return v  # assume already b64u str

    # Already have a session for this station?
    station = normalise_station(station)
    if book.get_session(station):
        return

    # Look up station public keys (we need x25519 pub)
    try:
        _, x2_pub = get_pubkeys(station)
    except KeyError:
        print(f"[ERROR] Unknown station '{station}'. Add it to config/publicKeys.json or STATION_ALIASES.")
        return

    # --- Build session id + symmetric session key
    sid = random_session_id_b64u()
    skey = random_session_key()  # bytes

    # Wrap session key for the station (returns base64url string)
    wrapped = wrap_session_key(x25519_priv, x2_pub, skey)

    # --- Load aircraft public key (always required now)
    try:
        reg_pub_bytes, _ = get_pubkeys(aircraft_id)
        reg_pub_b64u = _to_b64u(reg_pub_bytes)
    except Exception as e:
        print(f"[ERROR] Cannot load public key for aircraft '{aircraft_id}': {e}")
        return

    # ---- Canonical fields (what we SIGN == what we PRINT)
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    frm_txt = aircraft_id
    to_txt  = station

    # canonical signing string — MUST match subscriber verify (both use build_key_core)
    sign_core = build_key_core(ts, frm_txt, to_txt, reg_pub_b64u, sid, wrapped)
    key_sig = sign_detached_b64u(ed25519_priv, sign_core.encode("utf-8"))

    # ---- ASCII payload (must mirror those values)
    core = {
        "ts": ts,
        "frm": frm_txt,
        "to": to_txt,
        "public_key_b64u": reg_pub_b64u,
        "session_id": sid,
        "wrapped_key_b64": wrapped,
        "key_sig_b64": key_sig,
    }
    print("[DEBUG] core keys:", core.keys())
    payload = ascii_key(core)
    topic = f"{topic_base}/sec/key/{aircraft_id}"

    # ---- DEBUG: show exactly what we signed (enable with AV_DEBUG=1)
    if os.environ.get("AV_DEBUG", "0") == "1":
        print("\n[SIGN-CHECK] Publisher will sign this core exactly:")
        print(f"  core='{sign_core}'")
        print(
            "  parts:",
            f"ts='{ts}',",
            f"from='{frm_txt}',",
            f"to='{to_txt}',",
            f"sid_len={len(sid)},",
            f"wrapped_len={len(wrapped)}",
        )
        print(f"  sig_len={len(key_sig)} preview={key_sig[:12]}...")

        # Derive sender pub from private (to cross-check registry)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization

            priv = Ed25519PrivateKey.from_private_bytes(ed25519_priv)
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            sender_pub_b64u = _to_b64u(pub_bytes)
            print(f"  sender_pub_ed25519 (derived) = {sender_pub_b64u} (len={len(sender_pub_b64u)})")
        except Exception as e:
            print(f"  derive sender pubkey: skipped ({e})")
            sender_pub_b64u = None

        # Registry pubkey for aircraft (normalize to b64u if needed)
        try:
            print(f"  registry_pub_ed25519        = {reg_pub_b64u} (len={len(reg_pub_b64u)})")
            if sender_pub_b64u is not None:
                print(f"  pubkey_match={sender_pub_b64u == reg_pub_b64u}")
        except Exception as e:
            print(f"  registry pubkey fetch: skipped ({e})")
            reg_pub_b64u = None

        # Optional local self-verify against the registry pubkey
        try:
            if reg_pub_b64u is not None:
                ok_local = ed25519_verify(reg_pub_b64u, sign_core, key_sig)
                print(f"  local_verify(registry_pub)={ok_local}")
            else:
                print("  local_verify: skipped (no registry pub)")
        except Exception as e:
            print(f"  local_verify: skipped ({e})")

    # ---- Send once
    print(f"[SEND] {topic}\n{payload}\n")
    if do_publish and client is not None:
        client.publish(topic, payload, qos=0, retain=False)

    logger.wire("KEY", {"t_s": t_s, "topic": topic, "station": station, "payload": payload})
    logger.event("session established", {"aircraft": aircraft_id, "station": station, "sid": sid})

    # ---- Remember session for subsequent SA/CC signing
    book.put_session(station, SessionEntry(session_id=sid, key=skey))
    book.set_station(station)


def publish_sa(
    book: AircraftSessionBook,
    t_s: int,
    aircraft_id: str,
    station: str,
    sa_row: Dict[str, Any],
    topic_base: str,
    client: Optional[MQTTClient],
    logger: Any,
    do_publish: bool,
    ed25519_priv: bytes,
    x25519_priv: bytes,
):
    """
    Publish a Situational Awareness message:

    - Ensures a session exists for the current station (injects KEY if needed).
    - MAC = BLAKE3(session_key, newline-joined fields in canonical order).
    """
    from datetime import datetime, timezone
    import time as _time_mod  # avoid shadowing global time

    station = normalise_station(station)

    # Ensure there is a session for this station (no-op if already present)
    ensure_key_for_station(
        book=book,
        t_s=t_s if t_s is not None else int(_time_mod.time()),
        aircraft_id=aircraft_id,
        station=station,
        ed25519_priv=ed25519_priv,
        x25519_priv=x25519_priv,
        topic_base=topic_base,
        client=client if do_publish else None,
        logger=logger,
        do_publish=do_publish,
    )

    # Retrieve (possibly newly created) session
    sess = book.get_session(station)
    if not sess:
        print("[WARN] SA before session; injecting KEY (deferred)")
        return False  # caller may retry on next tick

    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    
    print(f"[SA] routing to {station}")
    
    core = {
        "ts": ts,
        "frm": aircraft_id,
        "to": station,
        "alt_ft": sa_row["alt_ft"],
        "lat": sa_row["lat"],
        "lon": sa_row["lon"],
        "gs_kt": sa_row["gs_kt"],
        "hdg_deg": sa_row["hdg_deg"],
        "on_ground": sa_row["on_ground"],
    }

    mac = compute_mac_b64u(
        sess.key,
        "\n".join([
            core["ts"],
            core["frm"],
            core["to"],
            str(core["alt_ft"]),
            f"{core['lat']}",
            f"{core['lon']}",
            str(core["gs_kt"]),
            str(core["hdg_deg"]),
            str(core["on_ground"]),
        ]).encode("utf-8"),
    )

    payload = ascii_sa(core, mac)
    topic = f"{topic_base}/pos/sa/{aircraft_id}"

    print(f"[SEND] {topic}\n{payload}\n")
    if do_publish and client is not None:
        client.publish(topic, payload, qos=0, retain=False)

    logger.wire("SA", {"t_s": t_s, "topic": topic, "station": station, "payload": payload})
    return True


def publish_cc(
    book: AircraftSessionBook,
    t_s: int,
    aircraft_id: str,
    station: str,
    cc_row: Dict[str, Any],
    topic_base: str,
    client: Optional[MQTTClient],
    logger: Any,
    do_publish: bool,
    ed25519_priv: bytes,
    x25519_priv: bytes,
):
    """
    Publish a CC message. Special-cases CONTACT to perform a handover:
      - If CONTACT, rotate session to target (publish KEY) and switch active station.
      - For all other CC types, ensure a live session exists first (publish KEY if needed).
    """
    from datetime import datetime, timezone
    import time as _time_mod

    # Normalise inputs
    station = normalise_station(station)
    cc_type_raw = (cc_row.get("cc_type") or "").strip()
    if not cc_type_raw:
        print("[WARN] CC event missing cc_type; ignored.")
        return True
    cc_type = cc_type_raw.upper()

    # ---------------- CONTACT (handover) ----------------
    if cc_type == "CONTACT":
        body = cc_row.get("body") or ""
        target = detect_contact_target(body)
        if not target:
            print("[HANDOVER] CONTACT has empty or invalid target — skipped.")
            return True

        current = book.current_station()

        # Avoid no-op and duplicate handovers
        if target == current:
            print(f"[HANDOVER] (skip: already on {target})")
            return True
        if book.already_handover(current, target, t_s):
            print(f"[HANDOVER] (skip dup) -> {target}")
            return True

        print(f"[HANDOVER] -> {target}")

        # Ensure a fresh session for the new ground station (publishes KEY once)
        ensure_key_for_station(
            book=book,
            t_s=t_s if t_s is not None else int(_time_mod.time()),
            aircraft_id=aircraft_id,
            station=target,
            ed25519_priv=ed25519_priv,
            x25519_priv=x25519_priv,
            topic_base=topic_base,
            client=client if do_publish else None,
            logger=logger,
            do_publish=do_publish,
        )
        logger.event("handover", {"from": current, "to": target, "t_s": t_s})

        # Switch active station
        book.set_station(target)
        return True

    # ---------------- Non-CONTACT CC ----------------
    # Make sure we have a session for the addressed station.
    ensure_key_for_station(
        book=book,
        t_s=t_s if t_s is not None else int(_time_mod.time()),
        aircraft_id=aircraft_id,
        station=station,
        ed25519_priv=ed25519_priv,
        x25519_priv=x25519_priv,
        topic_base=topic_base,
        client=client if do_publish else None,
        logger=logger,
        do_publish=do_publish,
    )

    sess = book.get_session(station)
    if not sess:
        # Should be rare; caller can retry on next tick.
        print("[WARN] CC before session; KEY injection deferred.")
        return False


    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    frm_value = cc_row.get("from")
    aircraft_txt = aircraft_id

    # FROM: default to aircraft unless scenario explicitly sets something else
    frm_txt = aircraft_txt if frm_value in (None, "", aircraft_id, aircraft_txt) else str(frm_value)

    # TO: honour scenario if present; otherwise infer based on who is sending
    to_value = cc_row.get("to")
    if to_value not in (None, ""):
         to_txt = str(to_value)
    else:
        # If aircraft is sending, it's addressed to the current station.
        # If ground is sending, it's addressed to the aircraft.
        if frm_txt == aircraft_txt:
            to_txt = station
        else:
            to_txt = aircraft_txt

    core = {
        "ts": ts,
        "frm": frm_txt,
        "to": to_txt,
        "cc_type": cc_type,                 # keep canonical upper-case in payload
        "body": cc_row.get("body", ""),
    }

    # MAC over canonical fields in the exact order used by the subscriber
    mac = compute_mac_b64u(
        sess.key,
        "\n".join([core["ts"], str(core["frm"]), core["to"], core["cc_type"], core["body"]]).encode("utf-8"),
    )
    payload = ascii_cc(core, mac)

    # Topic group: lower-case the type and make it safe for MQTT segment
    cc_group = re.sub(r"[^a-z0-9]+", "_", cc_type.lower()).strip("_") or "other"
    topic = f"{topic_base}/cc/{cc_group}/{aircraft_id}"

    print(f"[SEND] {topic}\n{payload}\n")
    if do_publish and client is not None:
        client.publish(topic, payload, qos=0, retain=False)

    logger.wire("CC", {"t_s": t_s, "topic": topic, "station": station, "payload": payload})
    return True




# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

def main():
    args = parse_args()

    # load scenario
    with open(args.scenario_json, "r", encoding="utf-8") as f:
        scenario = json.load(f)

    flight = scenario["flight"]
    events: List[Dict[str, Any]] = scenario["events"]

    aircraft_id: str = flight.get("aircraft_id", "OOABC")

    initial_station = normalise_station(flight.get("initial_station", ""))
    if not initial_station:
        raise ValueError("Scenario missing initial_station")
    print(f"[INIT] Current station = {initial_station}")

    topic_base: str = args.topic_base

    # keys for aircraft (sender)
    ed25519_priv, x25519_priv = load_private_keys(aircraft_id)

    # MQTT
    client: Optional[MQTTClient] = None
    if args.publish: 
        client = MQTTClient(client_id=f"scenario-{os.getpid()}")
        client.connect(args.mqtt_host, args.mqtt_port)
        client.loop_start()
        print(f"[MQTT] Connected to {args.mqtt_host}:{args.mqtt_port}")

    logger = get_logger(aircraft_id)

    # session book
    book = AircraftSessionBook(initial_station)

    # timing model (real time)
    start_wall = time.time()

    def _parse_ts(e: Dict[str, Any]) -> int:
        t_str = (e.get("t") or e.get("ts") or "00:00:00").strip()
        h, m, s = map(int, t_str.split(":"))
        return h * 3600 + m * 60 + s

    base_t_s = 0
    if events:
        base_t_s = min(_parse_ts(e) for e in events)

    last_target_wall = start_wall  # ensure non-decreasing schedule

    for ev in events:
        t_str = (ev.get("t") or ev.get("ts") or "00:00:00").strip()
        hh, mm, ss = map(int, t_str.split(":"))
        t_s = hh * 3600 + mm * 60 + ss

        # Jitter only for CC events
        etype = (ev.get("type") or ev.get("kind") or "").strip().upper()
        jitter = _draw_cc_jitter() if etype == "CC" else 0.0

        # Relative schedule from scenario start (cannot go negative)
        rel = max(0.0, (t_s - base_t_s) + jitter)

        # Convert to wall clock and enforce non-decreasing order
        target_wall = start_wall + rel
        if target_wall < last_target_wall:
            target_wall = last_target_wall

        # (Optional) debug trace
        if args.debug:
            jt = f"{jitter:+.2f}s" if jitter else "+0.00s"
            print(f"[SCHED] {etype} t={t_str} jitter={jt} → sleep until {target_wall:.3f}")

        sleep_until(target_wall)
        last_target_wall = target_wall

        # SA event
        if etype == "SA":
            ok = publish_sa(
                book=book,
                t_s=t_s,
                aircraft_id=aircraft_id,
                station=book.current_station(),
                sa_row=ev,
                topic_base=topic_base,
                client=client,
                logger=logger,
                do_publish=args.publish,
                ed25519_priv=ed25519_priv,
                x25519_priv=x25519_priv,
            )
            if not ok:
                ensure_key_for_station(
                    book, t_s, aircraft_id, book.current_station(),
                    ed25519_priv, x25519_priv, topic_base, client, logger, args.publish,
                )
                publish_sa(
                    book, t_s, aircraft_id, book.current_station(), ev,
                    topic_base, client, logger, args.publish,
                    ed25519_priv=ed25519_priv, x25519_priv=x25519_priv,
                )
            continue

        # KEY event (explicit in scenario)
        if etype == "KEY":
            target = normalise_station(ev.get("to"))
            if not target:
                raise ValueError("KEY event missing 'to'")

            ensure_key_for_station(
                book, t_s, aircraft_id, target,
                ed25519_priv, x25519_priv, topic_base, client, logger, args.publish,
            )
            print(f"[SESSION] Switched current_station -> {book.current_station()}")
            continue

        # CC event (CONTACT handled inside publish_cc)
        if etype == "CC":
            ok = publish_cc(
                book=book,
                t_s=t_s,
                aircraft_id=aircraft_id,
                station=book.current_station(),
                cc_row=ev,
                topic_base=topic_base,
                client=client,
                logger=logger,
                do_publish=args.publish,
                ed25519_priv=ed25519_priv,
                x25519_priv=x25519_priv,
            )
            # ok is True whether CONTACT rotated or a CC was published.
            continue

        print(f"[WARN] Unknown event type: {etype}")

    logger.close()
    if client and hasattr(client, "disconnect"):
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass

    print("[SCENARIO] Completed all events. Exiting.")
    sys.exit(0)


if __name__ == "__main__":
    main()
