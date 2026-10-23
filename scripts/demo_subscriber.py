#!/usr/bin/env python3
"""
demo_subscriber.py
Merged, minimal-changes subscriber that:
- subscribes to aviation/sec/key/# and aviation/pos/sa/# and aviation/cc/#
- verifies KEY signatures (ed25519) using key_registry.get_pubkeys()
- unwraps session keys with station x25519 private key
- remembers per-aircraft sessions
- in --debug mode, will accept KEY even if signature verification fails (with WARNING)

Usage:
  python3 scripts/demo_subscriber.py \
    --station "EBBR GND" \
    --mqtt-host 127.0.0.1 --mqtt-port 1883 \
    --topic-base aviation \
    --only-for-us \
    --debug
"""
import os
import sys
import re
import argparse
import traceback
import time
import base64
import binascii
import random
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
from queue import Queue

from mqtt_client import MQTTClient
from core.registry import get_pubkeys
from encryption.crypto import (
    compute_mac_b64u,
    ed25519_verify,
    unwrap_session_key,
    bytes_to_b64u,
)
from utils.station_norm import normalise_station
from config.station_keys import get_priv_for_station
from core.comm_state import SessionBook, SessionEntry
from core.messages import ascii_ack, build_key_core, parse_ascii_block, key_signing_material
from core.logger import get_logger
from settings import BROKER_HOST, BROKER_PORT, CLIENT_KEEPALIVE, TOPIC_BASE

event_queue = Queue()


# -------------------- debug helpers --------------------
def dbg(enabled: bool, *args):
    if enabled:
        print("[DEBUG]", *args)

def redact(s: str, head=8, tail=6):
    """Return s with only head..tail visible."""
    if s is None:
        return "<None>"
    s = str(s)
    if len(s) <= head + tail + 3:
        return s
    return f"{s[:head]}...{s[-tail:]} (len={len(s)})"

def b64u_ok(s: str) -> bool:
    """Check if s looks like base64url without raising."""
    try:
        pad = '=' * (-len(s) % 4)
        base64.urlsafe_b64decode((s + pad).encode('ascii'))
        return True
    except Exception:
        return False


def to_b64u_str(x) -> str:
    """Normalize bytes/bytearray/str into base64url string (no padding)."""
    if isinstance(x, str):
        return x.strip().rstrip("=")
    if isinstance(x, (bytes, bytearray)):
        return base64.urlsafe_b64encode(bytes(x)).decode("ascii").rstrip("=")
    raise TypeError(f"expected bytes|str, got {type(x)!r}")

def hexdump_short(b: bytes, n=8):
    if not isinstance(b, (bytes, bytearray)):
        return f"<not-bytes:{type(b).__name__}>"
    return binascii.hexlify(bytes(b)[:n]).decode("ascii") + f"... (len={len(b)})"


def publish_ack(
    session_key,
    session_id,
    frm,
    to,
    ref_type,
    body,
    ref_hash,
    topic_base,
    client,
    logger,
):
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    core = {
        "ts": ts,
        "frm": frm,
        "to": to,
        "ref_type": ref_type,
        "session_id": session_id,
        "body": body,
    }

    if ref_hash:
        core["ref_hash"] = ref_hash

    parts = [
        core["ts"],
        core["frm"],
        core["to"],
        core["ref_type"],
        core["session_id"],
    ]

    if ref_hash:
        parts.append(ref_hash)

    parts.append(core["body"])

    canonical = "\n".join(parts).encode("utf-8")

    sig = compute_mac_b64u(session_key, canonical)

    payload = ascii_ack(core, sig)

    topic = f"{topic_base}/sec/ack/{to}"

    print(f"[SEND][ACK] {topic}\n{payload}\n")

    if client is not None:
        client._client.publish(topic, payload, qos=0, retain=False)

    logger.wire("ACK", {"topic": topic, "payload": payload})

def publisher_worker(client, topic_base, logger, debug=False):
    while True:
        evt = event_queue.get()

        try:
            if evt["type"] == "SESSION_ACK":
                publish_ack(
                    session_key=evt["session_key"],
                    session_id=evt["session_id"],
                    frm=evt["frm"],
                    to=evt["to"],
                    ref_type="SESSION",
                    body=evt["body"],
                    ref_hash=None,
                    topic_base=topic_base,
                    client=client,
                    logger=logger,
                )

                if debug:
                    print(f"[WORKER] ACK sent for session {evt['session_id']}")

            elif evt["type"] == "CC_ACK":
                publish_ack(
                    session_key=evt["session_key"],
                    session_id=evt["session_id"],
                    frm=evt["frm"],
                    to=evt["to"],
                    ref_type="CC",
                    body=evt["body"],
                    ref_hash=evt["ref_hash"],
                    topic_base=topic_base,
                    client=client,
                    logger=logger,
                )

                if debug:
                    print(f"[WORKER] CC ACK sent for SID={evt['session_id']}")

        except Exception as e:
            print(f"[WORKER][ERROR] {e}")
            logger.event("worker error", {"error": str(e), "evt_type": evt.get("type")})


# -------------------- Subscriber logic --------------------
class Subscriber:
    def __init__(self, station_human: str, topic_base: str, client, logger, debug: bool, only_for_us: bool = False) -> None:
        self.station_human = station_human
        self.station_id = normalise_station(station_human)
        self.topic_base = topic_base
        self.client = client
        self.logger = logger
        self.debug = debug
        self.only_for_us = only_for_us

        self.sessions = SessionBook()

        # load receiver private keys once
        try:
            self.ed_priv, self.x_priv = get_priv_for_station(self.station_id)
        except Exception as e:
            print(f"[FATAL] Could not load private keys for station '{self.station_id}': {e}")
            sys.exit(2)

        self.sa_log_every = int(os.environ.get("SA_LOG_EVERY", "10"))  # print every N SA messages
        self._sa_seen = 0
        self._sa_last = None  # (alt_ft, lat, lon, spd, hdg, on_ground, sid)

    def on_message(self, topic: str, payload_text: str):
        """
        Called by the MQTT adapter with:
          - topic: msg.topic
          - payload_text: decoded UTF-8 string
        """
##        print(f"[RAW] topic={topic}")
        if self.debug:
            first_line = payload_text.splitlines()[0][:160] if payload_text else ""
            print(f"[DBG] on_message topic={topic!r} len={len(payload_text)} first_line={first_line!r}")

        try:
            if topic.startswith("aviation/sec/key/"):
                self.handle_key(topic, payload_text)
            elif topic.startswith("aviation/sec/ack/"):
                self.handle_ack(topic, payload_text)
            elif topic.startswith("aviation/pos/sa/"):
                self.handle_sa(topic, payload_text)
            elif topic.startswith("aviation/cc/"):
                self.handle_cc(topic, payload_text)
            else:
                # ignore other topics under aviation/ for now
                pass
        except Exception as e:
            print(f"Caught exception in on_message (topic={topic!r}): {e}")
            if self.debug:
                traceback.print_exc()

    # --- Handlers ---
    def handle_key(self, topic: str, text: str) -> None:
        fields = parse_ascii_block(text)

        # Normalise addressing & optional filter
        raw_to = fields.get("to", "")
        to_norm = normalise_station(raw_to)

        if self.only_for_us and to_norm not in (self.station_id, "ALL", "BROADCAST", ""):
            if self.debug:
                print(f"[KEY-DBG] not for us: to={to_norm!r} self={self.station_id!r}")
            return

        dbg(self.debug, f"KEY fields present: {sorted(fields.keys())}")

        needed = ("ts", "from", "to", "public_key_ascii", "session_id", "wrapped_key_b64", "signature")
        if not all(k in fields for k in needed):
            print("[KEY] Missing fields in KEY; ignoring.")
            if self.debug:
                print(text)
            return

        ts      = fields["ts"]
        frm     = fields["from"]          # e.g. "OOABC"
        to_s    = fields["to"]            # e.g. "EBBR GND"
        pubkey_msg = fields["public_key_ascii"]
        sid     = fields["session_id"]
        wrapped = fields["wrapped_key_b64"]
        sig     = fields["signature"]

        # Drop keys not intended for this station
        to_norm = normalise_station(to_s)
        if to_norm != self.station_id:
            dbg(self.debug, f"[KEY-DBG] not for us: to='{to_norm}' (raw='{to_s}') self='{self.station_id}'")
            return

        if self.debug:
            print("\n=== [DEBUG] KEY received ===")
            print(f"FROM={frm} TO={to_s} SID={sid}")
            print(f"WRAP(len)={len(wrapped)} SIG={sig[:16]}...")

        if not b64u_ok(wrapped):
            print("[VERIFY] Wrapped session key is not valid base64url — dropped.")
            if self.debug:
                print("   payload:\n" + text)
            return

        if not b64u_ok(sig):
            print("[VERIFY] KEY signature field is not valid base64url — dropped.")
            if self.debug:
                print("   payload:\n" + text)
            return

        # Load sender pubkeys
        try:
            ed_pub_bytes, x_pub_bytes = get_pubkeys(frm)
        except KeyError:
            if self.debug:
                print(f"[VERIFY] No public key for '{frm}' in publicKeys.json — cannot verify or unwrap.")
                print("   payload:\n" + text)
            else:
                print(f"[VERIFY] Unknown aircraft '{frm}' — dropped.")
            return

        # Verify ed25519 signature
        try:
            ed_pub_b64u = bytes_to_b64u(ed_pub_bytes)
        except Exception as e:
            print(f"[VERIFY] Failed to encode Ed25519 pubkey for '{frm}': {e}")
            if self.debug:
                traceback.print_exc()
            return

        if pubkey_msg.strip() == ed_pub_b64u.strip():
            print("")
            print(f"[KEY CHECK] PUBLIC KEY MATCHES REGISTRY for {frm} ✅")
            print("")
        else:
            print("")
            print(f"[KEY CHECK] PUBLIC KEY MISMATCH for {frm} ❌")
            print(f"  expected: {ed_pub_b64u}")
            print(f"  received: {pubkey_msg}")
            print("")
            return


        ok_sig = False
        try:
            pipe_core = key_signing_material(text)
            ok_sig = ed25519_verify(ed_pub_b64u, pipe_core, sig)

            print(f"[KEY VERIFY] sig_ok={ok_sig}") #temp extra debug
            print(f"[KEY VERIFY] core='{pipe_core}'") #temp extra debug
            print(f"[KEY VERIFY] RAW to_s='{to_s}' len={len(to_s)}") #temp extra debug

            if self.debug:
                core_preview = pipe_core if len(pipe_core) < 200 else pipe_core[:200] + "…"
                print("[DEBUG] sig-verify inputs:")
                print(f"  ed25519_pub(raw_len)={len(ed_pub_bytes)}, b64u_len={len(ed_pub_b64u)}")
                print(f"  core='{core_preview}'")
                print(f"  sig(len)={len(sig)} ok={ok_sig}")
        except Exception as e:
            print(f"[VERIFY] Signature verification raised: {e}")
            if self.debug:
                traceback.print_exc()
            ok_sig = False

        if not ok_sig:
            if self.debug:
                print("[WARN] --debug: accepting KEY despite invalid signature for diagnostics.")
                print("   payload:\n" + text)
            else:
                print("[VERIFY] KEY signature INVALID — dropped.")
                return

        # Unwrap session key
        try:
            if not isinstance(self.x_priv, (bytes, bytearray)) or len(self.x_priv) != 32:
                raise ValueError("self.x_priv must be 32 bytes (raw X25519 private key)")

            if not isinstance(x_pub_bytes, (bytes, bytearray)) or len(x_pub_bytes) != 32:
                raise ValueError("publisher X25519 public key must be 32 bytes")

            t0 = time.perf_counter()
            skey = unwrap_session_key(self.x_priv, x_pub_bytes, wrapped)
            t1 = time.perf_counter()
            dbg(self.debug, f"unwrap_session_key ok in {(t1 - t0)*1e3:.2f} ms, key={hexdump_short(skey)}")

        except Exception as e:
            print(f"[ERROR] Failed to unwrap session key for {frm}: {e}")
            if self.debug:
                traceback.print_exc()
            return

        print(f"[SESS] Learned session for {frm}: SID={sid} (key {len(skey)} bytes)")
        self.logger.event("session learned", {"from": frm, "sid": sid, "key_len": len(skey)})
        self.logger.wire("KEY", {"from": frm, "to": self.station_id, "sid": sid, "payload": text})
        self.sessions.put(frm, SessionEntry(session_id=sid, key=skey))

        event_queue.put({
            "type": "SESSION_ACK",
            "session_key": skey,
            "session_id": sid,
            "frm": self.station_id,
            "to": frm,
            "body": f"IDENTIFIED AND MONITORED BY {self.station_id}",
        })


    def handle_ack(self, topic: str, text: str):
        fields = parse_ascii_block(text)

        frm = fields.get("from", "<?>")
        to_s = normalise_station(fields.get("to", ""))
        ref_type = fields.get("ref_type", "")
        sid = fields.get("session_id", "")
        body = fields.get("body", "")

        if self.only_for_us and to_s not in (self.station_id, "ALL", "BROADCAST", ""):
            if self.debug:
                print(f"[ACK-DBG] not for us: to={to_s!r} self={self.station_id!r}")
            return

        print(f"[ACK] {frm}→{to_s} {ref_type}: {body} SID={sid}")

        if self.debug:
            print(text)

    def handle_sa(self, topic: str, text: str):
        fields = parse_ascii_block(text)
        frm = fields.get("from", "<?>")

        # Normalise addressing & optional filter
        raw_to = fields.get("to", "")
        to_norm = normalise_station(raw_to)

        if self.only_for_us and to_norm not in (self.station_id, "ALL", "BROADCAST", ""):
            if self.debug:
                print(f"[SA-DBG] not for us: to={to_norm!r} self={self.station_id!r}")
            return

        sess = self.sessions.get(frm)
        if not sess:
            print(f"[VERIFY] {frm}: no session known; skip")
            if self.debug:
                print("   topic:", topic)
                print("   payload:\n" + text)
            return

        ts = fields.get("ts") or fields.get("timestamp")

        def _num(v, cast=float):
            try:
                return cast(v)
            except Exception:
                return v

        alt = _num(fields.get("alt_ft") or fields.get("altitude"))
        spd = _num(fields.get("speed"))
        hdg = _num(fields.get("heading"))

        on_g = fields.get("on_ground")
        if isinstance(on_g, str):
            on_g = on_g.strip().lower() in ("1", "true", "yes")

        lat, lon = None, None
        pos = fields.get("position")
        if isinstance(pos, str):
            nums = re.findall(r"-?\d+(?:\.\d+)?", pos)
            if len(nums) >= 2:
                try:
                    lat = float(nums[0])
                    lon = float(nums[1])
                except Exception:
                    pass
        if lat is None:
            lat = _num(fields.get("lat"))
        if lon is None:
            lon = _num(fields.get("lon") or fields.get("long"))

        self._sa_seen += 1
        state = (alt, lat, lon, spd, hdg, bool(on_g), sess.session_id)
        should_print = (self._sa_last != state) or (self._sa_seen % self.sa_log_every == 0)

        if should_print:
            self._sa_last = state
            og = 1 if bool(on_g) else 0
            core_line = (
                f"[RECV SA] {frm}: alt={alt}ft lat={lat} lon={lon} spd={spd} "
                f"hdg={hdg} on_ground={og} SID={sess.session_id}"
            )
            if ts:
                core_line = f"{core_line} ts={ts}"
            print(core_line)
            if self.debug:
                print(text)

    def handle_cc(self, topic: str, text: str):
        """
        Minimal CC display: parse + concise log.
        (Signature/session verification can be added later.)
        """

        if not text or text.strip().lower() in ("null", ""):
            if self.debug:
                print("[CC-DBG] empty/null CC message → skip")
            return

        try:
            fields = parse_ascii_block(text)
        except Exception as e:
            print(f"[CC] Parse error: {e}")
            if self.debug:
                traceback.print_exc()
            return

        needed = ("ts", "from", "to", "type", "body", "mac")
        missing = [k for k in needed if k not in fields]
        if missing:
            print(f"[CC] Missing required fields: {', '.join(missing)}; ignoring.")
            if self.debug:
                print(text)
            return

        raw_from = fields["from"]
        raw_to   = fields["to"]
        frm = normalise_station(raw_from)
        to_s = normalise_station(raw_to)

        if self.only_for_us and to_s not in (self.station_id, "ALL", "BROADCAST", ""):
            if self.debug:
                print(f"[CC-DBG] not for us: to={to_s!r} self={self.station_id!r}")
            return

        ts   = fields["ts"]
        ctyp = fields["type"].upper()
        body = fields.get("body", "")
        mac  = fields.get("mac", "")


        body_show = body if len(body) <= 120 else (body[:117] + "…")
        print(f"[CC] {ts} {frm}→{to_s} {ctyp}: {body_show}")
        self.logger.wire("CC", {"from": frm, "to": to_s, "type": ctyp, "payload": text})

        # --- ACK generation (aircraft side) ---
        if to_s == self.station_id:
            sess = self.sessions.get(frm)

            if not sess:
                if self.debug:
                    print("[ACK-DBG] no session for CC -> skip ACK")
                return

            ref_hash = fields.get("ref_hash")

            if not ref_hash:
                if self.debug:
                    print("[ACK-DBG] no REF_HASH -> cannot ACK")
                return

            ack_word = "WILCO"

            delay = random.uniform(0.2, 1.5)

            def delayed_ack():
                time.sleep(delay)
                event_queue.put({
                    "type": "CC_ACK",
                    "session_key": sess.key,
                    "session_id": sess.session_id,
                    "frm": self.station_id,
                    "to": frm,
                    "ref_hash": ref_hash,
                    "body": ack_word,
                })

            threading.Thread(target=delayed_ack, daemon=True).start()


# -------------------- CLI / main --------------------
def main():
    ap = argparse.ArgumentParser(description="Aviation demo subscriber (MQTTClient wrapper; Paho VERSION2-safe).")
    ap.add_argument("--station", required=True, help='Receiver station name, e.g. "EBBR GND"')
    ap.add_argument("--only-for-us", action="store_true", help="Only show messages addressed to this station (after normalization).")
    ap.add_argument("--mqtt-host", default=BROKER_HOST)
    ap.add_argument("--mqtt-port", type=int, default=BROKER_PORT)
    ap.add_argument("--topic-base", default=TOPIC_BASE)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    # Compute station_id FIRST (no dependency on Subscriber)
    station_id = normalise_station(args.station)
    logger = get_logger(station_id)

    # Adapter: MQTTClient gives (client, userdata, msg)
    def on_message(_client, _userdata, msg):
        payload = msg.payload

        if isinstance(payload, (bytes, bytearray)):
            text = payload.decode("utf-8", "replace")
        else:
            text = str(payload)

        topic = msg.topic  # ✅ FIX 1

        # ✅ Proper routing via Subscriber instance
        if "/cc/" in topic:
            sub.handle_cc(topic, text)

        elif "/pos/sa/" in topic:
            sub.handle_sa(topic, text)

        elif "/sec/key/" in topic:
            sub.handle_key(topic, text)

        elif "/sec/ack/" in topic:
            sub.handle_ack(topic, text)

        else:
            if args.debug:
                print(f"[WARN] Unknown topic: {topic}")


    # Create client using station_id (NOT sub)
    client = MQTTClient(
        client_id=f"listener-{station_id}",
        on_message=on_message,
        enable_logger=args.debug,
        clean_session=True,
    )

    # Now create Subscriber
    sub = Subscriber(
        station_human=args.station,
        topic_base=args.topic_base,
        client=client,
        logger=logger,
        debug=args.debug,
        only_for_us=args.only_for_us,
    )


    client.connect(args.mqtt_host, args.mqtt_port, keepalive=CLIENT_KEEPALIVE)
    
    # Subscribe to topics
    client.subscribe(f"{args.topic_base}/sec/key/#", qos=0)
    print(f"[SUB] {args.topic_base}/sec/key/#")

    client.subscribe(f"{args.topic_base}/sec/ack/#", qos=0)
    print(f"[SUB] {args.topic_base}/sec/ack/#")

    client.subscribe(f"{args.topic_base}/pos/sa/#", qos=0)
    print(f"[SUB] {args.topic_base}/pos/sa/#")

    client.subscribe(f"{args.topic_base}/cc/#", qos=0)
    print(f"[SUB] {args.topic_base}/cc/#")

    client.loop_start()
    # small delay to ensure connection established
    time.sleep(0.2)

    threading.Thread(
        target=publisher_worker,
        args=(client, args.topic_base, logger, args.debug),
        daemon=True
    ).start()

    print("Subscriber running. Press Ctrl+C to stop…")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            client.loop_stop()
        except Exception:
            pass
        logger.close()


if __name__ == "__main__":
    main()

