#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import json
import re
import sys
import time
import os
from pathlib import Path
from datetime import datetime, timezone


from mqtt_client import MQTTClient
from settings import BROKER_HOST, BROKER_PORT

# ---------------------------------------------------------------------
# MQTT recorder / viewer with optional regex filtering:
#   --grep "<regex>"         only show messages whose topic or payload match
#   --ignore-case            case-insensitive matching for --grep
#   --log-filtered           if set, only matched messages are written to --out
#
# New:
#   --out-array <path>       also write a single JSON array file on shutdown
#   Parent directories for --out / --out-array are auto-created
# ---------------------------------------------------------------------

def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def make_args():
    ap = argparse.ArgumentParser(description="Simple MQTT recorder / viewer")
    ap.add_argument("--host", default=BROKER_HOST, help=f"MQTT broker host (default: {BROKER_HOST})")
    ap.add_argument("--port", type=int, default=BROKER_PORT, help=f"MQTT broker port (default: {BROKER_PORT})")
    ap.add_argument("--topic", default="#", help='Topic filter to subscribe (default: "#")')

    # Logging
    ap.add_argument("--out", default="", help="Optional JSONL log file (newline-delimited JSON)")
    ap.add_argument("--out-array", default="", help="Optional JSON array file written on shutdown")

    # Viewing
    ap.add_argument("--view", choices=["ascii", "json", "raw"], default="ascii",
                    help="How to display payloads (default: ascii)")

    # Filtering
    ap.add_argument("--grep", default="", help="Show only messages whose topic or payload match this regex")
    ap.add_argument("--ignore-case", action="store_true", help="Case-insensitive --grep")
    ap.add_argument("--log-filtered", action="store_true",
                    help="If set, only matched messages are written to --out (default logs everything)")
    return ap.parse_args()

def main():


    args = make_args()  # uses your existing parser (now with --out-array)

    # --- helpers ---
    def utc_now_iso():
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    # optional regex filter
    regex = None
    if args.grep:
        flags = re.IGNORECASE if args.ignore_case else 0
        try:
            regex = re.compile(args.grep, flags)
        except re.error as e:
            print(f"[ERROR] Invalid regex for --grep: {e}", file=sys.stderr)
            sys.exit(2)

    # ensure parent dir exists for output files
    def ensure_parent_dir(path: str):
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    # open JSONL stream if requested
    logf = None
    if args.out:
        ensure_parent_dir(args.out)
        logf = open(args.out, "a", encoding="utf-8")

    # buffer for final JSON array (Firefox/openable)
    events = []
    out_array_path = getattr(args, "out_array", "")
    if out_array_path:
        ensure_parent_dir(out_array_path)

    # decide if a message should be shown/logged (by regex)
    def should_show(topic: str, text: str | None, b64: str | None) -> bool:
        if regex is None:
            return True
        haystacks = [topic]
        if text is not None:
            haystacks.append(text)
        if b64:
            haystacks.append(b64)
        for h in haystacks:
            try:
                if regex.search(h):
                    return True
            except Exception:
                pass
        return False

    # JSONL writer (line-by-line)
    def log_jsonl(obj, matched: bool):
        if not logf:
            return
        if args.log_filtered and not matched:
            return
        logf.write(json.dumps(obj, ensure_ascii=False) + "\n")
        logf.flush()

    # single append path (streams JSONL and buffers for array)
    def append_event(meta, text, b64, matched):
        obj = {
            **meta,
            "payload_text": text,
            "payload_b64": b64,
            "matched": matched,
        }
        log_jsonl(obj, matched)
        events.append(obj)

    # --- MQTT on_message ---
    def on_message(_client, _userdata, msg):
        ts = utc_now_iso()
        meta = {
            "time": ts,
            "topic": msg.topic,
            "qos": msg.qos,
            "retain": bool(getattr(msg, "retain", False)),
            "mid": getattr(msg, "mid", 0),
        }

        payload_bytes = msg.payload or b""
        try:
            text = payload_bytes.decode("utf-8")
        except Exception:
            text = None
        b64 = base64.b64encode(payload_bytes).decode("ascii") if payload_bytes else ""

        matched = should_show(msg.topic, text, b64)

        # Console view (ASCII) — only for matched
        if matched:
            print(f"TOPIC: {msg.topic}")
            print(f"TIME : {ts}  qos={meta['qos']}  retain={meta['retain']}  mid={meta['mid']}")
            if args.view == "ascii":
                if text is not None:
                    print(text)
                else:
                    print(f"[non-utf8 payload base64] {b64}")
            elif args.view == "json":
                if text is not None:
                    try:
                        obj = json.loads(text)
                        print(json.dumps(obj, ensure_ascii=False, indent=2))
                    except Exception:
                        print(text)
                else:
                    print(f"[non-utf8 payload base64] {b64}")
            else:  # raw
                print(f"[raw {len(payload_bytes)} bytes]")
            print("")  # separator

        append_event(meta, text, b64, matched)

    # --- MQTT setup & run ---
    client = MQTTClient(client_id=f"recorder-{os.getpid()}", on_message=on_message)
    client.connect(args.host, args.port)
    client.subscribe(args.topic, qos=0)
    client.loop_start()

    print(f"[MQTT] Connected to {args.host}:{args.port}, subscribed to '{args.topic}'")
    if args.out:
        print(f"[LOG ] Streaming JSONL to {args.out}"
              + (" (filtered)" if args.log_filtered else " (all messages)"))
    if out_array_path:
        print(f"[LOG ] Will write JSON array on shutdown to {out_array_path}")
    if regex:
        print(f"[GREP] Showing only messages that match: {args.grep!r}"
              + (" (ignore-case)" if args.ignore_case else ""))

    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\n[INTERRUPT] Stopping recorder…")
    finally:
        # 1) Disconnect first so the Paho loop thread can exit cleanly
        try:
            # Prefer a friendly wrapper if your MQTTClient exposes it
            if hasattr(client, "disconnect"):
                client.disconnect()
            else:
                client._client.disconnect()
        except Exception:
            pass

        # 2) Now stop/join the background loop thread
        try:
            client.loop_stop()   # your wrapper typically joins its thread
        except KeyboardInterrupt:
            # Swallow a second ^C so we still flush logs to disk
            pass
        except Exception:
            pass

        # 3) Write final JSON array (Firefox-friendly) if requested
        if out_array_path:
            try:
                os.makedirs(os.path.dirname(out_array_path) or ".", exist_ok=True)
                tmp = out_array_path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(events, f, ensure_ascii=False, indent=2)
                    f.write("\n")
                os.replace(tmp, out_array_path)
                print(f"[LOG ] JSON array written to {out_array_path} ({len(events)} events)")
            except Exception as e:
                print(f"[ERROR] Failed to write JSON array: {e}")

        # 4) Close JSONL stream if used
        if logf:
            try:
                logf.flush()
                logf.close()
            except Exception:
                pass

        print("[INFO] Recorder stopped cleanly.")


if __name__ == "__main__":
    main()
