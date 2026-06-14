# core/messages.py
"""
Wire-format utilities: canonical KEY signing string, ASCII payload builders,
ASCII parser, and basic serialisation helpers.

All modules that build, sign, verify, or parse messages import from here.
"""

import json
import time
import uuid
from typing import Any, Dict, Optional


# ---------- basic helpers ----------

def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_id() -> str:
    return str(uuid.uuid4())


def serialize(obj: Any) -> str:
    """Compact JSON serialisation."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def deserialize(s: str) -> Dict[str, Any]:
    return json.loads(s)


# ---------- ASCII payload builders ----------

def ascii_key(core: Dict[str, Any]) -> str:
    """
    Required keys: ts, frm, to, public_key_b64u, session_id, wrapped_key_b64, key_sig_b64
    Wire payload = signed portion (build_key_core) + KEY SIG line.
    """
    signed = build_key_core(
        core["ts"], core["frm"], core["to"],
        core["public_key_b64u"], core["session_id"], core["wrapped_key_b64"],
    )
    return f"{signed}\nKEY SIG: {core['key_sig_b64']}"


def ascii_sa(core: Dict[str, Any], sig_b64: str) -> str:
    """
    Required keys: ts, frm, to, alt_ft, lat, lon, gs_kt, hdg_deg, on_ground
    """
    lines = [
        f"TIMESTAMP: {core['ts']}",
        f"FROM: {core['frm']}",
        f"TO: {core['to']}",
        f"ALTITUDE: {core['alt_ft']}",
        f"POSITION: {core['lat']} LAT {core['lon']} LONG",
        f"SPEED: {core['gs_kt']}",
        f"HEADING: {core['hdg_deg']}",
        f"ON GROUND: {1 if core['on_ground'] else 0}",
        f"SIG: {sig_b64}",
    ]
    return "\n".join(lines)


def ascii_cc(core: Dict[str, Any], sig_b64: str) -> str:
    """
    Required keys: ts, frm, to, cc_type, body
    """
    lines = [
        f"TIMESTAMP: {core['ts']}",
        f"FROM: {core['frm']}",
        f"TO: {core['to']}",
        f"TYPE: {core['cc_type']}",
        f"PAYLOAD: {core['body']}",
        f"ENC_HASH: {sig_b64}",
    ]
    return "\n".join(lines)


def ascii_ack(core: Dict[str, Any], sig_b64: str) -> str:
    """
    Required keys: ts, frm, to, ref_type, session_id, body
    Optional key:  ref_hash
    """
    lines = [
        f"TIMESTAMP: {core['ts']}",
        f"FROM: {core['frm']}",
        f"TO: {core['to']}",
        f"REF_TYPE: {core['ref_type']}",
        f"SESSION ID: {core['session_id']}",
    ]
    if core.get("ref_hash"):
        lines.append(f"REF_HASH: {core['ref_hash']}")
    lines.append(f"BODY: {core['body']}")
    lines.append(f"SIG: {sig_b64}")
    return "\n".join(lines)


# ---------- KEY signing string ----------

def build_key_core(ts: str, frm: str, to: str, pubkey_b64u: str,
                   session_id: str, wrapped: str) -> str:
    """
    The portion of a KEY wire payload that is Ed25519-signed — everything
    above the KEY SIG line.  Identical to what ascii_key() produces without
    its final line.  The sender signs this; the receiver calls
    key_signing_material() to extract the same bytes from the raw payload.
    """
    return "\n".join([
        f"TIMESTAMP: {ts}",
        f"FROM: {frm}",
        f"TO: {to}",
        f"PUBLIC KEY: {pubkey_b64u}",
        f"SESSION ID: {session_id}",
        f"WRAPPED SESSION KEY: {wrapped}",
    ])


def key_signing_material(raw_payload: str) -> str:
    """
    Extract the signed portion from a received KEY wire payload by discarding
    the KEY SIG line.  Use this on the receiver side for Ed25519 verification
    so that exactly the bytes that were sent are verified — no reconstruction.
    """
    lines = []
    for line in raw_payload.splitlines():
        if line.strip().upper().startswith("KEY SIG"):
            break
        lines.append(line)
    return "\n".join(lines)


# ---------- ASCII wire parser ----------

def parse_ascii_block(payload: str) -> Dict[str, Any]:
    """
    Parse an ASCII wire frame (colon-delimited lines) into a dict.

    Handles KEY, SA, CC, and ACK frames.  Unknown fields are silently ignored.
    """
    d: Dict[str, Any] = {}

    for raw in payload.splitlines():
        ln = raw.strip()
        if not ln:
            continue

        if ":" in ln:
            left, _, right = ln.partition(":")
            key = left.strip().upper()
            val = right.strip()
        else:
            # legacy "FROM OOABC" / "TO EBBR GND" (no colon)
            parts = ln.split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts[0].upper(), parts[1].strip()

        if key == "TIMESTAMP":
            d["ts"] = val
        elif key == "FROM":
            d["from"] = val
        elif key == "TO":
            d["to"] = val

        # KEY fields
        elif key == "PUBLIC KEY":
            d["public_key_ascii"] = val
        elif key == "SESSION ID":
            d["session_id"] = val
        elif key == "WRAPPED SESSION KEY":
            d["wrapped_key_b64"] = val
        elif key == "KEY SIG":
            d["key_sig_b64"] = val

        # SA fields
        elif key == "ALTITUDE":
            d["altitude"] = val
        elif key == "POSITION":
            parts = val.split()
            if len(parts) >= 4 and parts[1].upper() == "LAT" and parts[3].upper() == "LONG":
                try:
                    d["lat"] = float(parts[0])
                    d["lon"] = float(parts[2])
                except ValueError:
                    pass
        elif key == "SPEED":
            d["speed"] = val
        elif key == "HEADING":
            d["heading"] = val
        elif key in ("ON GROUND", "ON"):
            if key == "ON" and not val.upper().startswith("GROUND"):
                pass
            else:
                ground_val = val.split(None, 1)[1] if key == "ON" and " " in val else val
                d["on_ground"] = ground_val

        # CC / ACK fields
        elif key == "TYPE":
            d["type"] = val
        elif key == "PAYLOAD":
            d["body"] = val
        elif key == "BODY":
            d["body"] = val
        elif key == "REF_TYPE":
            d["ref_type"] = val
        elif key == "REF_HASH":
            d["ref_hash"] = val

        # Signature fields
        elif key == "SIG":
            d["sig"] = val
        elif key == "ENC_HASH":
            d["sig"] = val

    return d
