# Secure Aviation Messaging Prototype – Developer Guide

## 1. Introduction

The **Developer Guide** describes the internal architecture, modules, file structure, data flows, and cryptographic mechanisms of the *Secure Aviation Messaging Prototype*. It is intended for engineers who want to:

* Understand how the system works internally.
* Modify, extend, or customise components.
* Add new stations, aircraft, or message types.
* Debug cryptographic validation, message routing, or scenario behaviour.

---

## 2. System Architecture Overview

```
scripts/scenario_player.py  ──► MQTT Broker ──►  scripts/demo_subscriber.py
                                      │
                               scripts/mqtt_recorder.py

Shared packages
  encryption/   – all cryptographic primitives
  core/         – message format, session state, key registry, logger
  config/       – public-key registry, station private-key loader
  utils/        – station normalisation, aircraft reg normalisation, JSON DB loaders
  mqtt_client.py – Paho wrapper (root-level module)
  settings.py   – runtime configuration (root-level module)
```

### 2.1 Package Layout

```
encryption/
  crypto.py     Ed25519, X25519, BLAKE3/ASCON-MAC
  ascon.py      vendored ASCON (never modify)

core/
  messages.py   ASCII wire builders, KEY signing string, parser
  comm_state.py session state (SessionBook, AircraftSessionBook)
  registry.py   public + private key lookup
  logger.py     unified file logger

config/
  station_keys.py   load local station private keys
  publicKeys.json   public key registry (written by add_actor.py)
  aircraft_db.json  aircraft metadata
  airports_db.json  airport + en-route unit metadata

utils/
  station_norm.py   normalise_station() / pretty_station()
  regnorm.py        normalise_reg()
  registry.py       LRU-cached JSON DB loaders

scripts/          thin CLI entry points
visualisation/    macOS shell scripts (launch, tile, stop)
scenarios/        scenario JSON files
```

### 2.2 High-Level Message Flow

For each outbound message:

1. `scenario_player` constructs raw data.
2. Signs it with **Ed25519** (KEY) or computes **BLAKE3/ASCON-MAC** (SA/CC).
3. Wraps session key with **X25519 + ChaCha20-Poly1305** (KEY only).
4. Publishes via MQTT under structured topics.
5. Ground stations receive, filter, verify, and display messages.

---

## 3. Cryptography Subsystem

Implemented in **`encryption/crypto.py`**.

### 3.1 Key Types

* **Ed25519** → Authentication and integrity via detached signatures.
* **X25519** → Key exchange for secure session key delivery.
* **Session keys** → Symmetric 32-byte keys used to authenticate SA/CC messages.

### 3.2 KEY Message Signing (Option B — wire-format signing)

The Ed25519 signature on a KEY message covers the wire payload directly — everything above the `KEY SIG:` line, newline-separated:

```
TIMESTAMP: <ts>
FROM: <aircraft>
TO: <station>
PUBLIC KEY: <ed25519_pub_b64u>
SESSION ID: <sid>
WRAPPED SESSION KEY: <wrapped_b64u>
```

**Sender** (`scenario_player`):
```python
sign_core = build_key_core(ts, frm, to, pubkey_b64u, sid, wrapped)
sig = sign_detached_b64u(ed25519_priv, sign_core.encode("utf-8"))
payload = ascii_key({…, "key_sig_b64": sig})
```

**Receiver** (`demo_subscriber`):
```python
sign_core = key_signing_material(raw_payload)   # strips KEY SIG line
ok = ed25519_verify(ed_pub_b64u, sign_core, sig)
```

Both functions are in `core/messages.py`. The receiver never reconstructs the signing string from parsed fields — it uses the raw wire bytes, ensuring byte-exact verification.

### 3.3 Session Key Wrapping

Applied only to KEY messages:

```
shared_secret = X25519(sender_x_priv, receiver_x_pub)
wrapped_key   = ChaCha20-Poly1305(key=BLAKE3(shared_secret), plaintext=session_key)
```

`wrap_session_key()` / `unwrap_session_key()` are in `encryption/crypto.py`.

### 3.4 MAC Algorithm Selection

The data-plane MAC is configurable via `settings.MAC_ALG`:

* `"BLAKE3"` (default) — 32-byte keyed MAC; uses the full 32-byte session key.
* `"ASCON-MAC"` — 16-byte tag; uses `session_key[:16]`. `encryption/ascon.py` is vendored (no pip install required).

Switching is done by changing one line in `settings.py`. All MAC computation is centralised in `encryption.crypto.compute_mac()` / `compute_mac_b64u()`; scenario player and subscriber call only those functions.

### 3.5 Station Normalisation

Defined in `utils/station_norm.py`:

* `normalise_station()` — canonical internal name (e.g. `"EBBR GND"` → `"EBBR_GND"`). Used for all internal addressing and key lookups.
* `pretty_station()` — human-readable label for display **only**. Never use for addressing.
* `normalise_reg()` in `utils/regnorm.py` — canonical aircraft registration (e.g. `"OO-ABC"` → `"OOABC"`).

---

## 4. Session State (`core/comm_state.py`)

### 4.1 Data Structures

**`SessionEntry`** (dataclass):
```
session_id: str
key: bytes      # 32-byte symmetric session key
```

**`SessionBook`** — generic store keyed by any string:
```
get(key)  → SessionEntry | None
put(key, entry)
drop(key)
```

**`AircraftSessionBook`** (extends `SessionBook`) — aircraft-side:
```
current_station()               → str
set_station(station)
get_session(station)            → SessionEntry | None
put_session(station, entry)
drop_session(station)
already_handover(old, new, t_s) → bool   (deduplicates handover events)
```

### 4.2 Session Lifecycle

1. Ground station receives a **KEY** message.
2. Verifies the Ed25519 signature via `key_signing_material()`.
3. Unwraps session key with its own X25519 private key.
4. Stores the session in `SessionBook`.
5. All subsequent SA/CC messages require a known session — rejected if none exists.

---

## 5. MQTT Layer

### 5.1 Topic Structure

```
aviation/sec/key/<aircraft>       KEY messages
aviation/pos/sa/<aircraft>        SA position reports
aviation/cc/<type>/<aircraft>     CC control commands
aviation/sec/ack/<station>        ACK replies (subscriber → aircraft)
```

### 5.2 Broker

Default setup (Mosquitto):

* Host: `127.0.0.1`
* Port: `1883`

### 5.3 Note on ACKs

`demo_subscriber` publishes ACKs to `aviation/sec/ack/<to>` but `scenario_player` does not subscribe to that topic. ACKs are one-way in the current prototype — they are logged but not processed by the sender side.

---

## 6. Ground Station Listener (`scripts/demo_subscriber.py`)

### 6.1 Address Filtering

When `--only-for-us` is set:
```python
if to_norm not in (self.station_id, "ALL", "BROADCAST", ""):
    ignore message
```

### 6.2 KEY Handling

1. Parse ASCII block with `parse_ascii_block()`.
2. Verify public key matches registry.
3. Extract signing material with `key_signing_material(raw_payload)`.
4. Verify Ed25519 signature.
5. Unwrap X25519 session key.
6. Store session; queue SESSION_ACK.
7. Log via `logger.event("session learned", …)` and `logger.wire("KEY", …)`.

### 6.3 SA Handling

1. Verify session exists.
2. Parse altitude, position, speed, heading, on-ground flag.
3. Print only when state changes or at periodic intervals.

### 6.4 CC Handling

1. Parse and validate required fields.
2. Display content; log via `logger.wire("CC", …)`.
3. If addressed to this station and session known: queue CC_ACK with random delay.

---

## 7. Scenario Engine (`scripts/scenario_player.py`)

### 7.1 Scenario File Structure

```json
{
  "flight": {
    "aircraft_id": "OOABC",
    "initial_station": "EBBR_GND"
  },
  "events": [ … ]
}
```

### 7.2 Supported Event Types

* **KEY** → explicit session creation for a named station
* **SA** → position report
* **CC** → clearance / request / instruction; `CONTACT` triggers a handover

### 7.3 Timing Jitter

CC timestamps are randomised:
```
t_actual = t_nominal + Normal(μ = 0, σ = 5s), clamped ±15s
```

### 7.4 Logging

A `Logger` is created once in `main()` with `component = aircraft_id`. Wire payloads go to `logger.wire()`, session and handover events go to `logger.event()`.

---

## 8. Unified Logger (`core/logger.py`)

`get_logger(component)` returns a `Logger` that writes structured log files to `logs/`:

| Level | Method | Written when |
|---|---|---|
| WIRE | `logger.wire(msg, data)` | Always (LOG_LEVEL = any) |
| LIMITED | `logger.event(msg, data)` | LOG_LEVEL ∈ {LIMITED, FULL} |
| FULL | `logger.debug(msg, data)` | LOG_LEVEL = FULL only |

File format is controlled by `settings.LOG_FORMAT`:
* `TXT` → `logs/<component>.txt` — human-readable timestamped lines
* `JSON` → `logs/<component>.jsonl` — one JSON object per line
* `BOTH` → both files simultaneously (default)

On startup, existing files are renamed to `.prev` if `settings.LOG_BACKUP = True`.

Console (`print()`) output is separate and continues to be captured by `tee` in the launch scripts.

---

## 9. Configuration & Databases

### 9.1 `config/publicKeys.json`

All public Ed25519 + X25519 identity keys. Written by `add_actor.py`.

### 9.2 `config/aircraft_db.json`

Aircraft metadata (ICAO24, registration, type, operator).

### 9.3 `config/airports_db.json`

Airport and en-route unit metadata. Used by `utils/station_norm.py` for name resolution.

---

## 10. Setup

### 10.1 Editable Install

After cloning, run once inside the venv:

```
pip install -e .
```

This registers the repo root via `pyproject.toml` so all packages and root-level modules are importable from any script without `sys.path` hacks.

### 10.2 Private Keys

Each actor needs a local key directory:
```
~/AviationLocalKeys/<ACTOR_ID>/ed25519_private.key
~/AviationLocalKeys/<ACTOR_ID>/x25519_private.key
```

Generate them with:
```
python3 scripts/add_actor.py add <ACTOR_ID> <type>
```

---

## 11. Extending the System

### 11.1 Adding New Stations

```
python3 scripts/add_actor.py add <STATION_ID> <type>
```

Where `<type>` is one of: `aircraft`, `atc`, `enroute`, `ground`, `test`, `tower`, `uav`.

Then add the station name to `STATIONS` in `visualisation/launch_all_listeners.sh`.

### 11.2 Adding New Message Types

Modify:
* `core/messages.py` — add ASCII builder and update `parse_ascii_block()`
* `scripts/scenario_player.py` — add publish function and event-loop branch
* `scripts/demo_subscriber.py` — add handler and subscribe to new topic

### 11.3 Switching MAC Algorithm

Change `settings.MAC_ALG` to `"ASCON-MAC"`. No other files need updating.

---

## 12. Troubleshooting

### "Could not load private keys"

Check `~/AviationLocalKeys/<STATION>/` for `ed25519_private.key` and `x25519_private.key`.

### "no session known; skip"

The KEY message has not yet arrived or was dropped. Enable `--debug` on the subscriber to see why.

### "KEY signature INVALID — dropped"

The signing material (wire payload above KEY SIG line) did not match between sender and receiver. Check that `build_key_core()` in `scenario_player` and `key_signing_material()` in `demo_subscriber` are using the same raw text.

### Listener windows not closing

```
./visualisation/stop_all_listeners.sh
```

---
