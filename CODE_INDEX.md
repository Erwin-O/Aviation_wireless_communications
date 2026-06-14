# Code Index – Secure Aviation Messaging Prototype

---

## Architecture at a Glance

```
scripts/scenario_player.py  ──► MQTT Broker ──►  scripts/demo_subscriber.py (one per ATC station)
                                     │
                              scripts/mqtt_recorder.py (passive logger)

Shared libraries
  encryption/crypto.py   (Ed25519 sign, X25519 wrap, BLAKE3/ASCON-MAC)
  encryption/ascon.py    (vendored ASCON — NIST lightweight crypto)
  core/messages.py       (ASCII payload builders, KEY signing, parser)
  core/comm_state.py     (SessionEntry, SessionBook, AircraftSessionBook)
  core/registry.py       (public + private key lookup)
  core/logger.py         (unified file logger)
  mqtt_client.py         (Paho wrapper — root-level module)
```

**MQTT topics:**

| Topic | Publisher | Subscriber |
|---|---|---|
| `aviation/sec/key/<aircraft>` | scenario_player | demo_subscriber |
| `aviation/pos/sa/<aircraft>` | scenario_player | demo_subscriber |
| `aviation/cc/<type>/<aircraft>` | scenario_player | demo_subscriber |
| `aviation/sec/ack/<station>` | demo_subscriber | (not subscribed by scenario_player) |
| `#` | — | mqtt_recorder |

---

## `encryption/` Package

### [`encryption/crypto.py`](encryption/crypto.py)
**Core security module. Modify with extreme care.**

| Symbol | Type | Purpose |
|---|---|---|
| `b64u_to_bytes(s)` | fn | Base64-URL decode → bytes |
| `bytes_to_b64u(b)` | fn | bytes → Base64-URL string (no padding) |
| `random_session_id_b64u()` | fn | Generate random session ID (16 bytes) |
| `random_session_key()` | fn | Generate symmetric session key (32 bytes) |
| `compute_mac(key, data)` | fn | Algorithm-agnostic MAC; dispatches on `settings.MAC_ALG` (32 b BLAKE3, 16 b ASCON-MAC) |
| `compute_mac_b64u(key, data)` | fn | `compute_mac()` → base64url string |
| `sign_detached_b64u(priv, data)` | fn | Ed25519 detached signature → base64url |
| `ed25519_verify(pub_b64u, data, sig_b64u)` | fn | Ed25519 verify (base64url inputs) |
| `wrap_session_key(x_priv, x_pub, skey)` | fn | X25519 ECDH + ChaCha20-Poly1305 encrypt session key |
| `unwrap_session_key(x_priv, x_pub, wrapped_b64u)` | fn | Inverse of wrap: decrypt session key |
| `dec_hash(key, data, sig_b64u)` | fn | Verify keyed MAC on SA/CC payloads |
| `_hash_keystream(key, sid, n)` | fn | BLAKE3 keystream from key + session_id |

**Dependencies:** `base64`, `secrets`, `blake3`, `cryptography` (Ed25519, X25519, ChaCha20-Poly1305), `encryption.ascon` (lazy import when MAC_ALG = "ASCON-MAC"), `settings` (lazy import)

---

### [`encryption/ascon.py`](encryption/ascon.py)
Vendored ASCON implementation (NIST Lightweight Crypto standard). Source: [meichlseder/pyascon](https://github.com/meichlseder/pyascon). **Never modify.**

| Symbol | Type | Purpose |
|---|---|---|
| `ascon_mac(key, message)` | fn | ASCON-MAC: 16-byte key → 16-byte tag |
| `ascon_hash(message, ...)` | fn | ASCON hash / XOF |
| `ascon_encrypt(key, nonce, ad, plaintext)` | fn | ASCON-AEAD128 authenticated encryption |
| `ascon_decrypt(key, nonce, ad, ciphertext)` | fn | ASCON-AEAD128 authenticated decryption |

Only `ascon_mac` is used. Imported lazily inside `compute_mac()` when `settings.MAC_ALG == "ASCON-MAC"`.

---

## `core/` Package

### [`core/messages.py`](core/messages.py)
Wire-format utilities: canonical KEY signing string, ASCII payload builders, ASCII parser, and serialisation helpers.

| Symbol | Type | Purpose |
|---|---|---|
| `utc_now_iso()` | fn | Current UTC timestamp as ISO string |
| `new_id()` | fn | Generate UUID4 string |
| `serialize(obj)` | fn | Compact JSON serialisation |
| `deserialize(s)` | fn | JSON decode → dict |
| `build_key_core(ts, frm, to, pubkey_b64u, session_id, wrapped)` | fn | Newline-separated signing string for KEY messages (6 labelled lines, everything above the KEY SIG line) |
| `key_signing_material(raw_payload)` | fn | Strip KEY SIG line from a received raw payload; use on receiver side for Ed25519 verification |
| `ascii_key(core)` | fn | Compose full KEY wire payload: `build_key_core(…)` + `KEY SIG:` line |
| `ascii_sa(core, sig_b64)` | fn | Build SA ASCII block (8 data fields + SIG) |
| `ascii_cc(core, sig_b64)` | fn | Build CC ASCII block (5 fields + ENC_HASH) |
| `ascii_ack(core, sig_b64)` | fn | Build ACK ASCII block (5–6 fields + SIG; REF_HASH optional) |
| `parse_ascii_block(payload)` | fn | Parse colon-delimited ASCII wire frame → dict. Handles KEY, SA, CC, ACK. |

**KEY signing invariant:** `ascii_key()` = `build_key_core(…)` + `"\nKEY SIG: " + sig`. The sender signs `build_key_core(…).encode("utf-8")`; the receiver calls `key_signing_material(raw_payload)` to extract the identical bytes from the wire without reconstruction.

**Dependencies:** `json`, `time`, `uuid` (standard library only)

---

### [`core/comm_state.py`](core/comm_state.py)
Session state management for both aircraft and ground station sides.

| Symbol | Type | Purpose |
|---|---|---|
| `SessionEntry` | dataclass | Single active session: `session_id: str`, `key: bytes` |
| `SessionBook` | class | Generic per-key session store: `get()`, `put()`, `drop()` |
| `AircraftSessionBook` | class | Extends `SessionBook`: tracks current ground station and deduplicates handover events |

**`AircraftSessionBook` methods:**

| Method | Purpose |
|---|---|
| `current_station()` | Returns normalised name of active ground station |
| `set_station(station)` | Update active station (normalises input) |
| `get_session(station)` | Look up session for a station |
| `put_session(station, entry)` | Store session for a station |
| `drop_session(station)` | Remove session for a station |
| `already_handover(old, new, t_s)` | Deduplicates handover events at the same scenario second |

**Dependencies:** `utils.station_norm.normalise_station` (deferred import)

---

### [`core/registry.py`](core/registry.py)
Public and private key lookup from `config/publicKeys.json` and `~/AviationLocalKeys/`.

| Symbol | Type | Purpose |
|---|---|---|
| `get_pubkeys(actor_id)` | fn | Returns `(ed25519_pub: bytes, x25519_pub: bytes)` from registry |
| `load_private_keys(actor_id)` | fn | Returns `(ed25519_priv: bytes, x25519_priv: bytes)` from `~/AviationLocalKeys/<ID>/` |
| `_norm(actor_id)` | fn | Normalise actor ID for registry lookups |
| `_load_registry()` | fn | Load and return parsed `publicKeys.json` |

**Dependencies:** `encryption.crypto` (b64u helpers), `config/publicKeys.json`, `~/AviationLocalKeys/`

---

### [`core/logger.py`](core/logger.py)
Unified file logger. All scripts use this instead of writing log files manually.

| Symbol | Type | Purpose |
|---|---|---|
| `get_logger(component, log_dir)` | fn | Return a new `Logger` writing to `logs/<component>.{txt,jsonl}` |
| `Logger.wire(msg, data)` | method | Log raw wire payload — always written (lowest level) |
| `Logger.event(msg, data)` | method | Log key event (session, handover, error) — written at `LOG_LEVEL >= LIMITED` |
| `Logger.debug(msg, data)` | method | Verbose debug — written at `LOG_LEVEL == FULL` only |
| `Logger.close()` | method | Flush and close log files |

Behaviour is controlled by `settings.py`:

| Setting | Values | Effect |
|---|---|---|
| `LOG_LEVEL` | `WIRE` / `LIMITED` / `FULL` | Minimum event level written to file |
| `LOG_FORMAT` | `TXT` / `JSON` / `BOTH` | Writes `.txt`, `.jsonl`, or both |
| `LOG_BACKUP` | `True` / `False` | Renames existing log to `.prev` on startup |

**Note:** `Logger` writes to log files only. Console output is left to the existing `print()` calls in each script — Terminal windows capture those via `tee`.

---

## Root-Level Python Modules

### [`mqtt_client.py`](mqtt_client.py)
Thin wrapper over Paho MQTT with Callback API VERSION2.

| Symbol | Type | Purpose |
|---|---|---|
| `MQTTClient` | class | Wraps `paho.mqtt.client`; exposes `connect`, `publish`, `subscribe`, `loop_start`, `loop_stop`, `disconnect`, `is_connected`, `set_handlers` |

**Dependencies:** `paho.mqtt.client`, `json`, `threading`, `uuid`

---

### [`settings.py`](settings.py)
Central runtime configuration. All scripts pull their defaults from here.

| Setting | Default | Purpose |
|---|---|---|
| `BROKER_HOST` | `"127.0.0.1"` | MQTT broker hostname |
| `BROKER_PORT` | `1883` | MQTT broker port |
| `CLIENT_KEEPALIVE` | `60` | MQTT keepalive (seconds) |
| `TOPIC_BASE` | `"aviation"` | Root prefix for all MQTT topics |
| `MAC_ALG` | `"BLAKE3"` | Data-plane MAC algorithm (`"BLAKE3"` or `"ASCON-MAC"`) |
| `KEY_SIG_ALG` | `"Ed25519"` | Control-plane signing algorithm label |
| `REQUIRE_KEY_SIG` | `False` | Enforce Ed25519 signature on KEY before accepting session |
| `LOG_LEVEL` | `"LIMITED"` | Logger verbosity: `WIRE` / `LIMITED` / `FULL` |
| `LOG_FORMAT` | `"BOTH"` | Logger output format: `TXT` / `JSON` / `BOTH` |
| `LOG_BACKUP` | `True` | Rename existing log to `.prev` on startup |

---

### [`pyproject.toml`](pyproject.toml)
Declares the repository as an editable Python package. Run once after cloning:

```
pip install -e .
```

This adds the repo root to `sys.path` via the venv's site-packages, making all packages (`core`, `encryption`, `config`, `utils`) and root-level modules (`settings`, `mqtt_client`) importable from any script without `sys.path` hacks.

---

## `config/` Package

### [`config/station_keys.py`](config/station_keys.py)
Loads station private keys from the filesystem with multiple fallback paths.

| Symbol | Type | Purpose |
|---|---|---|
| `get_priv_for_station(station_id)` | fn | Returns `(ed25519_priv: bytes, x25519_priv: bytes)` for a station. Searches env dir → `~/AviationLocalKeys` → project dir → legacy `.b64` files → CSV. Raises `FileNotFoundError` with full diagnostic if not found. |

**Search order:**
1. `$AVIATION_KEYS_DIR/<STATION>/`
2. `~/AviationLocalKeys/<STATION>/`
3. `<repo>/AviationLocalKeys/<STATION>/`
4. Legacy flat `.b64` files
5. Legacy CSV (`privateKeys.csv`, `private_keys.csv`)

### [`config/publicKeys.json`](config/publicKeys.json)
JSON registry of all public keys. Written by `add_actor.py`.

```json
{
  "schema_version": 1,
  "actors": {
    "OOABC": {
      "type": "aircraft",
      "pubkey_ed25519": "<base64url 32 bytes>",
      "pubkey_x25519":  "<base64url 32 bytes>"
    }
  }
}
```

### [`config/aircraft_db.json`](config/aircraft_db.json)
Aircraft metadata: icao24, registration, type_code, model, operator, country. Written by `add_aircraft.py`.

### [`config/airports_db.json`](config/airports_db.json)
Airport metadata and en-route unit definitions. Used by `utils/station_norm.py` for station name resolution.

---

## `utils/` Package

### [`utils/station_norm.py`](utils/station_norm.py)
DB-backed ATC station name normaliser. **Central to all internal addressing.**

| Symbol | Type | Purpose |
|---|---|---|
| `normalise_station(name)` | fn | **Main internal API:** `"EBBR GND"` → `"EBBR_GND"` |
| `pretty_station(name)` | fn | **Display-only:** `"EBBR_GND"` → `"EBBR GND"`. Never use for internal addressing. |

All internal code uses normalised names. `pretty_station()` is the single point where human-readable output is produced.

Has a built-in CLI tester: `python3 -m utils.station_norm "EBBR GND"`.

### [`utils/regnorm.py`](utils/regnorm.py)

| Symbol | Type | Purpose |
|---|---|---|
| `normalise_reg(reg)` | fn | `"OO-ABC"` → `"OOABC"` (strip dashes/spaces, uppercase) |

### [`utils/registry.py`](utils/registry.py)
LRU-cached loaders for the JSON databases.

| Symbol | Type | Purpose |
|---|---|---|
| `load_airports_db()` | fn | Load and cache `airports_db.json` |
| `load_aircraft_db()` | fn | Load and cache `aircraft_db.json` |

---

## `scripts/` — Runnable Scripts

### [`scripts/demo_subscriber.py`](scripts/demo_subscriber.py)
**ATC ground station listener.** One instance per station.

**Key functions:**

| Symbol | Purpose |
|---|---|
| `publish_ack(…, logger)` | Build and publish a MAC-signed ACK; logs wire payload via `logger.wire()` |
| `publisher_worker(client, topic_base, logger)` | Background thread: dequeues SESSION_ACK and CC_ACK events |
| `Subscriber.handle_key()` | Verify Ed25519 sig via `key_signing_material()`, unwrap session key, store session, queue SESSION_ACK; logs session via `logger.event()` |
| `Subscriber.handle_sa()` | Check session exists, parse position, print on state change |
| `Subscriber.handle_cc()` | Display CC content, log wire payload, queue CC_ACK if addressed to us |
| `Subscriber.handle_ack()` | Log incoming ACKs |
| `main()` | CLI entry point; creates logger, sets up MQTT client + Subscriber |

**Session state:** `SessionBook` / `SessionEntry` from `core.comm_state`.

**CLI flags:** `--station`, `--only-for-us`, `--mqtt-host`, `--mqtt-port`, `--topic-base`, `--debug`

---

### [`scripts/scenario_player.py`](scripts/scenario_player.py)
**Aircraft simulator.** Reads scenario JSON and publishes KEY/SA/CC events with realistic timing.

**Session state:** `AircraftSessionBook` / `SessionEntry` from `core.comm_state`.

**Key functions:**

| Symbol | Purpose |
|---|---|
| `detect_contact_target(text)` | Extract target station from CONTACT body |
| `_draw_cc_jitter()` | Sample Gaussian jitter N(0, σ=5s), clamped ±15s |
| `ensure_key_for_station(…, logger)` | Generate session, wrap key, sign with `build_key_core()`, publish KEY; logs via `logger.wire()` + `logger.event()` |
| `publish_sa(…, logger)` | MAC-authenticated SA → `aviation/pos/sa/<aircraft>`; logs via `logger.wire()` |
| `publish_cc(…, logger)` | MAC-authenticated CC → `aviation/cc/<type>/<aircraft>`; handles CONTACT handover, logs via `logger.wire()` / `logger.event()` |
| `main()` | Parse scenario JSON, create logger, drive event loop with wall-clock scheduling |

**MAC:** `compute_mac_b64u()` dispatches on `settings.MAC_ALG`.

**Important:** Time is divided by 1000 to speed up the demo (`sleep((target - now)/1000)`). Remove the division for real-time operation.

**CLI flags:** `scenario_json` (positional), `--publish`, `--mqtt-host`, `--mqtt-port`, `--topic-base`, `--debug`

---

### [`scripts/mqtt_recorder.py`](scripts/mqtt_recorder.py)
Passive MQTT recorder. No cryptography — subscribes to `#` and logs everything.

**CLI flags:** `--host`, `--port`, `--topic`, `--out` (JSONL), `--out-array` (JSON array on shutdown), `--view` (ascii/json/raw), `--grep` (regex), `--ignore-case`, `--log-filtered`

---

### [`scripts/add_actor.py`](scripts/add_actor.py)
Key generation and registration tool.

- Generates Ed25519 + X25519 keypairs
- Saves private keys to `~/AviationLocalKeys/<ACTOR_ID>/` (chmod 600)
- Writes/updates public keys in `config/publicKeys.json` (with `.bak` backup)

**Commands:** `add <actor_id> <actor_type> [--overwrite]`, `list`

---

### [`scripts/add_aircraft.py`](scripts/add_aircraft.py)
Aircraft metadata management for `config/aircraft_db.json`.

---

### [`scripts/build_scenario_from_tables.py`](scripts/build_scenario_from_tables.py)
Converts SA + CC CSV files into a scenario JSON for `scenario_player.py`.

**CLI flags:** `--sa`, `--cc`, `--out`, `--aircraft`, `--station`, `--sa-delim`, `--cc-delim`

---

### [`scripts/visualise_flight.py`](scripts/visualise_flight.py)
Post-run flight visualisation from the MQTT recorder log. Generates an animated Folium map and a matplotlib trajectory plot.

---

### [`scripts/fetch_db_from_github.py`](scripts/fetch_db_from_github.py)
Bootstrap tool: fetches `aircraft_db.json` from a GitHub raw URL.

---

## Shell Scripts (`visualisation/`)

### [`visualisation/launch_all_listeners.sh`](visualisation/launch_all_listeners.sh)
Opens a macOS Terminal window per station and starts `demo_subscriber.py --only-for-us`. Logs to `logs/<STATION>.log` via `tee`.

### [`visualisation/stop_all_listeners.sh`](visualisation/stop_all_listeners.sh)
Kills all `demo_subscriber.py` processes and closes their Terminal windows.

### [`visualisation/tile_listeners.sh`](visualisation/tile_listeners.sh)
Tiles all listener windows for side-by-side monitoring.

### [`run_demo.sh`](run_demo.sh)
Quick-start at the repo root: launches listeners, optional recorder, optional scenario player.

### [`stop_demo.sh`](stop_demo.sh)
Stops all demo processes.

---

## Scenarios

| File | Description |
|---|---|
| [`scenarios/commercial_flight_EBBR-EDDF.json`](scenarios/commercial_flight_EBBR-EDDF.json) | Brussels → Frankfurt (aircraft OOABC) |
| [`scenarios/flight_EHAM_EDDM_PHAEX.json`](scenarios/flight_EHAM_EDDM_PHAEX.json) | Amsterdam → Munich (aircraft PHAEX) |

---

## Logs

`logs/` contains two kinds of files:

**Terminal-capture logs** (created by `tee` in `launch_all_listeners.sh`):

| File | Content |
|---|---|
| `logs/<STATION>.log` | All stdout from the listener for that station |
| `logs/mqtt_recorder.out` | All stdout from mqtt_recorder |

**Structured logger files** (created by `core/logger.py`):

| File | Content |
|---|---|
| `logs/<component>.txt` | Human-readable: `<ts> [LEVEL] [component] msg  {data}` |
| `logs/<component>.jsonl` | Machine-readable: one JSON object per line |
| `logs/<component>.prev` | Previous run's log (if `LOG_BACKUP = True`) |
| `logs/scenario_log.json` | JSON array of all MQTT traffic (from mqtt_recorder `--out-array`) |

---

## Dependency Matrix

| Module | Imports from project |
|---|---|
| `encryption/crypto` | `settings` (lazy), `encryption.ascon` (lazy, ASCON-MAC only) |
| `core/comm_state` | `utils.station_norm` (deferred) |
| `core/messages` | — (stdlib only) |
| `core/registry` | `encryption.crypto`, `config/publicKeys.json`, `~/AviationLocalKeys/` |
| `core/logger` | `settings` |
| `utils/regnorm` | — (leaf) |
| `utils/registry` | — (leaf, loads JSON) |
| `utils/station_norm` | `utils.registry` |
| `mqtt_client` | `paho.mqtt` |
| `config/station_keys` | `encryption.crypto`, `utils.station_norm`, filesystem |
| `scripts/demo_subscriber` | `mqtt_client`, `core.registry`, `encryption.crypto`, `core.comm_state`, `core.messages`, `core.logger`, `settings`, `utils.station_norm`, `config.station_keys` |
| `scripts/scenario_player` | `mqtt_client`, `core.registry`, `encryption.crypto`, `core.comm_state`, `core.messages`, `core.logger`, `settings`, `utils.station_norm` |
| `scripts/mqtt_recorder` | `mqtt_client`, `settings` |
| `scripts/add_actor` | `cryptography`, `encryption.crypto`, `config/publicKeys.json` |
| `scripts/add_aircraft` | `config/aircraft_db.json` |
| `scripts/build_scenario_from_tables` | `utils.station_norm`, `utils.regnorm` |
| `scripts/visualise_flight` | `folium`, `matplotlib` |

---

*End of Code Index*
