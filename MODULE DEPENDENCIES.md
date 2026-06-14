# Module Dependencies – Secure Aviation Messaging Prototype

This document describes module-level dependencies, import relationships, responsibilities, and interaction patterns across the entire codebase.

---

## 1. High-Level Dependency Graph

```
scripts/scenario_player.py
   ├── core/messages.py
   ├── core/comm_state.py
   ├── core/registry.py
   ├── core/logger.py
   ├── encryption/crypto.py
   ├── mqtt_client.py
   ├── utils/station_norm.py
   └── settings.py

scripts/demo_subscriber.py
   ├── core/messages.py
   ├── core/comm_state.py
   ├── core/registry.py
   ├── core/logger.py
   ├── encryption/crypto.py
   ├── mqtt_client.py
   ├── utils/station_norm.py
   ├── config/station_keys.py
   └── settings.py

scripts/mqtt_recorder.py
   ├── mqtt_client.py
   └── settings.py

scripts/add_actor.py
   ├── cryptography (Ed25519PrivateKey, X25519PrivateKey)
   ├── encryption/crypto.py
   └── config/publicKeys.json (writes)

scripts/add_aircraft.py
   ├── utils/regnorm.py
   └── config/aircraft_db.json (writes)

scripts/build_scenario_from_tables.py
   ├── utils/station_norm.py
   ├── utils/regnorm.py
   └── CSV input tables

core/registry.py
   ├── encryption/crypto.py
   ├── config/publicKeys.json (reads)
   └── ~/AviationLocalKeys/ (reads private keys)

encryption/crypto.py
   ├── settings (lazy import inside compute_mac())
   └── encryption/ascon.py (lazy import — ASCON-MAC only)
```

---

## 2. Module-by-Module Dependencies

---

### 2.1 `encryption/crypto.py`

#### Provides

* Ed25519 signing (`sign_detached_b64u`) & verification (`ed25519_verify`)
* X25519 key wrapping/unwrapping (`wrap_session_key`, `unwrap_session_key`) via ChaCha20-Poly1305 AEAD
* BLAKE3 keyed MAC + algorithm-agnostic `compute_mac()` / `compute_mac_b64u()`
* XOR-obfuscated MAC verification (`dec_hash()`)
* URL-safe Base64 helpers (`b64u_to_bytes`, `bytes_to_b64u`)
* Session primitives (`random_session_key`, `random_session_id_b64u`)

#### Depends on

* `base64`, `secrets` (stdlib)
* `blake3`
* `cryptography` (Ed25519, X25519, ChaCha20-Poly1305)
* `encryption.ascon` (lazy import — only when `settings.MAC_ALG == "ASCON-MAC"`)
* `settings` (lazy import inside `compute_mac()`)

#### Used by

* `scripts/scenario_player.py` (sign/wrap/MAC)
* `scripts/demo_subscriber.py` (verify/unwrap/MAC)
* `core/registry.py` (Base64 helpers)
* `scripts/add_actor.py` (Base64 helpers)
* `config/station_keys.py` (Base64 helpers)

#### Notes

Core security module. Switching MAC algorithm requires only changing `settings.MAC_ALG`.

---

### 2.2 `encryption/ascon.py`

#### Provides

* Vendored ASCON-MAC, ASCON hash, ASCON-AEAD128.

#### Depends on

* Nothing (pure Python).

#### Used by

* `encryption/crypto.py` (lazy import via `from encryption.ascon import ascon_mac`).

#### Notes

Never modify. Only `ascon_mac` is used by this project.

---

### 2.3 `core/messages.py`

#### Provides

* ASCII payload builders: `ascii_key()`, `ascii_sa()`, `ascii_cc()`, `ascii_ack()`
* KEY wire-format signing helpers: `build_key_core()`, `key_signing_material()`
* Wire parser: `parse_ascii_block()`
* Serialisation helpers: `serialize()`, `deserialize()`
* Utilities: `utc_now_iso()`, `new_id()`

#### Depends on

* `json`, `time`, `uuid` (stdlib only)

#### Used by

* `scripts/scenario_player.py`
* `scripts/demo_subscriber.py`
* `scripts/build_scenario_from_tables.py`

#### Notes

Contains the canonical definition of every message type's on-wire ASCII format and the KEY signing invariant:

```
ascii_key(core) = build_key_core(…) + "\nKEY SIG: " + sig
```

Sender signs `build_key_core(…).encode("utf-8")`; receiver calls `key_signing_material(raw_payload)` to extract the identical bytes without reconstruction.

---

### 2.4 `core/comm_state.py`

#### Provides

* `SessionEntry` dataclass — `(session_id: str, key: bytes)`
* `SessionBook` — generic per-key session store (`get`, `put`, `drop`)
* `AircraftSessionBook` — aircraft-side store with current-station tracking and handover deduplication

#### Depends on

* `utils.station_norm.normalise_station` (deferred import)

#### Used by

* `scripts/demo_subscriber.py` — ground stations use `SessionBook` keyed by aircraft ID
* `scripts/scenario_player.py` — aircraft uses `AircraftSessionBook` keyed by station ID

---

### 2.5 `core/registry.py`

#### Provides

* `get_pubkeys(actor_id)` → `(ed25519_pub: bytes, x25519_pub: bytes)`
* `load_private_keys(actor_id)` → `(ed25519_priv: bytes, x25519_priv: bytes)`

#### Depends on

* `encryption.crypto` (b64u helpers)
* `config/publicKeys.json` (reads)
* `~/AviationLocalKeys/<ID>/` (reads private keys)

#### Used by

* `scripts/demo_subscriber.py`
* `scripts/scenario_player.py`

---

### 2.6 `core/logger.py`

#### Provides

* `get_logger(component, log_dir)` → `Logger`
* `Logger.wire(msg, data)` — always written
* `Logger.event(msg, data)` — written at `LOG_LEVEL >= LIMITED`
* `Logger.debug(msg, data)` — written at `LOG_LEVEL == FULL`
* `Logger.close()`

#### Depends on

* `settings` (`LOG_LEVEL`, `LOG_FORMAT`, `LOG_BACKUP`)
* `json`, `time`, `pathlib` (stdlib)

#### Used by

* `scripts/demo_subscriber.py`
* `scripts/scenario_player.py`

#### Notes

Writes to `logs/<component>.txt` and/or `logs/<component>.jsonl`. Console output (print) is separate and continues unchanged.

---

### 2.7 `mqtt_client.py`

#### Provides

* Thin abstraction over Paho MQTT (VERSION2 callback API)
* `connect`, `publish`, `subscribe`, `loop_start`, `loop_stop`, `disconnect`

#### Depends on

* `paho.mqtt.client`

#### Used by

* `scripts/scenario_player.py`
* `scripts/demo_subscriber.py`
* `scripts/mqtt_recorder.py`

---

### 2.8 `config/station_keys.py`

#### Provides

* `get_priv_for_station(station_id)` → `(ed25519_priv: bytes, x25519_priv: bytes)`
* Multiple fallback search paths (env var, `~/AviationLocalKeys`, project dir, legacy formats)

#### Depends on

* `encryption.crypto` (`b64u_to_bytes`)
* `utils.station_norm`
* Filesystem

#### Used by

* `scripts/demo_subscriber.py` (mandatory on startup)

#### Notes

If keys are missing, the listener refuses to start with a full diagnostic.

---

### 2.9 `config/publicKeys.json`

Public Ed25519 + X25519 keys for all actors. Written by `scripts/add_actor.py`, read by `core/registry.py`.

---

### 2.10 `utils/station_norm.py`

#### Provides

* `normalise_station(name)` — canonical internal name (e.g. `"EBBR GND"` → `"EBBR_GND"`)
* `pretty_station(name)` — display-only label. Never use for addressing.

#### Used by

* `scripts/demo_subscriber.py`
* `scripts/scenario_player.py`
* `core/comm_state.py` (deferred)
* `scripts/build_scenario_from_tables.py`
* `config/station_keys.py`

---

### 2.11 `utils/regnorm.py`

#### Provides

* `normalise_reg(reg)` — `"OO-ABC"` → `"OOABC"`

#### Used by

* `scripts/scenario_player.py`
* `scripts/add_aircraft.py`
* `scripts/build_scenario_from_tables.py`

---

### 2.12 `utils/registry.py`

#### Provides

* LRU-cached `load_airports_db()`, `load_aircraft_db()`

#### Used by

* `utils/station_norm.py`

---

### 2.13 `scripts/demo_subscriber.py`

#### Depends on

* `mqtt_client`
* `core.registry`
* `encryption.crypto`
* `core.comm_state`
* `core.messages`
* `core.logger`
* `utils.station_norm`
* `config.station_keys`
* `settings`

#### Provides

* Secure message receiver for each ATSU
* KEY/SA/CC parsing and signature/MAC verification
* Address filtering (`--only-for-us`)
* Structured log output via `core.logger`

---

### 2.14 `scripts/scenario_player.py`

#### Depends on

* `mqtt_client`
* `core.registry`
* `encryption.crypto`
* `core.comm_state`
* `core.messages`
* `core.logger`
* `utils.station_norm`
* `settings`

#### Provides

* Aircraft simulator: KEY/SA/CC message production with wall-clock scheduling
* CONTACT-driven session handover
* Gaussian CC jitter injection

---

### 2.15 `scripts/mqtt_recorder.py`

#### Depends on

* `mqtt_client`
* `settings`

#### Provides

* Passive capture of all MQTT traffic. No cryptography.

---

### 2.16 `scripts/add_actor.py`

#### Depends on

* `cryptography` (Ed25519PrivateKey, X25519PrivateKey, serialization)
* `encryption.crypto` (`bytes_to_b64u`)
* `config/publicKeys.json` (reads and writes)
* Filesystem (`~/AviationLocalKeys/<ID>/`)

#### Provides

* Generation of new actor identity (Ed25519 + X25519 keypairs)
* Private key storage (chmod 600)
* Public key registry update (with `.bak` backup)

---

### 2.17 `scripts/build_scenario_from_tables.py`

#### Depends on

* `utils.station_norm`
* `utils.regnorm`
* CSV files

#### Provides

* Conversion from SA/CC CSV tables → scenario JSON for `scenario_player.py`

---

## 3. Runtime Interaction Summary

| Component | Receives From | Sends To | Notes |
|---|---|---|---|
| `scenario_player.py` | scenario JSON | MQTT broker | Signs & publishes KEY/SA/CC; writes to logger |
| `demo_subscriber.py` | MQTT broker | stdout + logger files | Verifies, parses, filters; publishes ACKs |
| `mqtt_recorder.py` | MQTT broker | log files | Passive recorder — no crypto |
| `add_actor.py` | user | FS + publicKeys | Generates keypairs |
| `build_scenario_from_tables.py` | CSV files | scenario JSON | Preprocessing tool |

---

## 4. Cryptographic Data Dependencies

| Operation | Requires | Provided By |
|---|---|---|
| Sign KEY | aircraft private Ed25519 key | `scenario_player` + `encryption.crypto` |
| Verify KEY sig | sender Ed25519 pubkey + raw wire bytes | `publicKeys.json` + `core.registry` + `core.messages.key_signing_material()` |
| Wrap session key | recipient X25519 pubkey | `encryption.crypto.wrap_session_key()` |
| Unwrap KEY | station private X25519 key | `demo_subscriber` + `encryption.crypto` |
| MAC SA/CC | session key (32 bytes) | `encryption.crypto.compute_mac_b64u()` |
| MAC algorithm | `settings.MAC_ALG` | `encryption.crypto.compute_mac()` |

---

## 5. Topic Dependencies

```
aviation/sec/key/<aircraft>     scenario_player publishes, demo_subscriber subscribes
aviation/pos/sa/<aircraft>      scenario_player publishes, demo_subscriber subscribes
aviation/cc/<type>/<aircraft>   scenario_player publishes, demo_subscriber subscribes
aviation/sec/ack/<station>      demo_subscriber publishes (not subscribed by scenario_player)
#                               mqtt_recorder subscribes (all traffic)
```

---

## 6. File-Level Dependency Summary

| File | Reads | Writes | Uses |
|---|---|---|---|
| `scripts/demo_subscriber.py` | private keys, publicKeys.json | `logs/<station>.{txt,jsonl}` | mqtt, core, encryption, settings |
| `scripts/scenario_player.py` | publicKeys.json, scenario JSON | `logs/<aircraft>.{txt,jsonl}` | mqtt, core, encryption, settings |
| `scripts/mqtt_recorder.py` | — | `scenario_log.json` | mqtt, settings |
| `core/registry.py` | publicKeys.json, private keys | — | encryption.crypto |
| `scripts/add_actor.py` | publicKeys.json | publicKeys.json + private keys | cryptography lib, encryption.crypto |
| `scripts/add_aircraft.py` | aircraft_db | aircraft_db | utils.regnorm |
| `scripts/build_scenario_from_tables.py` | CSV | scenario JSON | utils.station_norm, utils.regnorm |

---
