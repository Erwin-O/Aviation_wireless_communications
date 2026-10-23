# Code Index – Secure Aviation Messaging Prototype

A file-by-file map of the repository. For *how* the protocol works see
`DEVELOPER GUIDE.md`; for how modules depend on each other see
`MODULE DEPENDENCIES.md`; for running it see `USER GUIDE.md`.

---

## Architecture at a Glance

The repository holds **two implementations**.

| | Conforming | Legacy |
|---|---|---|
| Protocol | `protocol/` package | `core/` + `encryption/crypto.py` |
| Aircraft | `scripts/aircraft.py` | `scripts/scenario_player.py` |
| Station | `scripts/station.py` | `scripts/demo_subscriber.py` |
| Launcher | `visualisation/launch_all_stations.sh` | `visualisation/launch_all_listeners.sh` |
| Run with | `./run_demo.sh` | `./run_demo.sh --legacy` |

The conforming implementation follows Section 3.3 of the IJCIP paper: a
three-message authenticated key agreement, credentials rather than a directory
of known public keys, a challenge exchange binding every command to the
message it answers, and a three-state session model for transfer of control.

The legacy implementation is the earlier prototype. It is kept so that results
produced with it remain reproducible, and it is not where new work goes.

```
aircraft                     broker                    ground station
  |                         (untrusted)                       |
  |---- KEY ----------------------->---------------------------|
  |<--- KEYACK ---------------------<---------------------------|
  |---- KEYCONFIRM ----------------->---------------------------|   established
  |---- SA (LAST_EXEC, CHALLENGE) -->---------------------------|
  |<--- CC:CLEARANCE (IN_REPLY_TO) --<---------------------------|
  |---- ACK ------------------------>---------------------------|
```

---

## `protocol/` Package — the specification

Ten modules, each corresponding to a part of the paper. Nothing here knows
about MQTT except `mqtt_binding.py`, and nothing knows about files except
`identity.py`.

### [`protocol/encoding.py`](protocol/encoding.py) — 155 lines

The wire format (§3.3.1). One field per line: `NAME: value` followed by CRLF.
Printable ASCII only.

- `encode(fields)` / `parse(data)` — strict in both directions. Duplicate
  fields, non-ASCII values and unterminated messages are rejected.
- `authenticated_region(data, authenticator)` — the prefix a signature or tag
  covers, **sliced from the buffer as received**. Nothing is re-encoded, so a
  sender and receiver that disagree about the encoding cannot accidentally
  agree about the authenticated bytes.
- `get` / `require` — field lookup.
- `EncodingError`.

### [`protocol/primitives.py`](protocol/primitives.py) — 262 lines

The equations of §3.3.1–3.3.3, over Ed25519, X25519 and Ascon.

| Function | Paper |
|---|---|
| `derive_ephemeral_scalar(r, kex_secret)` | eq. (1), the NAXOS-style derivation |
| `dh(scalar, peer_public)` | eq. (2) |
| `session_key(shared)` | eq. (3), Ascon-CXOF128 |
| `transcript_hash(m_key, m_keyack)` | eq. (5), with the `0x00` separator |
| `derive_challenge(r, kex_secret)` | eq. (6) |
| `mac` / `verify_mac` | Ascon-Mac, 16-byte key, 16-byte tag |
| `ack_hash(body)` | the ACK digest |
| `sign` / `verify_signature` | Ed25519 |
| `b64u` / `unb64u` | URL-safe Base64, no padding, canonical only |

Domain-separation labels `L_EPH`, `L_CH`, `L_TR`, `L_ACK` and the
customisation string `C_SESSION` are declared here. They share a prefix and
end with a NUL, and no label contains a NUL, so the set is prefix-free.

Sizes: `SESSION_KEY_BYTES = 32`, `MAC_KEY_BYTES = 16`, `TAG_BYTES = 16`,
`CHALLENGE_BYTES = 32`.

### [`protocol/credentials.py`](protocol/credentials.py) — 250 lines

A credential is a signed labelled record carrying `ISSUER`, `SUBJECT`,
`VERIFY_KEY`, `NOT_BEFORE`, `NOT_AFTER`, `PERMITTED_ROLES` and, for a ground
station, `SECTOR`.

- `issue(...)` — build and sign.
- `parse(raw)` → `Credential`.
- `verify(...)` — runs the order §3.3.2 specifies: issuer signature against a
  trust anchor, validity interval, subject against `FROM`, sector scope, and
  only then the message signature. Raises `Rejected` naming the step.
- `Credential.permits(role)` — exact match; a credential listing `CC` permits
  no subtype.
- `default_sector_covers` — exact match or dotted-prefix containment
  (`EBBU` covers `EBBU.NORTH`). Deployments pass their own.

### [`protocol/rejection.py`](protocol/rejection.py) — 60 lines

One vocabulary for refusing a message, so that every test can assert *which*
check refused it.

`Step`: `malformed`, `role_unknown`, `addressee`, `timestamp_window`,
`credential_malformed`, `issuer_unknown`, `issuer_signature`, `validity`,
`subject`, `sector`, `message_signature`, `transcript`, `session_unknown`,
`tag`, `challenge`, `role_not_permitted`, `session_state`, `alt_ref`.

`Rejected(step, detail)` is raised everywhere a message is discarded.

### [`protocol/handshake.py`](protocol/handshake.py) — 326 lines

The three-message establishment (§3.3.2).

- `Initiator` (aircraft): `build_key`, `handle_keyack`, `build_keyconfirm`.
- `Responder` (station): `handle_key`, `build_keyack`, `handle_keyconfirm`.
- `Session` — what a completed handshake yields: peer, credential, key,
  transcript.
- `DEFAULT_WINDOW` — Δt_max, 120 s.

Ephemeral scalars are discarded the moment `K_sess` is derived. No session
identifier appears in any message.

### [`protocol/session.py`](protocol/session.py) — 281 lines

Session state (§3.3.4) and the challenge bookkeeping (§3.3.3).

- `State`: `PENDING`, `ESTABLISHED`, `HANDOVER`.
- `SessionTable`: `open_pending`, `establish`, `begin_handover`, `revert`,
  `expire`, `admits`.
- The four challenge rules as named functions: `arm`, `may_act`,
  `record_execution`, `station_should_resend`, `overdue`.
- `COMMAND_ROLES` — the roles an aircraft acts upon, and therefore the ones
  bound to a challenge and refused during handover.
- Timeouts: `DEFAULT_PENDING_TIMEOUT` 30 s, `DEFAULT_HANDOVER_TIMEOUT` 120 s
  (Δt_ho), `DEFAULT_REPORT_INTERVAL` 30 s (Δt_rep).

### [`protocol/operational.py`](protocol/operational.py) — 283 lines

SA, CC and ACK, and the one door for receipt (§3.3.3).

- `build_sa`, `build_command`, `build_aircraft_cc`, `build_ack`.
- `receive(...)` — structure, session, tag, acceptance window, challenge,
  scope, session state, in that order. Returns `Received` or raises
  `Rejected`.
- `ALT_REFS` — `BARO_QNH`, `BARO_STD`, `GEO_WGS84`, `GEO_EGM96`. A report with
  an absent or unrecognised reference frame is rejected.

### [`protocol/node.py`](protocol/node.py) — 328 lines

Endpoint behaviour, independent of transport. Each method returns the
messages to send, as a list.

- `Aircraft`: `connect`, `handle`, `report`, `tick`.
- `Station`: `handle`, `enqueue`, `nominate`, `tick`.
- `Outbound(to, role, raw)`.

### [`protocol/identity.py`](protocol/identity.py) — 167 lines

Key material and credentials on disk.

- `config/trust_anchors.json` — issuer name → Ed25519 public key. The only
  shared file, and it names authorities, not principals.
- `~/AviationLocalKeys/<ACTOR>/` — `ed25519_private.key`,
  `x25519_private.key`, `credential`.
- `load_identity(actor)` → `Identity`, which spreads into an endpoint with
  `endpoint_kwargs(anchors)`.
- `ensure_keys` reuses existing key files, so material generated by the legacy
  tooling is picked up unchanged.

### [`protocol/mqtt_binding.py`](protocol/mqtt_binding.py) — 74 lines

Topic per role: `aviation/<role>/<addressee>`; a node subscribes to
`aviation/+/<its own name>`.

`check_topic(topic, raw)` compares the role the topic advertises against the
role the message authenticates and refuses any disagreement. The topic is
routing convenience and carries no authority.

---

## `encryption/` Package

### [`encryption/ascon.py`](encryption/ascon.py) — 509 lines

Reference implementation of Ascon (NIST SP 800-232): `ascon_hash`
(Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128), `ascon_mac` (Ascon-Mac,
Ascon-Prf, Ascon-PrfShort), `ascon_encrypt` / `ascon_decrypt`
(Ascon-AEAD128). Used by `protocol/primitives.py` and by the legacy
`crypto.py`. Not modified by this project.

### [`encryption/crypto.py`](encryption/crypto.py) — 224 lines

Legacy cryptographic helpers: Base64, Ed25519 sign/verify, `compute_mac`
(Ascon-Mac), `verify_mac`, X25519 session-key wrap/unwrap. BLAKE3 and the
XOR-keystream `dec_hash` have been removed. Used by the legacy scripts only;
the conforming implementation uses `protocol/primitives.py`.

---

## `core/` Package — legacy

- [`core/messages.py`](core/messages.py) — the older ASCII builders and
  parser. Field names were corrected to `MAC` and `SIGNATURE`.
- [`core/comm_state.py`](core/comm_state.py) — `SessionBook`,
  `AircraftSessionBook`. Superseded by `protocol/session.py`.
- [`core/registry.py`](core/registry.py) — public keys from
  `config/publicKeys.json`, private keys from `~/AviationLocalKeys`.
  Superseded by `protocol/identity.py`.
- [`core/logger.py`](core/logger.py) — the structured logger, used by both.

---

## Root-Level Modules

- [`mqtt_client.py`](mqtt_client.py) — thin wrapper over paho-mqtt v2
  (MQTTv3.1.1, callback API v2). Note that handlers receive paho's own
  `(client, userdata, msg)`.
- [`settings.py`](settings.py) — broker host and port, topic base, log level
  and format. `MAC_ALG` is informational only; the data-plane MAC is
  Ascon-Mac and is no longer selectable.
- [`pyproject.toml`](pyproject.toml) — editable install; finds `core/`,
  `encryption/`, `config/`, `utils/`, `protocol/`.

---

## `config/`

- `trust_anchors.json` — issuers and their public keys. Written by
  `scripts/provision.py`.
- `publicKeys.json` — the legacy directory of principals.
- `aircraft_db.json`, `airports_db.json` — scenario metadata.
- `station_keys.py` — legacy key loading.

---

## `scripts/`

### Conforming

| Script | Lines | What it does |
|---|---|---|
| [`provision.py`](scripts/provision.py) | 181 | Creates an issuing authority and issues credentials for two aircraft and fourteen stations. Idempotent. Verifies what it issued against the anchor it wrote. |
| [`aircraft.py`](scripts/aircraft.py) | 214 | Flies a scenario: establishes, reports, acts, acknowledges, follows nominations. `--verbose`, `--speed`, `--connect-tries`. |
| [`station.py`](scripts/station.py) | 171 | A ground station: answers handshakes, verifies everything, names the check that refused what it discards, plays its own controller script. |
| [`replay.py`](scripts/replay.py) | 148 | The whole flight with no broker and no sockets. Prints message counts and bytes. |
| [`_scenario.py`](scripts/_scenario.py) | 166 | Translates the old scenario files: KEY and ACK rows dropped, CONTACT rows become nominations by the incumbent station. |
| [`_display.py`](scripts/_display.py) | 38 | Renders a message field by field for `--verbose`, eliding over-long Base64. |

### Legacy and shared

- [`demo_subscriber.py`](scripts/demo_subscriber.py) — the old listener.
- [`scenario_player.py`](scripts/scenario_player.py) — the old player, which
  published both sides of every exchange.
- [`mqtt_recorder.py`](scripts/mqtt_recorder.py) — records all traffic to a
  JSON array. Protocol-agnostic; works with both.
- [`add_actor.py`](scripts/add_actor.py), [`add_aircraft.py`](scripts/add_aircraft.py),
  [`build_scenario_from_tables.py`](scripts/build_scenario_from_tables.py),
  [`visualise_flight.py`](scripts/visualise_flight.py),
  [`fetch_db_from_github.py`](scripts/fetch_db_from_github.py) — tooling,
  unchanged.

---

## Shell Scripts

- [`run_demo.sh`](run_demo.sh) — provisions, launches stations and the
  aircraft, optionally the recorder, and tiles the windows.
  `--legacy`, `--speed`, `--verbose`, `--no-provision`, `--foreground`.
- [`stop_demo.sh`](stop_demo.sh) — stops everything.
- [`visualisation/launch_all_stations.sh`](visualisation/launch_all_stations.sh) — one window per station.
- [`visualisation/launch_aircraft.sh`](visualisation/launch_aircraft.sh) — a window for the aircraft.
- [`visualisation/launch_all_listeners.sh`](visualisation/launch_all_listeners.sh) — the legacy equivalent.
- [`visualisation/stop_all_listeners.sh`](visualisation/stop_all_listeners.sh) — ends processes **by PID file**, waits for them, then closes the windows by name.
- [`visualisation/tile_listeners.sh`](visualisation/tile_listeners.sh) — tiles the windows.

---

## `tests/` — 148 tests

| File | Tests | Covers |
|---|---|---|
| `test_encoding.py` | 15 | the wire format, one-parse, the authenticated region |
| `test_primitives.py` | 25 | the equations, domain separation, tags |
| `test_credentials.py` | 23 | issuing, and each step of the verification order |
| `test_handshake.py` | 27 | the three messages, and each way they are refused |
| `test_operational.py` | 39 | the challenge exchange, session states, receipt order |
| `test_node.py` | 19 | whole exchanges over an in-process network |

```bash
python -m unittest discover -s tests -t . -v
```

---

## Scenarios and Logs

`scenarios/*.json` — a flight: SA rows and CC rows on a clock from 00:00:00.
Two are provided, Brussels–Frankfurt (OOABC) and Amsterdam–Munich (PHAEX).

`logs/` — per-station capture (`<STATION>.log`), structured logger output,
the recorder's JSON array, and `logs/pids/` holding one PID file per running
process so the stop script can end exactly those.
