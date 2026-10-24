# Module Dependencies – Secure Aviation Messaging Prototype

Module-level dependencies, import relationships and responsibilities. It
complements `DEVELOPER GUIDE.md`, which explains the protocol, and
`CODE_INDEX.md`, which lists the files.

> **Scope**
>
> * Modules present in the repository, conforming and legacy
> * Imports, call-chains and shared resources
> * Not: third-party internals

---

# 1. High-Level Dependency Graph

## 1.1 Conforming implementation

```
scripts/aircraft.py
   ├── protocol.identity          (load_identity, load_trust_anchors)
   ├── protocol.node              (Aircraft, Outbound)
   ├── protocol.mqtt_binding      (topic_for, subscription_for, check_topic)
   ├── protocol.operational       (build_aircraft_cc, roles)
   ├── protocol.session           (State)
   ├── protocol.rejection         (Rejected)
   ├── scripts._scenario          (load_aircraft_script)
   ├── scripts._display           (banner)
   ├── mqtt_client, settings
   └── logs/pids/<name>.pid       (written on start, removed at exit)

scripts/station.py
   ├── protocol.identity, protocol.credentials
   ├── protocol.node              (Station)
   ├── protocol.mqtt_binding
   ├── protocol.rejection
   ├── scripts._scenario          (load_station_script)
   ├── scripts._display
   ├── mqtt_client, settings
   └── logs/pids/<name>.pid

scripts/provision.py
   ├── protocol.identity          (ensure_keys, issue_for, add_trust_anchor)
   ├── protocol.credentials       (parse, verify)
   ├── protocol.primitives        (public_signing_key, b64u)
   ├── config/trust_anchors.json  (written)
   └── ~/AviationLocalKeys/       (written)

scripts/replay.py
   ├── protocol.identity, protocol.credentials
   ├── protocol.node, protocol.operational, protocol.session
   ├── protocol.mqtt_binding      (topic_for, check_topic — no sockets)
   └── scripts._scenario
```

## 1.2 Inside `protocol/`

```
node.py
   ├── handshake.py
   ├── operational.py
   ├── session.py
   ├── identity.py            (type only)
   ├── encoding.py
   └── rejection.py

operational.py
   ├── session.py
   ├── credentials.py         (_iso, _parse_iso, default_sector_covers)
   ├── handshake.py           (DEFAULT_WINDOW, MAC)
   ├── encoding.py
   ├── primitives.py
   └── rejection.py

handshake.py
   ├── credentials.py
   ├── encoding.py
   ├── primitives.py
   └── rejection.py

session.py
   ├── credentials.py         (type only)
   ├── primitives.py
   └── rejection.py

credentials.py
   ├── encoding.py
   ├── primitives.py
   └── rejection.py

identity.py
   ├── credentials.py
   └── primitives.py

mqtt_binding.py
   ├── encoding.py
   └── rejection.py

primitives.py
   ├── encryption.ascon
   └── cryptography (Ed25519, X25519)

encoding.py                   no protocol dependencies
rejection.py                  no dependencies at all
```

The graph is acyclic and the direction never reverses: `encoding.py` and
`rejection.py` are the floor, `node.py` is the ceiling. A change that would
make a lower module import a higher one is a design error, not a convenience.

## 1.3 Legacy implementation

```
scripts/scenario_player.py        scripts/demo_subscriber.py
   ├── core.messages                 ├── core.messages
   ├── core.comm_state               ├── core.comm_state
   ├── core.registry                 ├── core.registry
   ├── encryption.crypto             ├── encryption.crypto
   ├── utils.station_norm            ├── config.station_keys
   ├── core.logger                   ├── core.logger
   ├── core.logger                   └── mqtt_client
   └── mqtt_client
```

---

# 2. Module-by-Module

## 2.1 `protocol/encoding.py`

**Provides** `encode`, `parse`, `authenticated_region`, `get`, `require`,
`EncodingError`, `LINE_TERMINATOR`.

**Depends on** the standard library only.

**Used by** `credentials`, `handshake`, `operational`, `node`,
`mqtt_binding`, and the scripts.

**Notes** `authenticated_region` slices the buffer as received and never
re-encodes. Everything that verifies a signature or a tag goes through it; if
a new call site re-encodes instead, the two sides can disagree about what was
authenticated without either being obviously wrong.

## 2.2 `protocol/rejection.py`

**Provides** `Step`, `Rejected`.

**Depends on** nothing.

**Used by** every module in `protocol/` and both scripts.

**Notes** One vocabulary for the whole package. `credentials.CredentialRejected`
is an alias kept for readers of §3.3.2.

## 2.3 `protocol/primitives.py`

**Provides** the equations: `derive_ephemeral_scalar`, `dh`, `session_key`,
`transcript_hash`, `derive_challenge`, `new_challenge`, `ack_hash`, `mac`,
`verify_mac`, `sign`, `verify_signature`, key generation, `b64u`/`unb64u`,
and the labels and sizes.

**Depends on** `encryption.ascon`, `cryptography`.

**Used by** `credentials`, `handshake`, `session`, `operational`, `identity`,
and the scripts.

**Notes** The only module that touches cryptography directly. Changing a
primitive means changing this file and nothing else; that is deliberate, and
is what the paper means by naming each primitive in one place so a
post-quantum substitution stays local.

## 2.4 `protocol/credentials.py`

**Provides** `Credential`, `issue`, `parse`, `verify`,
`default_sector_covers`, and the ISO 8601 helpers `_iso` / `_parse_iso` that
the rest of the package shares.

**Depends on** `encoding`, `primitives`, `rejection`.

**Used by** `handshake`, `operational`, `session` (type only), `identity`,
`station.py`, `provision.py`, `replay.py`.

**Notes** `verify` runs the specified order and raises with the step that
failed. The order is tested, including that a message failing two checks
reports the earlier one.

## 2.5 `protocol/handshake.py`

**Provides** `Initiator`, `Responder`, `Session`, `Endpoint`, the three role
constants, `SIGNATURE`, `MAC`, `DEFAULT_WINDOW`.

**Depends on** `credentials`, `encoding`, `primitives`, `rejection`.

**Used by** `node`, `operational` (for `DEFAULT_WINDOW` and `MAC`), tests.

**Notes** Holds one handshake in flight, not session state. What the
endpoints retain afterwards belongs to `session.py`.

## 2.6 `protocol/session.py`

**Provides** `State`, `Session`, `SessionTable`, `COMMAND_ROLES`, the three
timeouts, and the challenge functions `arm`, `may_act`, `record_execution`,
`station_should_resend`, `overdue`.

**Depends on** `credentials` (type only), `primitives`, `rejection`.

**Used by** `operational`, `node`, `aircraft.py`, `replay.py`, tests.

**Notes** Both the state machine and the challenge bookkeeping live here
because both are per-session state. `SessionTable.establish` drops any row in
`HANDOVER`, which is how the old session ends when a successor comes up.

## 2.7 `protocol/operational.py`

**Provides** the role constants, `ALT_REFS`, `TRANSFER_INCOMPLETE`,
`Received`, the builders `build_sa` / `build_command` / `build_aircraft_cc` /
`build_ack`, `receive`, `last_exec_of`.

**Depends on** `session`, `credentials`, `handshake`, `encoding`,
`primitives`, `rejection`.

**Used by** `node`, `aircraft.py`, `replay.py`, tests.

**Notes** `receive` is the only door for operational traffic. A second
entry point that skipped one of its checks is the most likely way to break
the implementation's central claim, so new paths call it rather than
reimplementing it.

## 2.8 `protocol/node.py`

**Provides** `Aircraft`, `Station`, `Outbound`.

**Depends on** `handshake`, `operational`, `session`, `identity` (type only),
`encoding`, `primitives`, `rejection`.

**Used by** `aircraft.py`, `station.py`, `replay.py`, `tests/test_node.py`.

**Notes** The top of the protocol stack and the bottom of the applications.
It imports no transport, which is what allows `test_node.py` to drive whole
flights in process.

## 2.9 `protocol/identity.py`

**Provides** `Identity`, `load_identity`, `issue_for`, `ensure_keys`,
`store_credential`, `load_trust_anchors`, `add_trust_anchor`, `norm`, and the
paths `ANCHORS_PATH` and `LOCAL_DIR`.

**Depends on** `credentials`, `primitives`.

**Used by** `aircraft.py`, `station.py`, `provision.py`, `replay.py`.

**Notes** The only module that touches the filesystem. It replaces
`core/registry.py`: a receiver holds issuer keys, not a directory of
principals. Private key file names match the legacy ones, so existing
material is reused.

## 2.10 `protocol/mqtt_binding.py`

**Provides** `slug`, `role_slug`, `topic_for`, `subscription_for`,
`check_topic`, `DEFAULT_BASE`.

**Depends on** `encoding`, `rejection`.

**Used by** `aircraft.py`, `station.py`, `replay.py`.

**Notes** The whole binding. `check_topic` is the only thing that gives the
topic any standing, and it gives it none: it compares the advertised role
against the authenticated one and refuses a disagreement.

---

# 3. Shared and legacy modules

## 3.1 `encryption/ascon.py`

**Provides** `ascon_hash`, `ascon_mac`, `ascon_encrypt`, `ascon_decrypt`.

**Used by** `protocol/primitives.py` and `encryption/crypto.py`.

**Notes** A reference implementation of NIST SP 800-232, vendored. Not
modified by this project.

## 3.2 `encryption/crypto.py` — legacy

**Provides** Base64 helpers, `compute_mac` (Ascon-Mac), `verify_mac`,
Ed25519 sign/verify, X25519 session-key wrap/unwrap.

**Used by** `core/registry.py`, `config/station_keys.py`, and the legacy
scripts.

**Notes** BLAKE3, the `MAC_ALG` dispatch and the XOR-keystream `dec_hash`
have been removed. The conforming implementation does not import this module
at all.

## 3.3 `core/messages.py`, `core/comm_state.py`, `core/registry.py` — legacy

Superseded by `protocol/encoding.py`, `protocol/session.py` and
`protocol/identity.py` respectively. Still used by the legacy scripts. Field
names on the wire were corrected to `MAC` and `SIGNATURE`.

## 3.4 `core/logger.py`

**Provides** the structured logger (`WIRE`, `LIMITED`, `FULL`; `TXT`, `JSON`,
`BOTH`).

**Used by** the legacy scripts. The conforming scripts print to stdout and are
captured by `tee` into `logs/<STATION>.log`.

## 3.5 `mqtt_client.py`

**Provides** `MQTTClient`: `connect`, `subscribe`, `publish`, `loop_start`,
`loop_stop`, `set_handlers`, `is_connected`.

**Depends on** `paho.mqtt` (v2 callback API, MQTTv3.1.1).

**Used by** every script that touches the broker.

**Notes** Two sharp edges, both documented in the developer guide: handlers
receive paho's own `(client, userdata, msg)`, and a `subscribe` issued before
the CONNACK is dropped rather than queued, so subscriptions belong in
`on_connect`.

## 3.6 `settings.py`

**Provides** broker host and port, topic base, logging configuration.

**Notes** `MAC_ALG` is informational. The data-plane MAC is Ascon-Mac and is
no longer selectable: a protocol that names its primitives in one place has
nothing to dispatch on.

## 3.7 `scripts/_scenario.py`

**Provides** `load_aircraft_script`, `load_station_script`,
`stations_in_order`, `aircraft_id`, `canonical`.

**Depends on** the standard library only.

**Used by** `aircraft.py`, `station.py`, `replay.py`.

**Notes** Translates scenario files written for the earlier design. KEY and
ACK rows are dropped because the protocol produces both; CONTACT rows become
nominations issued by whichever station held the aircraft at that moment.

## 3.8 `scripts/_display.py`

**Provides** `render`, `banner`.

**Used by** `aircraft.py`, `station.py` under `--verbose`.

**Notes** Elides over-long Base64 for display only.

---

# 4. Shared resources

| Resource | Written by | Read by |
|---|---|---|
| `config/trust_anchors.json` | `provision.py` | every conforming node |
| `~/AviationLocalKeys/<ACTOR>/` | `provision.py`, `add_actor.py` | `identity.load_identity`, `core/registry.py` |
| `config/publicKeys.json` | `add_actor.py` | legacy scripts only |
| `logs/pids/*.pid` | `aircraft.py`, `station.py` | `stop_all_listeners.sh` |
| `logs/pids/mqtt_recorder.pid` | `run_demo.sh` | `stop_demo.sh` |
| `logs/<STATION>.log` | `tee` in the launchers | people |
| `logs/scenario_log.json` | `mqtt_recorder.py` | `visualise_flight.py` |
| `scenarios/*.json` | `build_scenario_from_tables.py` | `_scenario.py`, legacy player |

The PID files are the contract between the launchers and the stop script.
They exist because killing by command-line pattern is unsafe: a shell whose
command line mentions the script matches it too.
