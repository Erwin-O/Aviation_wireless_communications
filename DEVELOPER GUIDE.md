# Secure Aviation Messaging Prototype – Developer Guide

How the implementation works and how to change it. `CODE_INDEX.md` lists the
files; `MODULE DEPENDENCIES.md` maps the imports; `USER GUIDE.md` covers
running it.

---

## 1. Introduction

This repository implements the air–ground communication protocol specified in
Section 3.3 of the IJCIP paper. The implementation exists to establish that
the specification can be realised as written, and that each check it requires
rejects the input it is meant to reject.

That second claim is the one that shapes the code. Every refusal anywhere in
`protocol/` raises `Rejected` carrying a `Step`, and the tests assert the
step rather than merely the refusal, because a message refused for the wrong
reason demonstrates nothing about the check under test.

An earlier prototype implemented a different protocol. It was removed when
this one replaced it, and remains in the git history at the tag
`legacy-implementation`.

---

## 2. Architecture

### 2.1 Layers

```
scripts/aircraft.py   scripts/station.py        processes, MQTT, scenarios
         \                 /
          protocol/node.py                      endpoint behaviour
                 |
   protocol/operational.py  protocol/handshake.py
                 |                  |
          protocol/session.py  protocol/credentials.py
                 \                  /
            protocol/primitives.py  protocol/encoding.py
                          |
                 encryption/ascon.py, cryptography
```

Each layer may use the one below it and never the one above. `node.py` knows
nothing of MQTT; `mqtt_binding.py` knows nothing of sessions.

### 2.2 Why a node layer

`protocol/node.py` holds `Aircraft` and `Station` as objects that take a
message and return the messages it obliges them to send. The transport is
whatever calls them. That is what makes the MQTT scripts thin, and it is also
what lets `tests/test_node.py` run whole flights with no sockets at all.

---

## 3. The wire format

One field per line, `NAME: value`, terminated by CRLF, printable ASCII.

```
ROLE: SA
TIMESTAMP: 2026-10-23T05:44:16+00:00
FROM: OOABC
TO: EBBR GND
ALTITUDE: 165
ALT_REF: BARO_QNH
POSITION: 50.901981 LAT 4.482942 LONG
SPEED: 0
HEADING: 334
ON_GROUND: 1
LAST_EXEC: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CHALLENGE: cQNrat6ILCJf1W1qSTrFYZcsdar7RgN8rRDsbb--Ncw
MAC: oxmXF3N6ZvlKer4vopHXRA
```

### 3.1 The rule that matters

**The bytes on the wire are the bytes that are authenticated.** There is no
canonicalisation step. A sender builds the byte string once, authenticates a
prefix of it and sends it; a receiver authenticates the prefix of what
arrived.

```python
body = encoding.encode(fields)                     # built once
wire = body + encoding.encode([("MAC", tag)])      # tag covers exactly `body`

region = encoding.authenticated_region(raw, "MAC") # sliced from what arrived
primitives.verify_mac(key, region, tag)
```

Never verify against a re-encoding of parsed fields. If you find yourself
calling `encode` on the receive path, something has gone wrong.

### 3.2 Strictness

`parse` rejects duplicate fields, non-ASCII values, missing terminators and
malformed lines. "A message admits exactly one parse" is a security property,
not a convenience, and a tolerant parser is how two implementations come to
disagree about what was signed.

---

## 4. Cryptography

| Purpose | Primitive | Where |
|---|---|---|
| Long-term signatures | Ed25519 | credentials, KEY, KEYACK (claim included) |
| Ephemeral key agreement | X25519 | KEY, KEYACK |
| Message authentication | Ascon-Mac, 16-byte tag | all operational messages, KEYCONFIRM |
| Hashing | Ascon-Hash256 | ephemeral derivation, challenge, transcript, ACK digest |
| Key derivation | Ascon-CXOF128 | session key |

### 4.1 Domain separation

Every use of Ascon-Hash256 prefixes a fixed label:

```python
L_EPH = b"AGCP-v1:ephemeral\x00"
L_CH  = b"AGCP-v1:challenge\x00"
L_TR  = b"AGCP-v1:transcript\x00"
L_ACK = b"AGCP-v1:ackhash\x00"
```

They share a prefix and end with a NUL, and no label contains a NUL, so the
set is prefix-free: no label followed by one input can equal another label
followed by a different input. A test asserts this. If you add a label, keep
the shape.

### 4.2 Ephemeral derivation

```python
r = primitives.random_r()                                  # 32 bytes
scalar = primitives.derive_ephemeral_scalar(r, kex_secret) # eq. (1)
```

The private scalar is not taken directly from the platform's random number
generator. An adversary that predicts `r` in full still cannot predict the
scalar without the long-term key-exchange secret, which is what makes the
weak-randomness goal attainable. Only the private half of that long-term pair
is ever used, so it appears in no credential.

### 4.3 The transcript

```python
h = Ascon-Hash256(L_tr ‖ m_KEY ‖ 0x00 ‖ m_KEYACK)
```

The `0x00` fixes the boundary between the two bodies. Without it `h(x, yz)`
would equal `h(xy, z)` and the confirmation would bind the parties to a
concatenation rather than to the exchange. A message body is printable ASCII
with CRLF terminators, so a zero byte cannot occur inside one.

---

## 5. Credentials

A credential is a signed labelled record:

```
ISSUER: BE CAA
SUBJECT: EBBR GND
VERIFY_KEY: <base64url>
NOT_BEFORE: 2026-10-23T05:02:50+00:00
NOT_AFTER: 2026-10-30T05:07:50+00:00
PERMITTED_ROLES: KEYACK,CC:CLEARANCE,CC:INSTRUCTION,CC:CONTACT,CC:EMERGENCY,CC:SYSTEM
SECTOR: EBBU.EBBR
ISSUER_SIG: <base64url>
```

A receiver holds **issuer keys**, not a directory of principals, which is
what lets a station verify an aircraft it has never heard of.

### 5.1 The verification order

Specified, and not an implementation detail:

1. the issuer signature on the credential, against a trust anchor
2. the validity interval, against the receiver's clock
3. the subject identity, against the message's `FROM`
4. the sector scope, against the airspace at issue, wherever the credential
   carries a `SECTOR`
5. and only then the message signature, against the credential's `VERIFY_KEY`

"The airspace at issue" means something different in each direction. At an
aircraft receiving `KEYACK` it is the airspace the station *claims* to be
working, which that message states. At a station receiving an operational
message it is the airspace the *aircraft* reports being in. Step 4 does not
apply to a `KEY`: an aircraft's credential carries no `SECTOR`, because an
aircraft asserts no airspace.

Failure at any step discards the message. A message failing two checks must
report the earlier one, and `tests/test_credentials.py` asserts exactly that.

### 5.2 Role admission

`Credential.permits(role)` is an **exact** match. A credential listing `CC`
permits no subtype; a station must list `CC:CLEARANCE` to issue a clearance.
The conservative reading, since `CC:CONTACT` is what nominates a successor.

Handshake roles are exempt: any principal holding a valid credential may
establish a session, and what its credential permits governs only what it may
do afterwards.

### 5.3 Sector: the grant, the claim, and who can check what

Three distinct things, and conflating them is the easiest mistake to make
here.

**The grant.** `SECTOR` in a ground station's credential is what its issuer
authorised it to control. It bounds everything below.

**The claim.** `AIRSPACE` in `KEYACK` is the airspace the station says it is
actually working. It must lie within the grant, and `build_keyack` refuses to
emit a claim that does not: a misconfigured station fails at home rather than
emitting a message every aircraft will refuse.

**Covering** is containment in the published airspace hierarchy, implemented
by `default_sector_covers` as exact match or dotted-prefix containment, so
`EBBU` covers `EBBU.EBBR`. This is now specified rather than left to the
deployment, because two implementations disagreeing about covering would
disagree about who may issue a clearance. A deployment whose designators are
not dotted passes its own function to `credentials.verify`.

Who checks what:

| Check | Who | Conditional on | Step |
|---|---|---|---|
| claim within the grant | every aircraft, on `KEYACK` | nothing | `sector` |
| claim contains the aircraft | aircraft with airspace data | holding that data | `airspace` |
| reported position within the station's own sector | the station, per message | the caller supplying it | `sector` |

The first needs no data of the aircraft's own: the grant and the claim are
both in the message in front of it. That is the point of carrying the claim.
The second is advisory, because requiring it would oblige every aircraft to
carry current airspace data and so reintroduce the equipage dependency the
design exists to avoid. An aircraft that dislikes a claim simply does not send
`KEYCONFIRM`; the station's pending session times out. The choice of which
station to work stays with the aircraft throughout.

```python
# the aircraft side: `airspace` is where the aircraft is, from data it loaded
# before the flight, and is optional
initiator.handle_keyack(raw, now, airspace="EBBU.NORTH")

# the station side: `local_sector` is its own entitlement, `airspace` the
# position the aircraft reported
operational.receive(raw, table, now, local="EBBR GND", as_aircraft=False,
                    local_sector="EBBU.EBBR", airspace="EBBU.NORTH")
```

Mapping a reported position to an airspace needs boundary data, so the caller
does it and passes the result.

**Nothing in this repository supplies that mapping.** `scripts/station.py`
and `scripts/replay.py` call `handle(raw, now)` with no `airspace`, so the
third row of the table above never fires in the demo: it is exercised by
`tests/test_operational.py` and not by the scenarios. That is a gap in the
demonstration, not in the implementation, and closing it honestly would need
real airspace boundaries rather than a mapping derived from whichever station
happens to be controlling, which would pass by construction and prove
nothing.

---

## 6. Session establishment

```
aircraft                                   ground station
  |-- KEY ------------------------------------>|  credential + ephemeral, signed
  |<-------------------------------- KEYACK ---|  the same, plus AIRSPACE
  |                                            |  pending
  |-- KEYCONFIRM ----------------------------->|  transcript, tagged under K_sess
  |                                            |  established
```

Both parties discard their ephemeral private scalars once `K_sess` is
derived. **No session identifier is carried**: the key distinguishes sessions,
because `Z` depends on scalars generated for that session alone. A test greps
the wire bytes to make sure no such field creeps back in.

One refinement on the paper, flagged in `handshake.py`: the acceptance-window
check on `TIMESTAMP` runs *before* the credential order, so a message outside
the window costs a receiver no signature verification. The relative order the
paper specifies is preserved within that.

---

## 7. Session states

| State | Entered | Traffic |
|---|---|---|
| `PENDING` | station on sending KEYACK; aircraft on receiving it | none |
| `ESTABLISHED` | station on verifying KEYCONFIRM; aircraft on sending it | everything |
| `HANDOVER` | on a nomination accepted | everything except `COMMAND_ROLES` |

`COMMAND_ROLES` is `CC:CLEARANCE`, `CC:INSTRUCTION`, `CC:CONTACT` — what an
aircraft acts upon. `CC:SYSTEM` and `CC:EMERGENCY` keep flowing during
handover by design, which is also why they are not gated on a challenge.

The two endpoints leave `HANDOVER` by different means, and that asymmetry is
what lets a transfer need no channel between ground stations:

- **aircraft** — when a session with the successor reaches `ESTABLISHED`
  (`SessionTable.establish` drops the handover row), or on `revert` after
  Δt_ho or a failed attempt, sending a `CC:SYSTEM` notification.
- **station** — on that notification, or on expiry of Δt_ho, which
  `SessionTable.expire` applies.

---

## 8. The challenge exchange

Four rules, implemented as four named functions in `session.py`:

| Rule | Function |
|---|---|
| Every message the aircraft sends carries a fresh challenge; sending retires the one before | `arm(row, kex_secret, now)` |
| A command is acted upon only if its `IN_REPLY_TO` equals the outstanding challenge | `may_act(row, in_reply_to)` |
| On acting, `LAST_EXEC` becomes that challenge and the challenge is retired | `record_execution(row)` |
| The station reads `LAST_EXEC` to decide whether to resend or advance | `station_should_resend(row, reported)` |
| The aircraft sends at least every Δt_rep | `overdue(row, now)` |

`LAST_EXEC` is information for the station's decision and **never** a
condition on accepting the message carrying it. That is what makes the
exchange tolerant of loss:

- a lost report changes nothing;
- a lost command leaves `LAST_EXEC` unchanged, so its sender learns on the
  next report and resends bound to the newer challenge — no timer, the
  reporting interval is the retry interval;
- a command delivered out of turn, or replayed, is bound to a retired
  challenge and refused.

An acknowledgement carries the next challenge, so an acknowledged command
re-arms the exchange at once rather than at the next report. Two queued
instructions therefore go out on a single report.

Nothing crosses a transfer: a new session starts with `LAST_EXEC` at zero and
nothing outstanding.

---

## 9. Receipt

`operational.receive` is the single door, and runs the checks in this order:

1. the message parses, and its `ROLE` and `TO` are what they should be
2. a session exists with the sender
3. the tag verifies under `K_sess`
4. the timestamp lies within Δt_max
5. a command-bearing message quotes the outstanding challenge
6. the `ROLE` lies within the sender's `PERMITTED_ROLES`; at a station, the
   station's own `SECTOR` covers the airspace reported. The aircraft makes no
   per-message airspace check: it made its one, against the claim, when the
   session was established
7. the session's state admits the role

Steps 1 and 2 precede the paper's "verifies the tag" because a receiver
cannot verify a tag before parsing the message and finding the key.

---

## 10. Identity on disk

```
config/trust_anchors.json          { "issuers": { "BE CAA": "<base64url>" } }
~/AviationLocalKeys/<ACTOR>/
    ed25519_private.key            signing key
    x25519_private.key             long-term kex secret, eq. (1)
    credential                     the signed record
```

`scripts/provision.py` creates the authority if there is none, issues
credentials, and then **verifies what it issued against the anchor it just
wrote**. If those two drift apart every message in the demo is refused at
`issuer_signature`, which is the correct answer to the wrong question and
takes a while to recognise.

Existing key files are reused rather than replaced, so key material already
on a machine is picked up unchanged and only the credential is new.

---

## 11. The MQTT binding

```
aviation/<role>/<addressee>        aviation/cc_clearance/OOABC
aviation/+/<name>                  what a node subscribes to
```

The exposed role carries **no authority**. `check_topic` compares it against
the authenticated `ROLE` and refuses any disagreement. An adversary may
publish anything to any topic; only the `ROLE` inside the tagged region
decides what a message is.

Two things to know about `mqtt_client.py`:

- handlers receive paho's own `(client, userdata, msg)`, not `(topic, payload)`;
- **subscribe from `on_connect`**. A subscribe issued before the CONNACK is
  dropped rather than queued, and the node then sits there having heard
  nothing.

---

## 12. Testing

```bash
python -m unittest discover -s tests -t . -v      # 148 tests, ~1 s
python -m unittest tests.test_node -v             # one file
python scripts/replay.py scenarios/commercial_flight_EBBR-EDDF.json
```

`replay.py` runs a whole flight with no broker, which is the quickest way to
see that a change has not broken the protocol, and prints the message counts.

### Writing a test

Assert the step, not just the refusal:

```python
with self.assertRaises(Rejected) as cm:
    station.handle(tampered, now)
self.assertEqual(cm.exception.step, Step.TAG)
```

And where the order of two checks matters, test it: construct a message that
fails both and assert the earlier one is reported.

---

## 13. Extending

### A new message role

1. Add the constant to `operational.py` and to `_KNOWN_ROLES`.
2. Decide whether it is command-bearing. If an aircraft acts on it, add it to
   `session.COMMAND_ROLES`, which gates it on a challenge and refuses it
   during handover.
3. Add it to the relevant role list in `scripts/provision.py` and reprovision.
4. Add a builder beside `build_sa` / `build_command`.
5. Add a test for a message of that role being refused for each reason it can
   be refused.

### A new station

Add the name and its sector to `STATIONS` in `scripts/provision.py` and to
`STATIONS` in `visualisation/launch_all_stations.sh`, then reprovision.

### A new transport binding

Write the equivalent of `mqtt_binding.py`. It needs to frame and address
messages, and to compare whatever role it exposes against the authenticated
`ROLE`. Nothing below `node.py` changes, which is the point of the
abstract-transport design.

### Changing a protocol constant

Constants that correspond to the paper live in one place each:
`primitives.CHALLENGE_BYTES`, `encoding.LINE_TERMINATOR`,
`handshake.DEFAULT_WINDOW`, `session.DEFAULT_HANDOVER_TIMEOUT`. Change the
code and the paper together; where a test pins the current behaviour, it is
pinned so that changing it forces the paper to change too.
