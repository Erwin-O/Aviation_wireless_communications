# Secure Aviation Messaging Prototype – Architecture

## 1. Purpose

This document describes the **architecture and design rationale** of the
prototype: its principles, its trust model, and the reasoning behind the
choices that are not forced.

It complements:

- `DEVELOPER GUIDE.md` → how the implementation works and how to change it
- `MODULE DEPENDENCIES.md` → how the code modules interact
- `CODE_INDEX.md` → what each file is
- `USER GUIDE.md` → running it

> **This document was substantially revised.** An earlier version described a
> *stateless* architecture in which session keys were "local optimisation,
> not a protocol dependency" and each message was processed with "no
> dependency on previous messages". That is no longer the design. Section 10
> sets out what changed and why, because the change is a reversal and not a
> clarification.

---

## 2. Architectural Overview

The system implements a **message-centric** architecture for air–ground
communication: what a message authorises is decided from the message, not
from the channel that carried it or the dialogue that preceded it.

### Core idea

> A receiver establishes from the message alone **what act it performs** and
> **whether its sender was entitled to perform it**.

Two fields carry that, both inside the region the authentication tag covers:
the `ROLE`, which names the operational kind of the message, and the
`CREDENTIAL` of its sender, which states what roles that sender may use and
in which airspace.

Session state exists and is load-bearing. The protocol is message-centric in
*what it authorises*, not in the sense of being stateless.

---

## 3. Design Principles

### 3.1 Role and authority bound to the message

Every message declares its operational kind, and that declaration is
authenticated. An adversary cannot cause one kind of message to be taken for
another without invalidating the tag. Authority is likewise carried: a
credential names the roles its holder may assert and the sector it may
control, so possession of a valid session key is **not sufficient** to issue
a clearance.

### 3.2 Session state, deliberately

An aircraft must be able to establish that a command is the one its
controller issued, that it is not acted upon twice, and that it is not acted
upon after a command issued later. None of the three follows from
authentication alone, because an adversary in control of the network may
deliver an authentic message repeatedly or out of turn.

Neither can a timestamp supply them: a clock has no notion of what a receiver
has already done.

So the protocol keeps per-session state — a key, a state, an outstanding
challenge and the last command executed — and the aircraft issues the
freshness itself. This is the principle the earlier architecture got wrong,
and it is the reason the three-message handshake and the challenge exchange
exist.

### 3.3 Transport independence

The specification is defined against an abstract transport. A *binding*
states how messages map onto a particular carrier: MQTT in this prototype,
and equally VDL, SATCOM or IP. Bindings differ in how messages are framed and
addressed and **not at all in what is authenticated**, which is what allows
the same message, unchanged, to be valid over any of them.

A binding may expose the role for routing convenience. The exposed value
carries no authority: a receiver compares it against the authenticated `ROLE`
and rejects a disagreement.

### 3.4 Untrusted infrastructure

Every intermediary is untrusted. The broker forwards and nothing else: it
validates no content, holds no key and has no security role. Because no
intermediary is trusted, the security properties are indifferent to how
relaying infrastructure is arranged — national, federated, commercial, or a
single node at an airfield. Topology becomes an operational and
jurisdictional question rather than a security one.

### 3.5 Credentials rather than a directory

A receiver holds the public keys of **credential issuers**, not a directory
of principals. A credential travels with the messages that use it, so a
station can verify an aircraft it has never heard of, and an aircraft can
verify a station it was told to contact a minute ago. The trust anchors are
the only shared configuration.

### 3.6 Explicit semantics

Messages carry explicit operational meaning rather than relying on position
in a dialogue:

| Role | Meaning |
|---|---|
| `SA` | measurable state |
| `CC:…` | operational intent, the subtype qualifying it |
| `ACK` | explicit confirmation, digesting what it answers |
| `KEY`, `KEYACK`, `KEYCONFIRM` | session establishment |

### 3.7 Payloads in clear

Operational payloads are not encrypted. Situational awareness is consumed by
many parties at once, and the archival record must be readable by an accident
investigator years later. What is protected is the *authenticity* of the
message: an Ascon-Mac tag under a session key derived from ephemeral scalars
that are discarded at once, so a later compromise of long-term keys does not
let anyone forge a message that checks out against the archive.

---

## 4. System Components

### 4.1 Aircraft node

Establishes sessions, reports its state, acts on commands that answer its
outstanding challenge, acknowledges them, and **decides for itself** which
station it talks to next. A nomination is advice, not an instruction.

### 4.2 Ground station

Answers handshakes, verifies every message it receives, issues commands bound
to the challenge it is answering, resends when a report shows its last
command was not acted upon, and relinquishes authority by naming a successor.

### 4.3 Message broker

Relays. Publish–subscribe routing, no security role, assumed hostile.

---

## 5. Message Types and Flows

### 5.1 Session establishment — three messages

```
aircraft                                   ground station
  |-- KEY ------------------------------------>|   credential + ephemeral, signed
  |<-------------------------------- KEYACK ---|   credential + ephemeral, signed
  |                                            |   pending
  |-- KEYCONFIRM ----------------------------->|   transcript hash, tagged
  |                                            |   established
```

Both parties contribute an ephemeral X25519 value; the session key is derived
from the shared value with Ascon-CXOF128. The third message confirms the key
over a hash of **both preceding bodies**, so the parties agree on the whole
exchange and not merely on the key.

Two messages would suffice to agree a key. They cannot give confirmation: the
station would learn that the aircraft holds the key only by inference from
traffic that may not arrive.

No session identifier is carried. The key distinguishes sessions, because the
shared value depends on scalars generated for that session alone.

### 5.2 `SA` — situational awareness

Position, altitude with its reference frame, speed, heading, on-ground. The
reference frame is mandatory: the same number denotes materially different
vertical positions under `BARO_QNH`, `BARO_STD` and `GEO_WGS84`.

Every `SA` also carries `LAST_EXEC` and a fresh `CHALLENGE`.

### 5.3 `CC:…` — command and control

`CC:REQUEST` from the aircraft; `CC:CLEARANCE` and `CC:INSTRUCTION` from the
controlling station; `CC:CONTACT` nominating a successor; `CC:EMERGENCY` in
either direction; `CC:SYSTEM` for matters concerning the communication rather
than the flight. Every station-sent `CC` carries `IN_REPLY_TO`.

### 5.4 `ACK` — acknowledgement

Digests the body it acknowledges, which identifies that message unambiguously
when several are outstanding, and carries the next challenge — so an
acknowledged command re-arms the exchange at once rather than at the next
report.

---

## 6. Security Model

### 6.1 Identity and trust

Each principal holds a long-term Ed25519 signing key, a long-term X25519
key-exchange secret used only as an input to the ephemeral derivation, and a
credential signed by an issuer. Trust anchors are issuer keys.

A credential carries `ISSUER`, `SUBJECT`, `VERIFY_KEY`, `NOT_BEFORE`,
`NOT_AFTER`, `PERMITTED_ROLES` and, for a ground station, `SECTOR`.

### 6.2 Cryptographic mechanisms

| Purpose | Primitive |
|---|---|
| Long-term signatures | Ed25519 |
| Ephemeral key agreement | X25519 |
| Message authentication | Ascon-Mac, 128-bit tag |
| Hashing and derivation | Ascon-Hash256, Ascon-CXOF128 |

128-bit security throughout. Each primitive is named in one place in the
code, so a future substitution stays local.

### 6.3 Verification order

Specified, and load-bearing: the issuer signature on the credential against a
trust anchor, the validity interval, the subject against the message's
sender, the sector scope, and only then the message signature. Failure at any
step discards the message.

### 6.4 Replay and ordering

Not by timestamp. Every message the aircraft sends carries a fresh challenge,
derived so that a platform with a predictable random source still issues
challenges an adversary cannot anticipate. A command is acted upon only if it
quotes the outstanding challenge; on acting, the aircraft records it as
`LAST_EXEC` and retires it. A command replayed, or delivered after a later
one, is bound to a retired challenge and refused.

`LAST_EXEC` informs the station's decision to resend or advance, and is never
a condition on accepting the message that carries it. That is what makes the
exchange tolerant of the loss these bearers impose: a lost report changes
nothing; a lost command is detected by its issuer on the next report and
resent, with the reporting interval serving as the retry interval.

Timestamps remain, doing different work: they place each message in time for
reconstruction after an accident, and bound the period over which a credential
is valid and a message may be presented at all.

### 6.5 Weak randomness

Ephemeral scalars are not taken directly from the platform's random number
generator but derived from its output together with the long-term
key-exchange secret. An adversary that predicts the generator in full still
cannot predict the scalar. This matters for an unmanned platform that may
begin a session with no accumulated entropy and no hardware source.

---

## 7. Operational Behaviour

### 7.1 Session states

| State | Traffic |
|---|---|
| `pending` | none; the station has not yet confirmed the aircraft derived the same key |
| `established` | everything; the only state in which the station holds command authority |
| `handover` | everything except commands the aircraft would act on |

### 7.2 Authority transitions

A station relinquishes authority by nominating a successor in an
authenticated message. The aircraft decides whether to follow it: the flight
plan establishes an expected sequence and the nomination ordinarily confirms
it, but a deviation is a legitimate and not infrequent event, and the aircraft
must be able to establish with whichever station serves the airspace it has in
fact entered.

Where it follows the nomination, it additionally requires that the credential
answering name the station nominated, so a party interposing itself is
refused even though its own credential may be valid.

The two endpoints leave `handover` by different means, and that asymmetry is
what makes a transfer need **no channel between ground stations**: the
aircraft leaves when a session with the successor is established, the
outgoing station when it is told or when Δt_ho expires.

Two stations are never simultaneously able to issue instructions the aircraft
will act on. The interval in which *no* station holds command authority is
accepted rather than engineered away, and the authenticated channel with the
previous station persists throughout — so an aircraft whose attempt at a
successor fails is not left without an authenticated peer, which is the
circumstance in which communication matters most. The reversion path mirrors
established practice, in which a crew unable to raise the next unit returns to
the previous frequency.

### 7.3 Degraded operation

The system tolerates message loss, delay and partial connectivity. What it
does not tolerate is silent acceptance: a failure presents as *no session*
rather than as an apparently valid one. Availability is outside the attacker
model — an adversary who drops every message prevents communication, which no
message-level protocol can prevent.

---

## 8. Comparison with Existing Systems

**Traditional aviation datalink (CPDLC over ATN).** Security guarantees are
bound to the transport layer and depend on persistent session state. Workable
where aviation is stable and human-centred; a constraint where connectivity
is intermittent, where several bearers coexist, and where automated systems
must interpret messages independently of shared context.

**Industrial and IoT middleware (MQTT, OPC UA, DDS).** Typically rely on
transport-layer security, session continuity, or a trusted broker. DDS comes
closest, its signed permissions document being the nearest existing analogue
to the credential here.

**This architecture.** Role and authority carried in the authenticated
message; transport-independent; every intermediary untrusted; freshness and
ordering from a challenge the aircraft itself issues.

---

## 9. Design Trade-offs

**What it buys.** Robustness under intermittent connectivity; deployment
across heterogeneous bearers with nothing required of the aircraft but a
channel carrying bytes, a key pair and a short-lived credential; a transfer of
control needing no ground-to-ground channel; an archival record that remains
verifiable.

**What it costs.** Per-session state at both endpoints, which the earlier
design avoided. One extra handshake message per session. A credential in every
`KEY` and `KEYACK`, which makes those messages some 700 bytes. A dependency on
credential issuance, where the residual risk now sits.

**What it does not address.** Denial of service and jamming. Compromise of a
long-term secret. Side channels. Large-scale behaviour, which remains
unevaluated at prototype stage.

---

## 10. What Changed, and Why

The earlier architecture claimed statelessness as a virtue: no
handshake-dependent flow, no dependency on message ordering, session keys as
local optimisation. Three things forced a reversal.

1. **Replay resistance does not follow from authentication.** An adversary in
   control of the network may deliver an authentic message twice. A stateless
   receiver cannot tell the second from the first.

2. **In-order execution does not follow either**, and a timestamp cannot
   supply it: a clock has no notion of what a receiver has already acted upon,
   and a symbolic model has no notion of elapsed time at all.

3. **Without both, the protocol cannot be claimed suitable for unmanned
   aircraft**, where no human crew catches a spoofed or stale instruction
   before it is executed.

The challenge exchange is what resolves this, and it needs exactly the state
it keeps: one outstanding challenge and one `LAST_EXEC` per session. It was
chosen over a shared counter precisely to preserve what the earlier
architecture was right about — a counter is state both parties must keep in
step, and a successor station cannot inherit one without the ground-to-ground
coordination the design sets out to avoid. A challenge carries no such
burden: the aircraft issues it, the station quotes it back, and nothing
survives a transfer that a successor would need to be told.

So the message-centric principle survives intact. What did not survive is the
claim that it implies statelessness.

---

## 11. Summary

The prototype demonstrates that:

- the operational role of a message and the authority of its sender can be
  carried in the message and verified from it alone;
- that is enough to make a clearance verifiable without a dialogue history, a
  certified stack, or trust in any intermediary;
- replay resistance and in-order execution require per-session state, and a
  challenge the receiver itself issues provides them without any state
  crossing a transfer of control;
- authority can pass between ground stations on the aircraft's own decision,
  with no channel between them.

The architecture is a shift from session-bound *security* to message-bound
*authority*. It is not a shift to statelessness, and the earlier version of
this document was wrong to say so.
