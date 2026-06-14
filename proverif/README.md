# ProVerif models for the air–ground communication protocol

This directory contains the ProVerif models used to formally verify the
air–ground communication protocol of the main paper.

The models are written in the **applied pi calculus** (ProVerif's default
input language, file extension `.pv`).


## Files

| File | Purpose |
|------|---------|
| `hello_world.pv` | A minimal sanity-check model used to confirm that ProVerif is installed and working. Verifies that a one-message symmetric-encryption exchange protects a secret against a network attacker. |
| `phase1_handshake.pv` | First real model. Two-message KEY/KEYACK handshake (no KEYCONFIRM yet). Verifies G1 (session-key secrecy), G2 (aircraft authentication), G3 (ground-station authentication). **Status: verified.** |
| `phase2_keyconfirm.pv` | Adds the third leg of the handshake (KEYCONFIRM) with SHA-256 transcript hash and Ascon-MAC under K_sess. Verifies G1, G2, G3 (carried over) plus G7 (handshake transcript agreement), which subsumes attack A12 (handshake re-binding). **Status: verified.** |
| `phase3_operational.pv` | Adds the operational message exchange after session establishment: SA (aircraft → ground), CC (ground → aircraft), ACK (aircraft → ground). Verifies G1, G2, G3, G7 (carried over) plus G4 (operational message integrity, split into three queries: G4_SA, G4_CC, G4_ACK). Attack A8 (type confusion) is defeated by construction through disjoint `[data]` constructors. **Status: verified.** |
| `phase4_handover.pv` | Adds a second ground station G2 and the handover triggered by a CC:CONTACT message. The aircraft does session 1 with G1, then session 2 with G2. Verifies G2, G3, G4, G7 (carried over, holding for both sessions) plus G5 (session isolation), captured operationally by leaking K_sess^(1) on the public channel **inside a `phase 1` block** (after the phase-0 protocol completes) and verifying that K_sess^(2) — used to encrypt the test secret Ksess2_test in phase 0 — remains secret. The phase directive is required to prevent spurious counterexamples where ProVerif would otherwise consider the attacker to hold K_sess^(1) during operational exchange. **Status: verified.** |
| `phase5_replay.pv` | Strengthens the correspondences to **injective** form (`inj-event ... ==> inj-event ...`), capturing G6 (cross-session replay resistance). G2 is now measured at session establishment (`groundAcceptsConfirm`), matching the paper's wording, and holds injectively: even when an attacker replays a signed KEY to multiple `! ground1` instances, only one ever completes the handshake (because KEYCONFIRM is transcript-bound to the chosen KEYACK). G3, G4 (SA/CC/ACK) and G7 are also injective. Sequence numbers are NOT introduced — the protocol's design philosophy is that operational messages are independent (except ACK → CC binding); within-session timing replay is addressed at deployment level. **Status: verified.** |
| `phase6_entropy.pv` | Strengthens the Phase-5 leak from "session key" to "ephemeral private key": the aircraft leaks `skA_eph` of session 1 in phase 1. This is a strictly stronger compromise — it both exposes session 1's `K_sess^(1)` and any future derivation depending on `skA_eph`. The model verifies that session 2's `K_sess^(2)` remains secret (carried over as G5/G8 refined) and that all phase-0 correspondences continue to hold. Discussion: the paper's G8 ("one strong RNG is enough") is strictly too strong for the symbolic model; the property that holds is per-session ephemeral compromise independence. |


## Running ProVerif

From this directory:

```sh
proverif hello_world.pv
```

ProVerif will print a progress trace and then summary lines beginning
with `RESULT`. For `hello_world.pv`, the relevant summary line is:

```
RESULT not attacker(hello_secret[]) is true.
```

If you see `is true` for that query, the installation is working
correctly.

If you see `is false`, ProVerif has found an attack — for the
`hello_world` model that would mean the installation or the model is
broken, not that there is a real attack.

If you see `cannot be proved`, ProVerif could not decide. For this
simple model that should not happen; if it does, please double-check the
ProVerif version (`proverif --version`).


## Verbose output

By default, ProVerif prints quite a lot of internal Horn-clause trace
information before the summary. If you only want to see the result
lines, pipe to `grep`:

```sh
proverif hello_world.pv | grep '^RESULT'
```

Or pass `-test` to get test-mode output:

```sh
proverif -test hello_world.pv
```


## What this model is not

The hello-world file is *not* a model of the air–ground protocol. It is
deliberately trivial and exercises only:

- type and free-name declarations,
- a single equational theory for symmetric encryption,
- one `query attacker(...)` secrecy query,
- the simplest possible process expression.

Its only purpose is to confirm that the ProVerif binary runs and reports
results in the expected format.


## Running Phase 1

```sh
cd /Users/erwin/Documents/Claude/Projects/PhD/proverif/
proverif phase1_handshake.pv
```

Three queries are verified. Look for these `RESULT` lines, each
ending in `is true`:

```
RESULT not attacker(Ksess_test[]) is true.
RESULT event(groundAcceptsKey(...)) ==> event(aircraftSentKey(...)) is true.
RESULT event(aircraftDerivesKsess(...)) ==> event(groundSentKeyAck(...)) is true.
```

(ProVerif spells out the argument bindings in the actual output; the
shapes above are abbreviations.)

If all three are `is true`, properties G1, G2, G3 from §5.1 of the
paper hold under the modelled assumptions and Phase 1 is complete.

If any query is `is false`, ProVerif will print a derivation showing
how the attacker breaks the property. Capture the derivation and let
us know — that is a real finding to debug.


## Running Phase 2

```sh
cd /Users/erwin/Documents/Claude/Projects/PhD/proverif/
proverif phase2_keyconfirm.pv
```

Four queries are verified. The first three are identical to Phase 1
(unchanged by adding the third leg); the fourth is new:

```
RESULT not attacker(Ksess_test[]) is true.
RESULT event(groundAcceptsKey(...)) ==> event(aircraftSentKey(...)) is true.
RESULT event(aircraftDerivesKsess(...)) ==> event(groundSentKeyAck(...)) is true.
RESULT event(groundAcceptsConfirm(...)) ==> event(aircraftSentConfirm(...)) is true.
```

The new G7 property states: if the ground station marks a session as
established (i.e., accepted a valid KEYCONFIRM with transcript hash
`t`), then the aircraft sent that KEYCONFIRM with the same transcript
hash `t`. This guarantees both parties agree, bit-for-bit, on every
canonical KEY and KEYACK they exchanged. It also subsumes attack A12
(handshake re-binding) from §5.3 of the paper.

Expected runtime: a few seconds — similar to Phase 1, since the model
remains small.


## Running Phase 3

```sh
cd /Users/erwin/Documents/Claude/Projects/PhD/proverif/
proverif phase3_operational.pv
```

Seven queries are verified: the four from Phase 2 plus three new
G4 queries (one per operational message type):

```
RESULT not attacker(Ksess_test[]) is true.                                       (G1)
RESULT event(groundAcceptsKey(...)) ==> event(aircraftSentKey(...)) is true.     (G2)
RESULT event(aircraftDerivesKsess(...)) ==> event(groundSentKeyAck(...)) is true.(G3)
RESULT event(groundAcceptsConfirm(...)) ==> event(aircraftSentConfirm(...)) is true. (G7)
RESULT event(groundAcceptsSA(...)) ==> event(aircraftSentSA(...)) is true.       (G4_SA)
RESULT event(aircraftAcceptsCC(...)) ==> event(groundSentCC(...)) is true.       (G4_CC)
RESULT event(groundAcceptsAck(...)) ==> event(aircraftSentAck(...)) is true.     (G4_ACK)
```

The three G4 queries state: if the receiving party accepts an
operational message as valid, the sending party must have generated
it (with the same field values). The proof rests on the unforgeability
of Ascon-MAC under K_sess and on the disjointness of the SA, CC and
ACK constructors at the symbolic level.

Replay defence (G6) is **not** modelled in this phase: the
correspondences are non-injective, so a replayed message would
satisfy them by mapping back to its original `aircraftSent...` or
`groundSent...` event. Phase 5 will introduce explicit replay
protection (timestamps, optional sequence numbers) and the
corresponding injective `inj-event` correspondences.

Expected runtime: a few seconds.


## Running Phase 4

```sh
cd /Users/erwin/Documents/Claude/Projects/PhD/proverif/
proverif phase4_handover.pv
```

Seven queries are verified — the same six correspondence queries as
Phase 3 (now ranging over both `(A, G1, s_1)` and `(A, G2, s_2)`
sessions) plus the new G5 secrecy query:

```
RESULT not attacker(Ksess2_test[]) is true.                                  (G5)
RESULT event(groundAcceptsKey(...)) ==> event(aircraftSentKey(...)) is true.     (G2)
RESULT event(aircraftDerivesKsess(...)) ==> event(groundSentKeyAck(...)) is true.(G3)
RESULT event(groundAcceptsConfirm(...)) ==> event(aircraftSentConfirm(...)) is true. (G7)
RESULT event(groundAcceptsSA(...)) ==> event(aircraftSentSA(...)) is true.       (G4_SA)
RESULT event(aircraftAcceptsCC(...)) ==> event(groundSentCC(...)) is true.       (G4_CC)
RESULT event(groundAcceptsAck(...)) ==> event(aircraftSentAck(...)) is true.     (G4_ACK)
```

The G5 query is the new and central one. The model is structured
into two ProVerif phases:

* **Phase 0** — the entire normal protocol execution: both sessions
  (with G1 and G2), all operational messages, and the G5 test
  encryption `senc(Ksess2_test, ksess2)`.
* **Phase 1** — the worst-case compromise: the aircraft leaks
  `K_sess^(1)` on the public channel (`out(c, ksess1)`).

The `phase 1` directive enforces a strict temporal partition. The
honest ground stations have no phase directive, so they remain in
phase 0 throughout and cannot receive the leaked key — which means
ProVerif does not consider scenarios where the attacker forges
operational messages under `K_sess^(1)` against a phase-0 receiver.
G5 still holds: the attacker, fully in possession of `K_sess^(1)`
in phase 1, gains no advantage in attacking `K_sess^(2)`.


## Running Phase 5

```sh
cd /Users/erwin/Documents/Claude/Projects/PhD/proverif/
proverif phase5_replay.pv
```

Seven queries are verified — the same set of properties as Phase 4
but with the operational and handshake-completion correspondences
strengthened to **injective** form:

```
RESULT not attacker_p1(Ksess2_test[]) is true.                                    (G5)
RESULT inj-event(groundAcceptsConfirm(...)) ==> inj-event(aircraftSentKey(...)) is true. (G2 session-level, injective)
RESULT inj-event(aircraftDerivesKsess(...)) ==> inj-event(groundSentKeyAck(...)) is true. (G3, injective)
RESULT inj-event(groundAcceptsConfirm(...)) ==> inj-event(aircraftSentConfirm(...)) is true. (G7, injective)
RESULT inj-event(groundAcceptsSA(...)) ==> inj-event(aircraftSentSA(...)) is true.       (G4_SA, injective)
RESULT inj-event(aircraftAcceptsCC(...)) ==> inj-event(groundSentCC(...)) is true.       (G4_CC, injective)
RESULT inj-event(groundAcceptsAck(...)) ==> inj-event(aircraftSentAck(...)) is true.     (G4_ACK, injective)
```

An injective correspondence is a stronger statement than the
non-injective form used in Phases 3 and 4: it says that each
*Accepts* event maps to a **distinct** *Sent* event. In other words,
the same legitimate send cannot be "counted twice" by the receiver
— which is exactly cross-session replay resistance.

**G2 is measured at SESSION ESTABLISHMENT, not at KEY-acceptance.**
The paper's §3.6 G2 says: "If G accepts a session established with
aircraft A, then A must have initiated that session." The natural
trigger is `groundAcceptsConfirm` (which fires only after KEYCONFIRM
verifies). At KEY-acceptance an attacker can replay a signed KEY to
many `! ground1` instances and each will fire `groundAcceptsKey` —
but only one of them ever completes the handshake. The aircraft
accepts only one KEYACK; its KEYCONFIRM is transcript-bound (`τ =
hash(mKEY ‖ mKEYACK_chosen)`) to that specific KEYACK; the other
`! ground1` instances each compute a different local τ and reject
the KEYCONFIRM. So although multiple `groundAcceptsKey` events fire
under KEY replay, only one `groundAcceptsConfirm` event fires, and
that one corresponds to a distinct `aircraftSentKey`. The injective
form of session-level G2 therefore holds.

Cross-station replay (KEY-to-G1 delivered to G2) is prevented at the
canonical-encoding level: every receiver pattern-matches the `TO`
field literally, so a message addressed to G1 cannot be accepted by
G2 regardless of who replays it.


## Running Phase 6

```sh
cd /Users/erwin/Documents/Claude/Projects/PhD/proverif/
proverif phase6_entropy.pv
```

Seven queries are verified, identical in form to Phase 5 but with a
stronger phase-1 compromise: the aircraft now leaks `skA_eph` of
session 1 (the ephemeral private key itself), not just `K_sess^(1)`.

```
RESULT not attacker_p1(Ksess2_test[]) is true.                                    (G5/G8 refined)
RESULT inj-event(groundAcceptsConfirm(...)) ==> inj-event(aircraftSentKey(...)) is true. (G2)
RESULT inj-event(aircraftDerivesKsess(...)) ==> inj-event(groundSentKeyAck(...)) is true. (G3)
RESULT inj-event(groundAcceptsConfirm(...)) ==> inj-event(aircraftSentConfirm(...)) is true. (G7)
RESULT inj-event(groundAcceptsSA(...)) ==> inj-event(aircraftSentSA(...)) is true.        (G4_SA)
RESULT inj-event(aircraftAcceptsCC(...)) ==> inj-event(groundSentCC(...)) is true.        (G4_CC)
RESULT inj-event(groundAcceptsAck(...)) ==> inj-event(aircraftSentAck(...)) is true.      (G4_ACK)
```

### What Phase 6 actually proves

Leaking `skA_eph1` lets the attacker compute `Z = exp(pkG_eph1,
skA_eph1)` directly, and from there derive session 1's `K_sess^(1)`
— this is a strictly stronger attack than Phase 4's `K_sess^(1)`
leak. ProVerif nonetheless confirms that session 2's `K_sess^(2)`
remains secret and that every phase-0 correspondence still holds.

The meaning: **per-session ephemeral compromise is bounded**. Even
if an attacker fully compromises one party's ephemeral private key
for one session — for example via an RNG attack on that specific
moment — the security of every other session is unaffected. This is
the meaningful symbolic capture of "contributory key agreement gives
entropy resilience".

### What Phase 6 does NOT prove, and what to do about the paper's G8

The paper's §3.6 / §5.1 G8 states a stronger claim — "K_sess remains
secure as long as at least one ephemeral is drawn from a strong
source, even if the other is weak or adversarially chosen". In the
symbolic model this claim is strictly too strong: if the attacker
obtains `skA_eph` it can compute `Z` and therefore `K_sess`
directly. The symbolic model does not distinguish "weak entropy"
from "fully known", so it cannot certify "one weak side compensates".

For the paper, G8 should be split into two precise statements:

* **G8a (symbolic, verified by Phase 6).** *Per-session
  bounded ephemeral compromise.* Compromise of one party's ephemeral
  private key in one session exposes only that session's `K_sess`;
  other sessions' keys remain secure because their ephemerals are
  freshly generated and independent.

* **G8b (computational, requires CryptoVerif).** *Entropy-quantitative
  resilience.* `K_sess` achieves the security-parameter strength as
  long as at least one party's ephemeral has security-parameter
  entropy AND that ephemeral is not directly recoverable by the
  attacker (e.g., its entropy exceeds the brute-force bound).

The paper can reference G8a as the formally verified property and
note G8b as the computational corollary that lies outside the
symbolic model's reach.

Expected runtime: similar to Phase 5.

**Why G3, G4 and G7 are injective.** All of KEYACK, KEYCONFIRM,
SA, CC and ACK are MAC-bound to K_sess, which depends on freshly
generated ephemerals on both sides. A replay to a fresh receiver
instance fails MAC verification because the receiver's K_sess
differs. The receiver state machine is sequential, so a single
receiver cannot accept the same message twice. Hence each *Accepts*
event maps to a distinct *Sent* event.

**Within-session replay** is the residual risk noted explicitly in
§5.3-A3 and §7.5: the symbolic model has no notion of time, so the
"timestamp window" attack vector cannot be captured here. In a real
deployment, application-layer duplicate filtering (timestamp window
or sequence counter) is required to enforce the same property under
timing uncertainty. Phase 6 (entropy resilience) does not change
this.

Expected runtime: noticeably longer than Phase 4 because the
injective correspondences expand the Horn-clause search space.
Tens of seconds to a couple of minutes is normal.

The other six queries are the same as Phase 3 but now range over
both ground stations: ProVerif must show that, even with G1 and G2
running concurrently and with messages from one session
potentially being misdelivered into the other, the correspondence
between sending and accepting events holds for the right host-pair.

Note that **G1 for session 1 is NOT queried in Phase 4** — the
model deliberately leaks `K_sess^(1)` and the G1 property for
session 1 was already verified in Phases 1–3.

Expected runtime: tens of seconds (the model is noticeably more
complex than Phase 3 because of the second ground station and the
sequential two-session aircraft flow).


## What Phase 1 covers and what it doesn't

Phase 1 covers the two-message handshake structure: KEY (signed by
the aircraft) and KEYACK (signed by the ground station), with
session-key derivation from both ephemeral DH contributions and the
session identifier as a domain separator.

Phase 1 deliberately leaves the following out, to be added in later
phases:

- **No KEYCONFIRM** — explicit transcript-bound confirmation is
  Phase 2.
- **No operational messages** — SA, CC, ACK are Phase 3.
- **No handover** — session isolation is Phase 4.
- **No replay defence** — timestamps and sequence-number handling
  are Phase 5.
- **No partial-corruption analysis** — entropy resilience under
  one-sided RNG weakness is Phase 6.


## Subsequent phases

2. `phase2_keyconfirm.pv` — adds the third leg with transcript hash,
   property G7 (handshake transcript agreement) and A12 (handshake
   re-binding).
3. `phase3_operational.pv` — adds SA/CC/ACK, property G4 (message
   integrity) and the operational-role part of A8.
4. `phase4_handover.pv` — adds CONTACT and second ground station,
   property G5 (session isolation).
5. `phase5_replay.pv` — adds replay defences, property G6.
6. `phase6_entropy.pv` — partial corruption of one ephemeral, property
   G8 (entropy resilience).

The eventual consolidated model goes into Appendix A of the paper.
