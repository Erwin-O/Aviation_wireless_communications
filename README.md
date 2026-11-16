# Secure Aviation Messaging Prototype

[![DOI](https://zenodo.org/badge/732568873.svg)](https://doi.org/10.5281/zenodo.24269463)

A research prototype of a secure, transport-independent air–ground
communication protocol, implementing the specification in Section 3.3 of the
accompanying paper.

Modern aviation runs on a diverse set of digital links — VDL2, ACARS, Mode-S,
CPDLC — whose security guarantees, where they exist, are bound to the
transport and depend on persistent session state. This prototype takes a
different position: what a message authorises is decided from the message.

---

## What it does

A receiver establishes from the message alone **what act it performs** and
**whether its sender was entitled to perform it**. Two authenticated fields
carry that: the `ROLE`, naming the operational kind of the message, and the
sender's `CREDENTIAL`, stating which roles it may assert and in which
airspace. Possession of a valid session key is not sufficient to issue a
clearance.

- Three-message mutually authenticated key agreement with explicit
  confirmation over the transcript
- Credentials carried in the messages, verified against **issuer** trust
  anchors rather than a directory of known principals
- A ground station states the airspace it is working, bounded by what its
  issuer granted it, so **any** aircraft can verify that claim with no
  airspace data of its own, and decides for itself whether to proceed
- A challenge the aircraft itself issues, binding every command to the report
  it answers, so a command cannot be acted upon twice or out of turn
- Transfer of control between ground stations requiring **no channel between
  them**
- Payloads in clear, authenticated with Ascon-Mac under a forward-secret
  session key
- Every intermediary untrusted, the MQTT broker included

Cryptography: Ed25519, X25519, and the Ascon family (NIST SP 800-232) —
Ascon-Mac, Ascon-Hash256, Ascon-CXOF128. 128-bit security throughout.

---

## Quick start

```bash
cd Software
python3 -m venv venv && source venv/bin/activate
pip install -e .

python -m unittest discover -s tests -t . -q   # 167 tests, all offline

docker compose up -d                       # mosquitto on 127.0.0.1:1883

./run_demo.sh --record --speed 20 \
  --scenario scenarios/commercial_flight_EBBR-EDDF.json
```

That provisions credentials, opens a Terminal window per ground station and
one for the aircraft, tiles them, and flies Brussels to Frankfurt across seven
stations at twenty times real time. Add `--verbose` to see every message field
by field.

```bash
./stop_demo.sh                             # ends the processes, closes the windows
```

No broker to hand? Fly the whole scenario in one process:

```bash
python3 scripts/replay.py scenarios/commercial_flight_EBBR-EDDF.json
```

Tests:

```bash
python -m unittest discover -s tests -t . -v      # 148 tests
```

---

## Repository layout

```
Software/
├── protocol/            the specification: encoding, primitives, credentials,
│                        handshake, session, operational, node, identity,
│                        mqtt_binding, rejection
├── encryption/          ascon.py, the NIST SP 800-232 reference implementation
├── scripts/             provision.py, aircraft.py, station.py, replay.py,
│                        and the scenario and database tooling
├── tests/               148 tests
├── visualisation/       Terminal window launchers, tiling, stop
├── config/              trust_anchors.json, aircraft and airport databases
├── scenarios/           recorded flights
├── proverif/            the formal models and their verification output
└── run_demo.sh, stop_demo.sh
```

An earlier prototype implemented a different protocol: session keys wrapped
to a static public key, a directory of known principals, and no verification
of operational messages on receipt. It was removed when this implementation
replaced it, and remains in the git history at the tag
`legacy-implementation` for anyone reproducing the results reported in the
companion paper.

---

## Documentation

| Document | For |
|---|---|
| `ARCHITECTURE.md` | the design and its rationale, and the trade-offs |
| `DEVELOPER GUIDE.md` | how the implementation works and how to change it |
| `MODULE DEPENDENCIES.md` | the import graph, module by module |
| `CODE_INDEX.md` | what every file is |
| `USER GUIDE.md` | installing, running, reading the output, troubleshooting |

Start with `USER GUIDE.md` to run it, `ARCHITECTURE.md` to understand it, and
`DEVELOPER GUIDE.md` before changing it.

---

## Status

A research prototype. It establishes that the specification can be realised
as written and that each check it requires rejects the input it is meant to
reject — every refusal names the check that refused it, and the tests assert
the check rather than merely the refusal.

It does not model real bearer behaviour: processes exchange messages through
a broker on the same host, and latency, loss and radio characteristics are
absent. Performance on airborne hardware and across real bearers is the
subject of a companion paper.

---

## Citing this work

Cite the paper. `CITATION.cff` carries the metadata, and GitHub offers a
formatted citation from it. If you need to refer to a particular state of the
code, cite a release.

---

## Licence

Apache-2.0. See `LICENSE`.

The implementation is the work of one author, written in his own time. Two
things in the tree are not his, and `NOTICE` records both:

- `proverif/` holds the three formal models printed in the paper's
  appendices. They are Frederic Lafitte's work, included with his
  permission. Nothing in the implementation depends on them.
- `encryption/ascon.py` is Maria Eichlseder's pyascon reference
  implementation, released under CC0 1.0. CC0 requires no attribution;
  `NOTICE` credits it anyway, because the cryptographic core of this work
  is hers.
