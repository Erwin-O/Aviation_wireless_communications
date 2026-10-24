# Secure Aviation Messaging Prototype – User Guide

Running the demo and reading what it shows you. For the code, see
`CODE_INDEX.md`, `DEVELOPER GUIDE.md` and `MODULE DEPENDENCIES.md`.

---

## 1. Introduction

The demo flies a recorded flight across a sequence of air traffic control
stations, each in its own Terminal window, over an MQTT broker that is
treated as untrusted. Every message is authenticated; every message that
fails a check is discarded with the name of the check that refused it.

What you are watching is the protocol of Section 3.3 of the IJCIP paper: a
three-message handshake, credentials carried in the messages themselves, a
challenge exchange binding each command to the report it answers, and a
transfer of control that needs no channel between ground stations.

---

## 2. System Overview

| Piece | What it is |
|---|---|
| Aircraft | `scripts/aircraft.py`, one process, flies the scenario |
| Stations | `scripts/station.py`, one process and one window per station |
| Broker | Mosquitto on `127.0.0.1:1883`, untrusted, relays only |
| Credentials | issued by `scripts/provision.py` before the demo starts |
| Recorder | `scripts/mqtt_recorder.py`, optional, captures all traffic |

---

## 3. Installation

### 3.1 Virtual environment

```bash
cd ~/Documents/Claude/Projects/PhD/Software
python3 -m venv venv
source venv/bin/activate
pip install -e .
pip install paho-mqtt cryptography
```

### 3.2 MQTT broker

```bash
docker compose up -d          # eclipse-mosquitto:2, port 1883
```

or with Homebrew:

```bash
brew install mosquitto
brew services start mosquitto
```

`run_demo.sh` does **not** start the broker. Check it is listening:

```bash
nc -z 127.0.0.1 1883 && echo "broker up"
```

---

## 4. Credentials

Everything in the demo depends on credentials, and `run_demo.sh` issues them
for you. To do it by hand:

```bash
python3 scripts/provision.py            # issue, valid 7 days
python3 scripts/provision.py --days 30  # a longer window
python3 scripts/provision.py --list     # show what exists
```

What it writes:

```
config/trust_anchors.json          the issuer's public key — the only shared file
~/AviationLocalKeys/<ACTOR>/
    ed25519_private.key            signing key
    x25519_private.key             long-term key-exchange secret
    credential                     the signed record
```

Existing keys are reused, so running it again reissues credentials without
invalidating anything. It finishes by checking that every credential it
issued verifies against the anchor it just wrote:

```
every credential verifies against the trust anchor
```

If that line is missing, stop and fix it before running the demo — see
Troubleshooting.

---

## 5. Running the demo

```bash
./run_demo.sh --record --scenario scenarios/commercial_flight_EBBR-EDDF.json --speed 20
```

This provisions credentials, opens one window per station plus one for the
aircraft, tiles them, starts the recorder, and flies the scenario at twenty
times real time.

| Option | Effect |
|---|---|
| `--scenario <path>` | which flight |
| `--speed <factor>` | replay multiplier, default 1.0 |
| `--verbose` | print every message, field by field, everywhere |
| `--record` | capture all traffic to `logs/scenario_log.json` |
| `--no-provision` | do not reissue credentials |
| `--foreground` | run the aircraft in this shell instead of its own window |
| `--no-listeners`, `--no-tile` | skip the windows or the tiling |

Scenarios: `commercial_flight_EBBR-EDDF.json` (OOABC, Brussels to Frankfurt,
seven stations) and `flight_EHAM_EDDM_PHAEX.json` (PHAEX, Amsterdam to
Munich, six).

### 5.1 Stopping

```bash
./stop_demo.sh
```

This ends every process first and then closes the windows, in that order.
Closing a window whose process is still running is what makes Terminal ask
"Do you want to terminate running processes in this window?".

To close only the station windows: `./visualisation/stop_all_listeners.sh`.

### 5.2 Without a broker

`scripts/replay.py` flies a whole scenario in one process, with no broker and
no sockets, and prints the totals:

```bash
python3 scripts/replay.py scenarios/commercial_flight_EBBR-EDDF.json
```

```
--- messages sent ---
  SA                 281
  ACK                 38
  CC:INSTRUCTION      26
  ...
  total              396   124.1 KiB, 320 B/message average
```

---

## 6. Reading the output

Ordinary mode prints one line per message:

```
  <- SA             accepted
  -> CC:CLEARANCE   OOABC
```

`--verbose` prints the message itself:

```
  <- SA             accepted   [aviation/sa/EBBR_GND]   327 B
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

  -> CC:CLEARANCE   OOABC   [aviation/cc_clearance/OOABC]   203 B
    INSTRUCTION: STARTUP APPROVED
    IN_REPLY_TO: cQNrat6ILCJf1W1qSTrFYZcsdar7RgN8rRDsbb--Ncw
    MAC: hINpaXq8iCtOIK4A2m38dw
```

The clearance quotes the report's `CHALLENGE` in its `IN_REPLY_TO`. That is
the exchange: the aircraft acts on the command only because it answers the
challenge the aircraft itself issued.

Credentials and signatures are shortened for display, with their length
shown. Nothing in the protocol sees the shortened form.

### 6.1 Message types

| Role | Direction | Carries |
|---|---|---|
| `KEY` | aircraft → station | credential, ephemeral public value, signature |
| `KEYACK` | station → aircraft | the same, from the station, plus `AIRSPACE`, the airspace it is working |
| `KEYCONFIRM` | aircraft → station | transcript hash, tag under the session key |
| `SA` | aircraft → station | position, altitude and reference, speed, heading, `LAST_EXEC`, `CHALLENGE` |
| `CC:REQUEST` | aircraft → station | a request |
| `CC:CLEARANCE`, `CC:INSTRUCTION` | station → aircraft | an instruction and `IN_REPLY_TO` |
| `CC:CONTACT` | station → aircraft | nominates a successor station |
| `CC:EMERGENCY` | either | a declaration |
| `CC:SYSTEM` | either | about the communication, not the flight |
| `ACK` | aircraft → station | a digest of the message acknowledged, and the next challenge |

### 6.2 Discards

```
  xx CC:INSTRUCTION DISCARDED at challenge: IN_REPLY_TO does not match the outstanding challenge
```

Every refusal names its check. The ones you are most likely to see:

| Step | Means |
|---|---|
| `challenge` | the command answered a challenge the aircraft has already retired |
| `tag` | the message was altered, or came from another session |
| `timestamp_window` | outside Δt_max of the receiver's clock |
| `session_state` | a command sent to an aircraft in handover |
| `role_not_permitted` | the sender's credential does not list that role |
| `sector` | a station claimed airspace beyond its credential, or is not credentialled for the airspace reported |
| `airspace` | the station's claim does not contain where the aircraft is |
| `issuer_signature` | the credential was not signed by a trusted issuer |

A handful of `challenge` discards in a fast replay is normal and is the
protocol working: where two reports overtake one another the station may
answer one the aircraft has already superseded, which costs a refusal and a
resend on the following report. At `--speed 20` or higher you will see
several; at real time, few.

---

## 7. Logs

| Path | What |
|---|---|
| `logs/<STATION>.log` | everything that window printed |
| `logs/OOABC.log` | the aircraft's side |
| `logs/scenario_log.json` | the recorder's capture, with `--record` |
| `logs/pids/*.pid` | one per running process, used by the stop script |
| `logs/mqtt_recorder.out` | the recorder's own output |

A quick count of what a station accepted and refused:

```bash
grep -c accepted logs/EBBR_GND.log
grep -o 'DISCARDED at [a-z_]*' logs/*.log | sort | uniq -c
```

---

## 8. Adding an aircraft or a station

### A station

1. Add its name and sector to `STATIONS` in `scripts/provision.py`.
2. Add the name to `STATIONS` in `visualisation/launch_all_stations.sh`.
3. `python3 scripts/provision.py`

Sectors use dotted containment: a credential for `EBBU` covers `EBBU.EBBR`.

### An aircraft

1. Add its registration to `AIRCRAFT` in `scripts/provision.py`.
2. `python3 scripts/provision.py`
3. Add its metadata to `config/aircraft_db.json` if the scenario tooling
   needs it.

### A scenario

`scripts/build_scenario_from_tables.py` builds one from CSV. The CONTACT rows
determine the sequence of controlling stations, and every station named must
hold a credential.

---

## 9. Troubleshooting

**Every message discarded at `issuer_signature`.**
The trust anchors and the issuer's key have drifted apart. Run
`python3 scripts/provision.py` and check it ends with "every credential
verifies against the trust anchor".

**`No credential for <name>`.**
That principal was never provisioned. Add it to `scripts/provision.py` and
reprovision.

**The aircraft says "no answer from <station>, retrying".**
The station is not running, is not subscribed, or the broker is down. The
aircraft repeats the first KEY five times before giving up; check the
station's window opened and shows "subscribed to aviation/+/<NAME>".

**Nothing is delivered, but everything says it connected.**
Usually the broker: `nc -z 127.0.0.1 1883`. If it is up, check the station
window printed its "subscribed to" line, which is printed from the connect
callback and so proves the subscription was actually issued.

**Terminal asks to terminate running processes when closing.**
Use `./stop_demo.sh` rather than closing windows by hand. If it still asks,
`ls logs/pids/` shows whether the processes registered themselves.

**The windows do not close.**
`stop_all_listeners.sh` reports how many it closed. It matches windows whose
title contains `AV-LISTENER:`, so a window you have renamed will not be
closed. macOS may also need Terminal to be allowed to control itself under
Privacy & Security → Automation.

**Everything discarded at `timestamp_window`.**
The clock is off by more than Δt_max (120 s), or a scenario is being replayed
against stale credentials. Reprovision.

**`ModuleNotFoundError: No module named 'protocol'`.**
Run from the repository root with the virtual environment active, or
reinstall with `pip install -e .`.
