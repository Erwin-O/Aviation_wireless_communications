# Secure Aviation Messaging Prototype – User Guide

## 1. Introduction

This User Guide explains how to **install, run, and operate** the Secure Aviation Messaging Prototype. It covers:

* Setting up the environment
* Starting ground-station listeners
* Playing simulation scenarios
* Reading and understanding logs
* Adding new actors, stations, and scenarios

For technical internals refer to the *Developer Guide*.

---

## 2. System Overview

The system simulates secure air–ground messaging using:

* **MQTT** as transport (Mosquitto broker)
* **`scripts/scenario_player.py`** — aircraft behaviour generator
* **`scripts/demo_subscriber.py`** — receiver for each ATS unit (one per station)
* **`scripts/mqtt_recorder.py`** — full-message logger

Message types:

* **KEY** → Establishes a secure cryptographic session (Ed25519 + X25519)
* **SA** → Situational Awareness position reports (BLAKE3/ASCON-MAC authenticated)
* **CC** → Control Commands: clearances, requests, instructions, handovers

---

## 3. Installation

### 3.1 Clone the Repository

```
git clone <repo-url>
cd <repo-directory>
```

### 3.2 Create a Virtual Environment and Install

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

The `pip install -e .` step is required once. It registers the project packages so all scripts can import them without manual path configuration.

### 3.3 Install MQTT Broker (macOS)

```
brew install mosquitto
brew services start mosquitto
```

Default broker settings (from `settings.py`):

* Host: `127.0.0.1`
* Port: `1883`

---

## 4. Key Setup

The system uses end-to-end cryptography. Every actor needs a keypair.

### 4.1 Public Keys

Located in `config/publicKeys.json`. Generated and updated by `add_actor.py`.

### 4.2 Private Keys

Each station must have its own private keys stored locally:

```
~/AviationLocalKeys/<STATION>/ed25519_private.key
~/AviationLocalKeys/<STATION>/x25519_private.key
```

Format: URL-safe Base64, 32 bytes decoded, no newlines.

Generate keypairs with:

```
python3 scripts/add_actor.py add EBBR_GND tower
python3 scripts/add_actor.py add OOABC aircraft
```

If private keys are missing, the listener refuses to start.

---

## 5. Starting All Listeners

Use the launcher script:

```
./visualisation/launch_all_listeners.sh
```

This opens one macOS Terminal window per station and starts `demo_subscriber.py --only-for-us` for each. Output is captured to `logs/<STATION>.log` via `tee`.

### 5.1 Stopping All Listeners

```
./visualisation/stop_all_listeners.sh
```

Kills all `demo_subscriber.py` processes and closes their Terminal windows.

### 5.2 Tiling Windows

```
./visualisation/tile_listeners.sh
```

Arranges all listener windows for a side-by-side overview.

---

## 6. Running a Full Demo

The quickest way to run everything at once:

```
./run_demo.sh --record --scenario scenarios/commercial_flight_EBBR-EDDF.json
```

This launches listeners, starts the recorder, and plays the scenario.

For individual control:

### 6.1 Start the Global Message Recorder (optional)

```
python3 scripts/mqtt_recorder.py \
  --host 127.0.0.1 --port 1883 \
  --topic '#' \
  --view ascii \
  --out-array logs/scenario_log.json
```

### 6.2 Run a Scenario

```
python3 scripts/scenario_player.py --publish \
  scenarios/commercial_flight_EBBR-EDDF.json
```

Add `--debug` for verbose scheduling output.

The aircraft (OOABC):

* Sends periodic **SA** position reports
* Exchanges **KEY** messages when switching ATC units
* Sends **CC** messages based on the scenario timeline

**Note:** Time is divided by 1000 internally so the demo runs fast. Remove the `/1000` in `scenario_player.py → sleep_until()` for real-time operation.

---

## 7. Understanding Message Types

### 7.1 KEY Messages

Establish a secure session. Transmitted once per station handover. Contain:

* Timestamp, From, To
* Aircraft Ed25519 public key
* Session ID
* Wrapped session key (X25519 + ChaCha20-Poly1305)
* Ed25519 signature covering everything above the signature line

Subscribers verify the signature and unwrap the session key.

### 7.2 SA (Situational Awareness) Messages

Periodic position reports. Contain:

* Altitude (ft), latitude, longitude
* Ground speed (kt), heading (degrees)
* On-ground flag
* BLAKE3 or ASCON-MAC over all fields

Stations display only on state change or every N messages (configurable via `SA_LOG_EVERY` env var).

### 7.3 CC (Control Commands)

ATC instructions with Gaussian timing jitter (σ = 5s):

* `CONTACT` → triggers a station handover (new KEY exchange)
* `REQUEST`, `CLEARANCE`, `INSTRUCTION`, `REPORT`, `ACK`

Subscribers queue a MAC-signed ACK reply after a short random delay.

---

## 8. Viewing Logs

### 8.1 Terminal-Capture Logs

Captured automatically by the launch scripts via `tee`:

```
logs/<STATION>.log        all stdout from the listener
logs/mqtt_recorder.out    all stdout from the recorder
```

### 8.2 Structured Logger Files

Written by `core/logger.py` for each component:

```
logs/<component>.txt      human-readable lines: <ts> [LEVEL] [component] msg
logs/<component>.jsonl    one JSON object per line — for analysis tools
logs/<component>.prev     previous run's log (if LOG_BACKUP = True in settings.py)
```

For `scenario_player.py` the component name is the aircraft ID (e.g. `OOABC`).  
For `demo_subscriber.py` it is the normalised station ID (e.g. `EBBR_GND`).

### 8.3 Global Scenario Log

```
logs/scenario_log.json
```

JSON array of all MQTT traffic captured by `mqtt_recorder`. Useful for replay and research analysis.

### 8.4 Adjusting Log Verbosity

Edit `settings.py`:

| Setting | Options | Default | Effect |
|---|---|---|---|
| `LOG_LEVEL` | `WIRE` / `LIMITED` / `FULL` | `LIMITED` | What goes into log files |
| `LOG_FORMAT` | `TXT` / `JSON` / `BOTH` | `BOTH` | Which file formats to write |
| `LOG_BACKUP` | `True` / `False` | `True` | Keep previous run as `.prev` |

`WIRE` logs only raw wire payloads. `LIMITED` adds session and handover events. `FULL` adds verbose debug output.

---

## 9. Adding Your Own Aircraft or Station

### 9.1 Add a New Actor

```
python3 scripts/add_actor.py add <ACTOR_ID> <type>
```

Types: `aircraft`, `atc`, `enroute`, `ground`, `test`, `tower`, `uav`.

Use `--overwrite` to replace existing keys.

### 9.2 Add Aircraft Metadata

```
python3 scripts/add_aircraft.py --icao24 <hex> --registration <reg> --operator <name>
```

### 9.3 Add a New Station to the Demo

1. Generate keypair: `python3 scripts/add_actor.py add <STATION_ID> tower`
2. Add the station name to `STATIONS` in `visualisation/launch_all_listeners.sh`

### 9.4 Create a New Scenario

Convert SA and CC CSV tables:

```
python3 scripts/build_scenario_from_tables.py \
  --sa path/to/sa.csv --cc path/to/cc.csv \
  --aircraft OOABC --station EBBR_GND \
  --out scenarios/my_flight.json
```

Then run:

```
python3 scripts/scenario_player.py --publish scenarios/my_flight.json
```

---

## 10. Troubleshooting

### "Could not load private keys"

Check `~/AviationLocalKeys/<STATION>/ed25519_private.key` and `x25519_private.key` exist and contain valid URL-safe Base64.

### "no session known; skip"

The ground station has not yet received the KEY message. Enable `--debug` on the subscriber to trace routing.

### "KEY signature INVALID — dropped"

The subscriber rejected the KEY. Run the subscriber with `--debug` to see the raw payload and signing inputs. In debug mode the KEY is accepted anyway so the session continues.

### No messages received

* Verify `mosquitto` is running: `brew services list | grep mosquitto`
* Confirm the topic base in all components matches (`aviation` by default)
* Check listener terminal windows for connection errors

### Terminal windows do not close

```
./visualisation/stop_all_listeners.sh
```

---

*End of User Guide*
