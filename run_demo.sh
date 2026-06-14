#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Defaults
# -----------------------------
HOST="127.0.0.1"
PORT="1883"
TOPIC="#"
VIEW="ascii"
OUT_ARRAY="logs/scenario_log.json"

RECORD=1
SCENARIO=""
DEBUG_SCENARIO=1

# If you already have launch_all_listeners.sh / tile_listeners.sh, we'll call them.
LAUNCH_LISTENERS=1
TILE=1

PID_DIR="logs/pids"
REC_PID_FILE="$PID_DIR/mqtt_recorder.pid"

# -----------------------------
# Helpers
# -----------------------------
usage() {
  cat <<'EOF'
Usage:
  ./run_demo.sh [options]

Options:
  --host <ip>            MQTT host (default: 127.0.0.1)
  --port <port>          MQTT port (default: 1883)
  --topic <topic>        Recorder topic filter (default: #)
  --view <ascii|json>    Recorder view (default: ascii)
  --out-array <path>     Recorder output JSON array file (default: logs/scenario_log.json)

  --no-listeners         Do not launch listeners
  --no-tile              Do not run tile_listeners.sh after launching listeners (optional)

  --record               Start mqtt_recorder
  --no-record            Explicitly do not start mqtt_recorder (default)

  --scenario <path>      Start scenario_player with given scenario JSON
  --debug-scenario        Pass --debug to scenario_player

  -h, --help             Show this help

Examples:
  # Listeners only
  ./run_demo.sh

  # Listeners + recorder
  ./run_demo.sh --record

  # Full demo: listeners + recorder + scenario
  ./run_demo.sh --record --scenario scenarios/commercial_flight_EBBR-EDDF.json

  # Full demo with scenario debug
  ./run_demo.sh --record --scenario scenarios/commercial_flight_EBBR-EDDF.json --debug-scenario
EOF
}

info() { echo "[run_demo] $*"; }
warn() { echo "[run_demo][WARN] $*" >&2; }

ensure_dirs() {
  mkdir -p logs
  mkdir -p "$PID_DIR"
}

start_listeners() {
  if [[ "$LAUNCH_LISTENERS" -eq 0 ]]; then
    info "Skipping listeners (--no-listeners)."
    return
  fi

  if [[ -x "./visualisation/launch_all_listeners.sh" ]]; then
    info "Launching listeners via ./visualisation/launch_all_listeners.sh"
    ./visualisation/launch_all_listeners.sh
  else
    warn "launch_all_listeners.sh not found or not executable. Skipping listeners."
  fi

  wait_for_av_listener_windows() {
    local expected="${1:-8}"     # you have 8 listeners in your output
    local tries=0
    local max_tries=60           # 60 * 0.2s = 12s

    while (( tries < max_tries )); do
      # Count Terminal windows whose name contains "AV-LISTENER:"
      local n
      n="$(osascript -e 'tell application "Terminal" to count (windows whose name contains "AV-LISTENER:")' 2>/dev/null || echo 0)"

      # Trim whitespace
      n="${n//[[:space:]]/}"

      if [[ "$n" =~ ^[0-9]+$ ]] && (( n >= expected )); then
        return 0
      fi

      sleep 0.2
      ((tries++))
    done

    echo "[run_demo][WARN] Only saw $n AV-LISTENER windows after waiting; tiling anyway." >&2
    return 1
  }


  if [[ "$TILE" -eq 1 ]]; then
    if [[ -x "./visualisation/tile_listeners.sh" ]]; then
      info "Waiting for listener terminals to exist..."
      wait_for_av_listener_windows 8
      info "Tiling listener terminals via ./visualisation/tile_listeners.sh"
      ./visualisation/tile_listeners.sh
    else
      warn "visualisation/tile_listeners.sh not found or not executable. Skipping tiling."
    fi
  fi
}



start_recorder() {
  if [[ "$RECORD" -eq 0 ]]; then
    info "Recorder disabled."
    return
  fi

  # If an old PID exists and process is alive, don't start a duplicate
  if [[ -f "$REC_PID_FILE" ]]; then
    local oldpid
    oldpid="$(cat "$REC_PID_FILE" || true)"
    if [[ -n "${oldpid:-}" ]] && kill -0 "$oldpid" 2>/dev/null; then
      warn "mqtt_recorder already running (pid=$oldpid). Not starting another."
      return
    else
      rm -f "$REC_PID_FILE"
    fi
  fi

  info "Preparing recorder log..."
  rm -f logs/scenario_log.json

  info "Starting mqtt_recorder..."
  # Run in background and store PID
  python3 scripts/mqtt_recorder.py \
    --host "$HOST" --port "$PORT" \
    --topic "$TOPIC" \
    --view "$VIEW" \
    --out-array "$OUT_ARRAY" \
    > logs/mqtt_recorder.out 2>&1 &

  local pid=$!
  echo "$pid" > "$REC_PID_FILE"
  info "mqtt_recorder started (pid=$pid), output -> logs/mqtt_recorder.out"
  info "log array -> $OUT_ARRAY"
}

start_scenario() {
  if [[ -z "$SCENARIO" ]]; then
    info "No scenario specified; not starting scenario_player."
    return
  fi

  if [[ ! -f "$SCENARIO" ]]; then
    warn "Scenario file not found: $SCENARIO"
    warn "Skipping scenario start."
    return
  fi

  info "Starting scenario_player: $SCENARIO"
  if [[ "$DEBUG_SCENARIO" -eq 1 ]]; then
    python3 scripts/scenario_player.py --publish "$SCENARIO" --debug

  else
    python3 scripts/scenario_player.py --publish "$SCENARIO"
  fi
}

# -----------------------------
# Parse args
# -----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --topic) TOPIC="$2"; shift 2 ;;
    --view) VIEW="$2"; shift 2 ;;
    --out-array) OUT_ARRAY="$2"; shift 2 ;;

    --no-listeners) LAUNCH_LISTENERS=0; shift ;;
    --no-tile) TILE=0; shift ;;

    --record) RECORD=1; shift ;;
    --no-record) RECORD=0; shift ;;

    --scenario) SCENARIO="$2"; shift 2 ;;
    --debug-scenario) DEBUG_SCENARIO=1; shift ;;

    -h|--help) usage; exit 0 ;;
    *)
      warn "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

# -----------------------------
# Main
# -----------------------------
ensure_dirs
start_listeners
start_recorder
start_scenario

info "Done."
info "To stop listeners: ./visualisation/stop_all_listeners.sh"
info "To stop recorder:  ./stop_demo.sh   (recommended)  OR  kill \$(cat $REC_PID_FILE)"
