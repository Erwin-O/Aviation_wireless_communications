#!/usr/bin/env bash
set -euo pipefail
#
# Open one Terminal window per ground station, each running scripts/station.py:
# the specification-conforming station of Section 3.3, which verifies every
# message it receives and names the check that refused the ones it discards.
#
# The legacy equivalent is launch_all_listeners.sh, which runs
# scripts/demo_subscriber.py and the older protocol.
#
# Windows are titled "AV-LISTENER: <station>", so stop_all_listeners.sh and
# tile_listeners.sh work on these exactly as they do on the legacy ones.
#
# Environment:
#   SCENARIO   scenario file, so each station plays its own controller script
#   SPEED      scenario speed multiplier (default 1.0)
#   DEBUG=1 with DEBUG_STATIONS=("EBBR GND" ...) starts only those
#

declare -a DEBUG_STATIONS=("${DEBUG_STATIONS[@]-}")

REPO="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
MQTT_HOST="${MQTT_HOST:-127.0.0.1}"
MQTT_PORT="${MQTT_PORT:-1883}"
TOPIC_BASE="${TOPIC_BASE:-aviation}"
SCENARIO="${SCENARIO:-}"
SPEED="${SPEED:-1.0}"

# Stations that hold a credential. Must match scripts/provision.py.
STATIONS=(
  "EBBR GND"
  "EBBR TWR"
  "BRUACC"
  "LANGEN"
  "EDDF APP"
  "EDDF TWR"
  "EDDF GND"
  "EHAM TWR"
  "EHAM APP"
  "EHAA CTR"
  "EDGG CTR"
  "EDMM CTR"
  "EDDM APP"
  "EDDM TWR"
)

log_name_for_station() { echo "$1" | tr ' ' '_'; }

escape_for_applescript_string() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  echo "$s"
}

is_debug_station() {
  (( ${#DEBUG_STATIONS[@]} == 0 )) && return 1
  local want="$1"
  for d in "${DEBUG_STATIONS[@]}"; do
    [[ "$d" == "$want" ]] && return 0
  done
  return 1
}

run_station() {
  local STATION="$1"
  local ST_LOG
  ST_LOG="$(log_name_for_station "$STATION")"

  local EXTRA=""
  is_debug_station "$STATION" && EXTRA="--debug"
  [[ -n "$SCENARIO" ]] && EXTRA="$EXTRA --scenario '$SCENARIO' --speed $SPEED"

  local CMD
  CMD="cd '$REPO'; mkdir -p logs; source venv/bin/activate; \
python3 -u scripts/station.py \
  --station \"$STATION\" \
  --host $MQTT_HOST \
  --port $MQTT_PORT \
  --base $TOPIC_BASE \
  $EXTRA \
  2>&1 | tee logs/${ST_LOG}.log"

  local CMD_ESC TITLE TITLE_ESC
  CMD_ESC="$(escape_for_applescript_string "$CMD")"
  TITLE="AV-LISTENER: $STATION"
  TITLE_ESC="$(escape_for_applescript_string "$TITLE")"

osascript <<EOF
tell application "Terminal"
  activate
  do script ""
  delay 0.1
  do script "$CMD_ESC" in front window
  tell front window
    set custom title of selected tab to "$TITLE_ESC"
  end tell
end tell
EOF
}

if [[ "${DEBUG:-0}" == "1" && ${#DEBUG_STATIONS[@]} -eq 0 ]]; then
  echo "[launch] DEBUG=1 and no DEBUG_STATIONS defined -> starting no stations."
  exit 0
fi

for ST in "${STATIONS[@]}"; do
  if [[ "${DEBUG:-0}" == "1" ]] && ! is_debug_station "$ST"; then
    continue
  fi
  run_station "$ST"
done

echo "All stations started (scripts/station.py for each)."
