#!/usr/bin/env bash
set -euo pipefail
# If DEBUG_STATIONS isn't defined (or is commented out), treat it as an empty array.
declare -a DEBUG_STATIONS=("${DEBUG_STATIONS[@]-}")

# Resolve repo root as the parent of the visualisation/ directory this script lives in
REPO="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
MQTT_HOST="127.0.0.1"
MQTT_PORT=1883
TOPIC_BASE="aviation"

# HUMAN station names (must match "TO: EBBR GND" etc.)
STATIONS=(
  "EBBR GND"
  "EBBR TWR"
  "BRUACC"
  "LANGEN"
  "EDDF APP"
  "EDDF TWR"
  "EDDF GND"
  "OOABC"
  "EHAM TWR"
  "EHAM APP"
  "EHAA CTR"
  "EDGG CTR"
  "EDMM CTR"
  "EDDM APP"
  "EDDM TWR"
  "PHAEX"
)

DEBUG_STATIONS=(
#  "EBBR GND"
#  "EBBR TWR"
#  "BRUACC"
#  "LANGEN"
#  "EDDF APP"
#  "EDDF TWR"
#  "EDDF GND"
#  "OOABC"
#  "EHAM TWR"
#  "EHAM APP"
#  "EHAA CTR"
#  "EDGG CTR"
#  "EDMM CTR"
#  "EDDM APP"
#  "EDDM TWR"
#  "PHAEX"
)

is_debug_station() {
  local s="$1"
  # If DEBUG_STATIONS is empty, nothing is a debug station
  (( ${#DEBUG_STATIONS[@]} == 0 )) && return 1

  local d
  for d in "${DEBUG_STATIONS[@]}"; do
    [[ "$d" == "$s" ]] && return 0
  done
  return 1
}

log_name_for_station() {
  # "EBBR GND" -> "EBBR_GND"
  echo "$1" | tr ' ' '_'
}

escape_for_applescript_string() {
  # Escape backslashes and double quotes for use inside AppleScript "..."
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  echo "$s"
}

run_listener() {
  local STATION="$1"
  local ST_LOG
  ST_LOG="$(log_name_for_station "$STATION")"

  local EXTRA_DEBUG=""
  if is_debug_station "$STATION"; then
    EXTRA_DEBUG="--debug"
  fi

  # One-line shell command (no fragile backslash-newlines)
  local CMD
  CMD="cd '$REPO'; mkdir -p logs; source venv/bin/activate; \
python3 -u scripts/demo_subscriber.py \
  --station \"$STATION\" \
  --mqtt-host $MQTT_HOST \
  --mqtt-port $MQTT_PORT \
  --topic-base $TOPIC_BASE \
  --only-for-us \
  $EXTRA_DEBUG \
  2>&1 | tee logs/${ST_LOG}.log"

  local CMD_ESC
  CMD_ESC="$(escape_for_applescript_string "$CMD")"

  local TITLE="AV-LISTENER: $STATION"
  local TITLE_ESC
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

# If DEBUG=1 and no debug stations configured -> start none
if [[ "${DEBUG:-0}" == "1" && ${#DEBUG_STATIONS[@]} -eq 0 ]]; then
  echo "[launch] DEBUG=1 and no DEBUG_STATIONS defined -> starting no listeners."
  exit 0
fi

for ST in "${STATIONS[@]}"; do
  # If in debug mode, only start stations listed in DEBUG_STATIONS
  if [[ "${DEBUG:-0}" == "1" ]]; then
    skip=1
    for D in "${DEBUG_STATIONS[@]}"; do
      [[ "$D" == "$ST" ]] && skip=0 && break
    done
    (( skip )) && continue
  fi

  run_listener "$ST"
done


echo "All listeners started (demo_subscriber.py for each station)."
