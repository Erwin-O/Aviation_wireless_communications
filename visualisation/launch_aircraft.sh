#!/usr/bin/env bash
set -euo pipefail
#
# Open a Terminal window for the aircraft, so it sits in the tiled view
# alongside the stations instead of scrolling past in the shell that started
# the demo.
#
# The window is titled "AV-LISTENER: <aircraft>" like the stations', so
# tile_listeners.sh and stop_all_listeners.sh treat it the same way. The
# aircraft is not a station and holds no station credential; the shared title
# is a convenience of the display, nothing more.
#
# Usage: launch_aircraft.sh <scenario>
# Environment: SPEED, VERBOSE, MQTT_HOST, MQTT_PORT, TOPIC_BASE
#

SCENARIO="${1:-}"
if [[ -z "$SCENARIO" ]]; then
  echo "[launch_aircraft] no scenario given" >&2
  exit 1
fi

REPO="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
MQTT_HOST="${MQTT_HOST:-127.0.0.1}"
MQTT_PORT="${MQTT_PORT:-1883}"
TOPIC_BASE="${TOPIC_BASE:-aviation}"
SPEED="${SPEED:-1.0}"
VERBOSE="${VERBOSE:-0}"

# The aircraft the scenario flies, so the window carries its registration.
AIRCRAFT="$(python3 - "$SCENARIO" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["flight"]["aircraft_id"].replace("_", " "))
PY
)"

escape_for_applescript_string() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  echo "$s"
}

EXTRA=""
[[ "$VERBOSE" == "1" ]] && EXTRA="--verbose"

LOG="$(echo "$AIRCRAFT" | tr ' ' '_')"
CMD="cd '$REPO'; mkdir -p logs; source venv/bin/activate; \
python3 -u scripts/aircraft.py \
  --scenario '$SCENARIO' \
  --host $MQTT_HOST \
  --port $MQTT_PORT \
  --base $TOPIC_BASE \
  --speed $SPEED \
  $EXTRA \
  2>&1 | tee logs/${LOG}.log"

CMD_ESC="$(escape_for_applescript_string "$CMD")"
TITLE_ESC="$(escape_for_applescript_string "AV-LISTENER: $AIRCRAFT")"

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

echo "Aircraft $AIRCRAFT started (scripts/aircraft.py)."
