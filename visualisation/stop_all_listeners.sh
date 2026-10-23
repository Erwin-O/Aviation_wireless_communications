#!/bin/bash
#
# Stop every demo process, then close its Terminal window.
#
# Order matters. Terminal asks "Do you want to terminate running processes in
# this window?" for any window whose process is still alive when it is closed,
# which turns tidying up into a row of dialogue boxes. So: end the processes,
# wait for them to actually go, and only then close the windows.
#
# Processes are identified by the PID files that scripts/station.py and
# scripts/aircraft.py write under logs/pids/, not by matching command lines.
# Matching is how this script used to work and it is not safe: a shell whose
# command line happens to mention the script matches it too.
#
# The legacy listener (scripts/demo_subscriber.py) writes no PID file, so it
# is still matched by name, exactly as before.
#

REPO="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
PID_DIR="$REPO/logs/pids"
LEGACY_PATTERN="scripts/demo_subscriber\.py"

echo "Stopping demo processes…"

PIDS=""

# From the PID files
if [ -d "$PID_DIR" ]; then
  for f in "$PID_DIR"/*.pid; do
    [ -e "$f" ] || continue
    case "$(basename "$f")" in
      mqtt_recorder.pid) continue ;;   # stop_demo.sh owns the recorder
    esac
    pid="$(cat "$f" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      ps -p "$pid" -o pid=,command= | cut -c1-100
      PIDS="$PIDS $pid"
    else
      rm -f "$f"                       # stale: the process is already gone
    fi
  done
fi

# Plus anything from the legacy demo
LEGACY=$(pgrep -f "$LEGACY_PATTERN" || true)
for pid in $LEGACY; do
  ps -p "$pid" -o pid=,command= | cut -c1-100
  PIDS="$PIDS $pid"
done

if [ -z "$(echo "$PIDS" | tr -d '[:space:]')" ]; then
  echo "  none running."
else
  for pid in $PIDS; do
    kill "$pid" 2>/dev/null || true
  done

  # Wait for them rather than assuming. This is the part that stops the
  # prompts: a window closed while its process lives is what triggers them.
  for _ in $(seq 1 20); do
    sleep 0.25
    still=""
    for pid in $PIDS; do
      kill -0 "$pid" 2>/dev/null && still="$still $pid"
    done
    [ -z "$(echo "$still" | tr -d '[:space:]')" ] && break
  done

  if [ -n "$(echo "$still" | tr -d '[:space:]')" ]; then
    echo "  still running after SIGTERM; sending SIGKILL:"
    for pid in $still; do
      ps -p "$pid" -o pid=,command= | cut -c1-100
      kill -9 "$pid" 2>/dev/null || true
    done
    sleep 0.5
  fi
  echo "  stopped."
fi

# Clear any PID files the processes did not remove themselves.
if [ -d "$PID_DIR" ]; then
  for f in "$PID_DIR"/*.pid; do
    [ -e "$f" ] || continue
    case "$(basename "$f")" in
      mqtt_recorder.pid) continue ;;
    esac
    pid="$(cat "$f" 2>/dev/null || true)"
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$f"
    fi
  done
fi

echo
echo "Closing Terminal windows for AV-LISTENER tabs…"

osascript <<'EOF'
tell application "Terminal"
    set windowsToClose to {}

    set n to count of windows
    repeat with i from 1 to n
        try
            set w to window i
        on error
            set w to missing value
        end try

        if w is not missing value then
            set shouldClose to false

            repeat with t in tabs of w
                set tTitle to ""
                try
                    set tTitle to custom title of t
                end try

                if tTitle is not "" then
                    if tTitle begins with "AV-LISTENER:" then
                        set shouldClose to true
                    end if
                end if
            end repeat

            if shouldClose is true then
                copy w to end of windowsToClose
            end if
        end if
    end repeat

    repeat with w in windowsToClose
        try
            close w saving no
        on error
            try
                close w
            end try
        end try
    end repeat
end tell
EOF

echo "Done."
