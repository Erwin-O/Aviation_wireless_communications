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

REPO="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
PID_DIR="$REPO/logs/pids"

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

CLOSED=$(osascript <<'APPLESCRIPT'
-- Close the demo's windows.
--
-- Filter on the window's name rather than walking its tabs. Asking for
-- "every tab of window id N" raises -1728 on a window Terminal will not
-- enumerate, and because that error propagates out of the whole script,
-- nothing gets closed at all. run_demo.sh already counts these windows with
-- the same "name contains" filter, so it is known to work.
--
-- Each close is guarded separately: one window that refuses must not stop
-- the rest.
tell application "Terminal"
    set targets to {}
    try
        set targets to (every window whose name contains "AV-LISTENER:")
    end try

    set closedCount to 0
    repeat with w in targets
        try
            close w saving no
            set closedCount to closedCount + 1
        on error
            try
                close w
                set closedCount to closedCount + 1
            end try
        end try
    end repeat
    return closedCount
end tell
APPLESCRIPT
)

if [ -z "$CLOSED" ]; then
  echo "  could not talk to Terminal; close the windows by hand."
else
  echo "  closed $CLOSED window(s)."
fi

echo "Done."
