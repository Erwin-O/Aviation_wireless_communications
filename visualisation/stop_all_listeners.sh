#!/bin/bash
#
# Stop all aviation demo_subscriber listeners and close their Terminal windows.
#

echo "Scanning for demo_subscriber listeners…"

# Match any process whose command line contains 'demo_subscriber.py'
PIDS=$(pgrep -f "demo_subscriber.py" || true)

if [ -z "$PIDS" ]; then
  echo "No demo_subscriber listeners found."
else
  echo "Running listeners:"
  for pid in $PIDS; do
    ps -p "$pid" -o pid,command
  done

  echo
  echo "Stopping…"
  for pid in $PIDS; do
    kill "$pid" 2>/dev/null || true
  done

  # give them a moment to die
  sleep 1

  LEFT=$(pgrep -f "demo_subscriber.py" || true)
  if [ -z "$LEFT" ]; then
    echo "All demo_subscriber listeners stopped."
  else
    echo "Some listeners still running (you may need to kill -9):"
    for pid in $LEFT; do
      ps -p "$pid" -o pid,command
    done
  fi
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
            close w
        end try
    end repeat
end tell
EOF

echo "Done."
