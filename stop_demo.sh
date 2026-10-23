#!/usr/bin/env bash
set -euo pipefail

PID_DIR="logs/pids"
REC_PID_FILE="$PID_DIR/mqtt_recorder.pid"

echo "[stop_demo] Stopping listeners (if script exists)..."
if [[ -x "./visualisation/stop_all_listeners.sh" ]]; then
  ./visualisation/stop_all_listeners.sh
elif [[ -x "./stop_all_listeners.sh" ]]; then
  ./stop_all_listeners.sh
else
  echo "[stop_demo][WARN] stop_all_listeners.sh not found or not executable."
fi

echo "[stop_demo] Stopping mqtt_recorder (if running)..."
if [[ -f "$REC_PID_FILE" ]]; then
  pid="$(cat "$REC_PID_FILE" || true)"

  if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "[stop_demo] Sending SIGINT to mqtt_recorder (pid=$pid)..."
    kill -INT "$pid" 2>/dev/null || true

    # wait up to 5 seconds for clean shutdown + JSON flush
    for _ in {1..50}; do
      if ! kill -0 "$pid" 2>/dev/null; then
        echo "[stop_demo] mqtt_recorder exited cleanly after SIGINT."
        break
      fi
      sleep 0.1
    done

    if kill -0 "$pid" 2>/dev/null; then
      echo "[stop_demo][WARN] Still running; sending SIGTERM..."
      kill -TERM "$pid" 2>/dev/null || true
      for _ in {1..50}; do
        if ! kill -0 "$pid" 2>/dev/null; then
          echo "[stop_demo] mqtt_recorder exited cleanly after SIGTERM."
          break
        fi
        sleep 0.1
      done
    fi

    if kill -0 "$pid" 2>/dev/null; then
      echo "[stop_demo][WARN] Still running; sending SIGKILL..."
      kill -KILL "$pid" 2>/dev/null || true
    fi

    echo "[stop_demo] mqtt_recorder stopped (pid=$pid)"
  else
    echo "[stop_demo] No running process found for pid=$pid"
  fi

  rm -f "$REC_PID_FILE"
else
  echo "[stop_demo] No recorder pid file found."
fi

echo "[stop_demo] Done."
