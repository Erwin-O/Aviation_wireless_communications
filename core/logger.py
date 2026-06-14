# core/logger.py
"""
Unified file logger for all components.

LOG_LEVEL  = "WIRE"    – raw wire payloads only (always written)
           = "LIMITED" – + key events (sessions, handovers, errors)
           = "FULL"    – + verbose debug output

LOG_FORMAT = "TXT"     – human-readable  logs/<component>.txt
           = "JSON"    – machine-readable logs/<component>.jsonl
           = "BOTH"    – both files simultaneously

LOG_BACKUP = True      – rename existing log file to .prev on startup
"""

import json
import time
from pathlib import Path

from settings import LOG_LEVEL, LOG_FORMAT, LOG_BACKUP

_LEVELS = {"WIRE": 0, "LIMITED": 1, "FULL": 2}


class Logger:
    """Per-component file logger.

    Console output is NOT the responsibility of this class — callers keep their
    existing print() calls.  This class writes to structured log files only.
    """

    def __init__(self, component: str, log_dir: str = "logs") -> None:
        self.component = component
        self._threshold = _LEVELS.get(LOG_LEVEL.upper(), _LEVELS["LIMITED"])

        base = Path(log_dir)
        base.mkdir(parents=True, exist_ok=True)

        self._txt = self._jsonl = None

        if LOG_FORMAT in ("TXT", "BOTH"):
            p = base / f"{component}.txt"
            if LOG_BACKUP and p.exists():
                p.rename(p.with_suffix(".prev"))
            self._txt = open(p, "a", encoding="utf-8")

        if LOG_FORMAT in ("JSON", "BOTH"):
            p = base / f"{component}.jsonl"
            if LOG_BACKUP and p.exists():
                p.rename(p.with_suffix(".prev"))
            self._jsonl = open(p, "a", encoding="utf-8")

    @staticmethod
    def _ts() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _write(self, level: str, msg: str, data: dict | None) -> None:
        ts = self._ts()
        if self._txt:
            line = f"{ts} [{level}] [{self.component}] {msg}"
            if data:
                line += "  " + json.dumps(data, separators=(",", ":"), ensure_ascii=False)
            self._txt.write(line + "\n")
            self._txt.flush()
        if self._jsonl:
            obj: dict = {"ts": ts, "level": level, "component": self.component, "msg": msg}
            if data:
                obj["data"] = data
            self._jsonl.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")
            self._jsonl.flush()

    def wire(self, msg: str, data: dict | None = None) -> None:
        """Raw wire payload. Always written (lowest level)."""
        self._write("WIRE", msg, data)

    def event(self, msg: str, data: dict | None = None) -> None:
        """Key event (session, handover, error). Written at LOG_LEVEL >= LIMITED."""
        if self._threshold >= _LEVELS["LIMITED"]:
            self._write("EVENT", msg, data)

    def debug(self, msg: str, data: dict | None = None) -> None:
        """Verbose debug. Written at LOG_LEVEL == FULL only."""
        if self._threshold >= _LEVELS["FULL"]:
            self._write("DEBUG", msg, data)

    def close(self) -> None:
        for f in (self._txt, self._jsonl):
            if f:
                try:
                    f.close()
                except OSError:
                    pass


def get_logger(component: str, log_dir: str = "logs") -> Logger:
    """Return a new Logger writing to logs/<component>.{txt,jsonl}."""
    return Logger(component, log_dir)
