# comm_state.py
"""
Shared session state for the scenario player (aircraft side) and
the ground-station subscriber.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class SessionEntry:
    """A single active cryptographic session."""
    session_id: str
    key: bytes          # 32-byte symmetric session key


class SessionBook:
    """
    Generic per-key session store.

    The subscriber keys entries by aircraft ID (e.g. 'OOABC').
    The aircraft side uses AircraftSessionBook, which keys by normalised station ID.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionEntry] = {}

    def get(self, key: str) -> Optional[SessionEntry]:
        return self._sessions.get(key)

    def put(self, key: str, entry: SessionEntry) -> None:
        self._sessions[key] = entry

    def drop(self, key: str) -> None:
        self._sessions.pop(key, None)

    def __repr__(self) -> str:
        return f"<SessionBook n={len(self._sessions)}>"


class AircraftSessionBook(SessionBook):
    """
    SessionBook extended with aircraft-side concerns:
      - tracks the currently active ground station (always normalised)
      - prevents duplicate handover events at the same scenario second
    """

    def __init__(self, initial_station: str) -> None:
        super().__init__()
        from utils.station_norm import normalise_station
        self._current_station: str = normalise_station(initial_station)
        self._last_handover: Optional[Tuple[str, str, int]] = None

    def current_station(self) -> str:
        return self._current_station

    def set_station(self, station: str) -> None:
        from utils.station_norm import normalise_station
        self._current_station = normalise_station(station)

    def get_session(self, station: str) -> Optional[SessionEntry]:
        from utils.station_norm import normalise_station
        return self.get(normalise_station(station))

    def put_session(self, station: str, entry: SessionEntry) -> None:
        from utils.station_norm import normalise_station
        self.put(normalise_station(station), entry)

    def drop_session(self, station: str) -> None:
        from utils.station_norm import normalise_station
        self.drop(normalise_station(station))

    def already_handover(self, old: str, new: str, t_s: int) -> bool:
        """Return True if this exact handover was already processed at this scenario second."""
        from utils.station_norm import normalise_station
        sig = (normalise_station(old), normalise_station(new), t_s)
        if self._last_handover == sig:
            return True
        self._last_handover = sig
        return False

    def __repr__(self) -> str:
        return f"<AircraftSessionBook station={self._current_station} n={len(self._sessions)}>"
