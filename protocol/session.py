"""
Session state and the challenge bookkeeping (paper, Sections 3.3.3 and 3.3.4).

Each endpoint keeps a table indexed by the aircraft--ground station pair. No
session identifier is carried anywhere: the key distinguishes sessions.

    pending       key agreed, confirmation outstanding. No operational
                  traffic passes in either direction.
    established   the only state carrying the full range of traffic, and
                  the only one in which the station holds command authority.
    handover      authority relinquished, channel retained.

The asymmetry in leaving `handover` is deliberate and is what lets a transfer
need no channel between ground stations: the aircraft leaves when a successor
session is established, the outgoing station when it is told or when
Delta t_ho expires.

The challenge bookkeeping lives here too, because it is per-session state:
what the aircraft has outstanding, what it last acted upon, and what the
station is waiting to hear about.
"""

from __future__ import annotations

import enum
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from protocol import credentials, primitives
from protocol.rejection import Rejected, Step


class State(enum.Enum):
    PENDING = "pending"
    ESTABLISHED = "established"
    HANDOVER = "handover"


#: Roles an aircraft acts upon, and therefore the ones bound to a challenge
#: and refused in `handover` (Section 3.3.4).
#:
#: CC:SYSTEM and CC:EMERGENCY are excluded by design: Section 3.3.4 keeps both
#: flowing in `handover`, which they could not do if they were gated on a
#: challenge the aircraft has retired. They carry IN_REPLY_TO like any other
#: ground-sent CC, but admission does not depend on it.
COMMAND_ROLES = frozenset({"CC:CLEARANCE", "CC:INSTRUCTION", "CC:CONTACT"})

#: How long a station keeps a session `pending` without KEYCONFIRM
#: ("a short timeout", Section 3.3.4; the paper gives no value).
DEFAULT_PENDING_TIMEOUT = timedelta(seconds=30)

#: Delta t_ho, the interval after which an outgoing station stops waiting
#: (Section 3.3.4; the paper gives no value).
DEFAULT_HANDOVER_TIMEOUT = timedelta(seconds=120)

#: Delta t_rep, the longest an aircraft may go without sending (Section
#: 3.3.3), so that a station is never left without a challenge to answer.
DEFAULT_REPORT_INTERVAL = timedelta(seconds=30)


@dataclass
class Session:
    """One row of the session table."""

    peer: str
    key: bytes
    peer_credential: credentials.Credential
    state: State
    since: datetime

    # --- aircraft side -------------------------------------------------
    #: The challenge carried by the most recent message this aircraft sent.
    #: Exactly one is outstanding at a time; sending retires the one before.
    outstanding: bytes | None = None
    #: The challenge of the last command acted upon, zero until the first.
    last_exec: bytes = primitives.ZERO_CHALLENGE
    #: The station named by a nomination this aircraft elected to act on.
    nominated_successor: str | None = None
    #: When this aircraft last sent, for the Delta t_rep obligation.
    last_sent: datetime | None = None

    # --- ground side ---------------------------------------------------
    #: The command most recently sent, and the challenge it was bound to,
    #: retained so that the station can tell a lost command from an ignored
    #: one when the next report arrives.
    command_in_flight: bytes | None = None
    command_challenge: bytes | None = None

    def is_operational(self) -> bool:
        """Whether operational traffic passes at all."""
        return self.state is not State.PENDING


class SessionTable:
    """
    The per-endpoint table. Indexed by peer, because the pair identifies the
    session and nothing on the wire names it.
    """

    def __init__(self) -> None:
        self._rows: dict[str, Session] = {}

    # -- lookup ---------------------------------------------------------

    def get(self, peer: str) -> Session | None:
        return self._rows.get(peer)

    def require(self, peer: str) -> Session:
        row = self._rows.get(peer)
        if row is None:
            raise Rejected(Step.SESSION_UNKNOWN, peer)
        return row

    def peers(self) -> tuple[str, ...]:
        return tuple(self._rows)

    def drop(self, peer: str) -> None:
        self._rows.pop(peer, None)

    def __len__(self) -> int:
        return len(self._rows)

    # -- lifecycle ------------------------------------------------------

    def open_pending(self, peer: str, key: bytes,
                     peer_credential: credentials.Credential,
                     now: datetime) -> Session:
        """
        Pending: at the station on sending KEYACK, at the aircraft on
        receiving it. Both hold the key; neither passes operational traffic.
        """
        row = Session(peer=peer, key=key, peer_credential=peer_credential,
                      state=State.PENDING, since=now)
        self._rows[peer] = row
        return row

    def establish(self, peer: str, now: datetime) -> Session:
        """
        Established: at the station on verifying KEYCONFIRM, at the aircraft
        on sending it.

        If this aircraft was in handover with some other station, that
        session ends here: "the session with G1 ends when a session with the
        successor reaches established".
        """
        row = self.require(peer)
        row.state = State.ESTABLISHED
        row.since = now
        for other, sess in list(self._rows.items()):
            if other != peer and sess.state is State.HANDOVER:
                del self._rows[other]
        return row

    def expire(self, now: datetime, *,
               pending_timeout: timedelta = DEFAULT_PENDING_TIMEOUT,
               handover_timeout: timedelta = DEFAULT_HANDOVER_TIMEOUT) -> list[tuple[str, str]]:
        """
        Apply the two timeouts. Returns what happened, as (peer, what) pairs,
        so a caller can act on it -- the aircraft owes a CC:SYSTEM
        notification when a handover lapses.

        A pending session whose KEYCONFIRM never arrived is discarded. A
        handover that has run past Delta t_ho is discarded at the station;
        at the aircraft it reverts, because the aircraft still has a peer and
        Section 3.3.4 would rather it had an authenticated one.
        """
        events: list[tuple[str, str]] = []
        for peer, row in list(self._rows.items()):
            age = now - row.since
            if row.state is State.PENDING and age > pending_timeout:
                del self._rows[peer]
                events.append((peer, "pending_discarded"))
            elif row.state is State.HANDOVER and age > handover_timeout:
                del self._rows[peer]
                events.append((peer, "handover_expired"))
        return events

    # -- transfer of control --------------------------------------------

    def begin_handover(self, peer: str, successor: str, now: datetime) -> Session:
        """
        The aircraft on electing to act on a nomination, and the outgoing
        station on sending one. Command authority is relinquished at once.
        """
        row = self.require(peer)
        if row.state is not State.ESTABLISHED:
            raise Rejected(Step.SESSION_STATE,
                           f"cannot hand over from {row.state.value}")
        row.state = State.HANDOVER
        row.since = now
        row.nominated_successor = successor
        return row

    def revert(self, peer: str, now: datetime) -> Session:
        """
        The aircraft when no successor session is established within
        Delta t_ho, or when an attempt fails at any verification step. The
        caller sends the CC:SYSTEM notification that gives the station a
        definite signal to resume authority.
        """
        row = self.require(peer)
        if row.state is not State.HANDOVER:
            raise Rejected(Step.SESSION_STATE,
                           f"cannot revert from {row.state.value}")
        row.state = State.ESTABLISHED
        row.since = now
        row.nominated_successor = None
        return row

    def admits(self, row: Session, role: str) -> bool:
        """Whether the session's state admits a message of this role."""
        if row.state is State.PENDING:
            return False
        if row.state is State.HANDOVER and role in COMMAND_ROLES:
            return False
        return True


# ---------------------------------------------------------------------------
# The challenge exchange (Section 3.3.3), the four rules
# ---------------------------------------------------------------------------

def arm(row: Session, kex_secret: bytes, now: datetime) -> bytes:
    """
    Rule 1: every message the aircraft sends carries a fresh challenge, and
    sending retires the one before. Returns the challenge to carry.
    """
    row.outstanding = primitives.new_challenge(kex_secret)
    row.last_sent = now
    return row.outstanding


def may_act(row: Session, in_reply_to: bytes | None) -> bool:
    """
    Rule 2, the test: a command is acted upon only if it quotes the
    outstanding challenge. A command bound to a retired challenge -- replayed,
    or delivered out of turn -- fails here.
    """
    if row.outstanding is None or in_reply_to is None:
        return False
    return secrets.compare_digest(row.outstanding, in_reply_to)


def record_execution(row: Session) -> bytes:
    """
    Rule 2, the effect: on acting, LAST_EXEC becomes that challenge and the
    challenge is retired. Nothing is outstanding until the aircraft next
    sends, which the acknowledgement does at once.
    """
    if row.outstanding is None:
        raise Rejected(Step.CHALLENGE, "nothing outstanding to execute against")
    row.last_exec = row.outstanding
    row.outstanding = None
    return row.last_exec


def station_should_resend(row: Session, reported_last_exec: bytes) -> bool:
    """
    Rule 3: the station reads LAST_EXEC to learn whether the command it last
    sent was acted upon. If it was not, it re-sends that command bound to the
    newly received challenge; if it was, it may issue the next.

    LAST_EXEC is information for this decision and never a condition on
    accepting the message that carries it, which is what makes the exchange
    tolerant of loss.
    """
    if row.command_in_flight is None or row.command_challenge is None:
        return False
    return not secrets.compare_digest(row.command_challenge, reported_last_exec)


def overdue(row: Session, now: datetime,
            interval: timedelta = DEFAULT_REPORT_INTERVAL) -> bool:
    """
    Rule 4: the aircraft sends at least one message every Delta t_rep, so a
    station is never left without a challenge to answer. True when the
    aircraft owes one.
    """
    reference = row.last_sent or row.since
    return now - reference > interval
