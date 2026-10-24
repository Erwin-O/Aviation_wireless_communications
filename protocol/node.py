"""
Endpoint behaviour, independent of any transport (paper, Section 3.3).

Two nodes, each wrapping the pieces below it: identity and credential,
a session table, and whatever handshakes are in flight. Neither knows what
carries its bytes. A transport calls `handle(raw)` with what arrived and
sends whatever comes back.

    Aircraft   starts sessions, reports, acts on commands, acknowledges,
               and decides for itself whether to follow a nomination.
    Station    answers handshakes, verifies everything, issues commands
               bound to the challenge it is answering, and resends when a
               report shows its last command was not acted upon.

Every method returns the messages to send, as a list, so a caller never has
to guess whether something is owed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from protocol import encoding, handshake as H, identity as I
from protocol import operational as O, primitives, session as S
from protocol.rejection import Rejected, Step


@dataclass
class Outbound:
    """A message and where it goes."""

    to: str
    role: str
    raw: bytes


def _role_of(raw: bytes) -> str:
    return encoding.get(encoding.parse(raw), "ROLE") or "?"


# ---------------------------------------------------------------------------
# Aircraft
# ---------------------------------------------------------------------------

@dataclass
class Aircraft:
    identity: I.Identity
    trust_anchors: dict[str, bytes]
    window: timedelta = H.DEFAULT_WINDOW
    handover_timeout: timedelta = S.DEFAULT_HANDOVER_TIMEOUT

    table: S.SessionTable = field(default_factory=S.SessionTable)
    #: Handshakes in flight, by station.
    _starting: dict[str, H.Initiator] = field(default_factory=dict)
    #: The station a nomination named, while we try to reach it.
    _expected: dict[str, str] = field(default_factory=dict)
    #: Bodies of commands awaiting acknowledgement, by station.
    _to_ack: dict[str, bytes] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.identity.name

    # -- starting a session ---------------------------------------------

    def connect(self, station: str, now: datetime,
                expected: str | None = None) -> list[Outbound]:
        """
        Begin a session. `expected` is the station a nomination named, when
        this attempt follows one: the credential that comes back must name
        it, so a party interposing itself is refused even if its own
        credential is valid (Section 3.3.4).
        """
        init = H.Initiator(window=self.window,
                           **self.identity.endpoint_kwargs(self.trust_anchors))
        self._starting[station] = init
        if expected:
            self._expected[station] = expected
        return [Outbound(station, H.ROLE_KEY, init.build_key(station, now))]

    # -- receiving ------------------------------------------------------

    def handle(self, raw: bytes, now: datetime,
               airspace: str | None = None) -> list[Outbound]:
        """Process one message and return whatever it obliges us to send."""
        role = _role_of(raw)
        sender = encoding.get(encoding.parse(raw), "FROM") or ""

        if role == H.ROLE_KEYACK:
            return self._keyack(raw, sender, now, airspace)

        msg = O.receive(raw, self.table, now, local=self.name,
                        as_aircraft=True, window=self.window)
        if msg.role == O.CC_CONTACT:
            return self._nomination(msg, now)
        if msg.role in S.COMMAND_ROLES:
            return self._command(msg, now)
        return []

    def _keyack(self, raw: bytes, sender: str, now: datetime,
                airspace: str | None) -> list[Outbound]:
        init = self._starting.get(sender)
        if init is None:
            # An answer from someone we did not address. If we are waiting on
            # a handshake at all, this is a party interposing itself: refuse
            # it by subject, which is the check Section 3.3.4 specifies, and
            # not merely because we have no row under its name.
            if self._starting:
                addressed = ", ".join(sorted(self._starting))
                raise Rejected(Step.SUBJECT,
                               f"KEY was sent to {addressed}; {sender} answered")
            raise Rejected(Step.SESSION_UNKNOWN,
                           f"no handshake in flight with {sender}")

        try:
            init.handle_keyack(raw, now, airspace=airspace)
            wire, sess = init.build_keyconfirm(now)
        except Rejected:
            # "or an attempt fails at any verification step": give up on this
            # successor and go back to the incumbent.
            self._starting.pop(sender, None)
            self._expected.pop(sender, None)
            raise

        self._starting.pop(sender, None)
        self._expected.pop(sender, None)
        self.table.open_pending(sender, sess.key, sess.peer_credential, now)
        # The aircraft is established on *sending* KEYCONFIRM, which also
        # ends any session it was handing over.
        self.table.establish(sender, now)
        return [Outbound(sender, H.ROLE_KEYCONFIRM, wire)]

    def _nomination(self, msg: O.Received, now: datetime) -> list[Outbound]:
        """
        A nomination is not an instruction. Which station we talk to next is
        our decision; here we take the nomination, which is the ordinary case.
        """
        successor = msg.get("INSTRUCTION") or ""
        S.record_execution(msg.session)
        out = [self._ack(msg, now, "WILCO")]
        self.table.begin_handover(msg.sender, successor, now)
        out += self.connect(successor, now, expected=successor)
        return out

    def _command(self, msg: O.Received, now: datetime) -> list[Outbound]:
        S.record_execution(msg.session)
        self._to_ack[msg.sender] = msg.body
        return [self._ack(msg, now, "WILCO")]

    def _ack(self, msg: O.Received, now: datetime, response: str) -> Outbound:
        wire = O.build_ack(msg.session, self.identity.kex_secret, now,
                           sender=self.name, acknowledged_body=msg.body,
                           response=response)
        return Outbound(msg.sender, O.ROLE_ACK, wire)

    # -- sending --------------------------------------------------------

    def report(self, now: datetime, **state) -> list[Outbound]:
        """A report to every station we have an operational session with."""
        out = []
        for peer in self.table.peers():
            row = self.table.get(peer)
            if row is None or not row.is_operational():
                continue
            out.append(Outbound(peer, O.ROLE_SA,
                                O.build_sa(row, self.identity.kex_secret, now,
                                           sender=self.name, **state)))
        return out

    def tick(self, now: datetime) -> list[Outbound]:
        """
        Housekeeping: a handover that has run past Delta t_ho reverts, and the
        station is told so that it resumes authority at once rather than
        waiting out its own timer (Section 3.3.4).
        """
        out = []
        for peer in self.table.peers():
            row = self.table.get(peer)
            if row is None or row.state is not S.State.HANDOVER:
                continue
            if now - row.since <= self.handover_timeout:
                continue
            successor = row.nominated_successor
            self._starting.pop(successor, None)
            self._expected.pop(successor, None)
            self.table.revert(peer, now)
            out.append(Outbound(peer, O.CC_SYSTEM, O.build_aircraft_cc(
                row, self.identity.kex_secret, now, sender=self.name,
                role=O.CC_SYSTEM, instruction=O.TRANSFER_INCOMPLETE)))
        return out


# ---------------------------------------------------------------------------
# Ground station
# ---------------------------------------------------------------------------

@dataclass
class Station:
    identity: I.Identity
    trust_anchors: dict[str, bytes]
    sector: str | None = None
    window: timedelta = H.DEFAULT_WINDOW

    table: S.SessionTable = field(default_factory=S.SessionTable)
    _answering: dict[str, H.Responder] = field(default_factory=dict)
    #: The latest challenge each aircraft has outstanding, so a command can be
    #: bound to it.
    _challenge: dict[str, bytes] = field(default_factory=dict)
    #: Instructions queued for an aircraft, issued one at a time.
    _queue: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.identity.name

    def enqueue(self, aircraft: str, role: str, instruction: str) -> None:
        """Queue an instruction; it goes out when a challenge is available."""
        self._queue.setdefault(aircraft, []).append((role, instruction))

    # -- receiving ------------------------------------------------------

    def handle(self, raw: bytes, now: datetime,
               airspace: str | None = None) -> list[Outbound]:
        role = _role_of(raw)
        sender = encoding.get(encoding.parse(raw), "FROM") or ""

        if role == H.ROLE_KEY:
            return self._key(raw, sender, now)
        if role == H.ROLE_KEYCONFIRM:
            return self._keyconfirm(raw, sender, now)

        msg = O.receive(raw, self.table, now, local=self.name,
                        as_aircraft=False, window=self.window,
                        local_sector=self.sector, airspace=airspace)
        return self._operational(msg, now)

    def _key(self, raw: bytes, sender: str, now: datetime) -> list[Outbound]:
        # `sector` is the airspace this station works: claimed in KEYACK, and
        # the same quantity against which a reported position is admitted.
        resp = H.Responder(window=self.window, airspace=self.sector,
                           **self.identity.endpoint_kwargs(self.trust_anchors))
        resp.handle_key(raw, now)
        wire = resp.build_keyack(now)
        self._answering[resp._peer] = resp
        # Pending from the moment KEYACK is sent; no operational traffic yet.
        self.table.open_pending(resp._peer, resp._key, resp._peer_credential, now)
        return [Outbound(resp._peer, H.ROLE_KEYACK, wire)]

    def _keyconfirm(self, raw: bytes, sender: str, now: datetime) -> list[Outbound]:
        resp = self._answering.get(sender)
        if resp is None:
            raise Rejected(Step.SESSION_UNKNOWN, f"no pending session with {sender}")
        resp.handle_keyconfirm(raw, now)
        self._answering.pop(sender, None)
        self.table.establish(sender, now)
        return []

    def _operational(self, msg: O.Received, now: datetime) -> list[Outbound]:
        """
        Read LAST_EXEC and the challenge, then decide: resend what was not
        acted upon, or issue the next thing.
        """
        challenge = msg.get("CHALLENGE")
        if challenge:
            try:
                self._challenge[msg.sender] = primitives.unb64u(challenge)
            except ValueError:
                pass

        row = msg.session
        reported = O.last_exec_of(msg)
        if reported is not None and S.station_should_resend(row, reported):
            return self._resend(row, now)

        row.command_in_flight = None
        row.command_challenge = None
        return self._next(row, now)

    def _resend(self, row: S.Session, now: datetime) -> list[Outbound]:
        """
        The command was not acted upon, so it goes again bound to the newly
        received challenge. No timer: the reporting interval is the retry
        interval.
        """
        previous = row.command_in_flight
        if previous is None:
            return []
        fields = encoding.parse(previous)
        role = encoding.get(fields, "ROLE") or O.CC_INSTRUCTION
        instruction = encoding.get(fields, "INSTRUCTION") or ""
        return self._issue(row, role, instruction, now)

    def _next(self, row: S.Session, now: datetime) -> list[Outbound]:
        queue = self._queue.get(row.peer) or []
        if not queue:
            return []
        role, instruction = queue.pop(0)
        return self._issue(row, role, instruction, now)

    def _issue(self, row: S.Session, role: str, instruction: str,
               now: datetime) -> list[Outbound]:
        challenge = self._challenge.get(row.peer)
        if challenge is None:
            return []
        if not self.table.admits(row, role):
            return []
        wire = O.build_command(row, now, sender=self.name, role=role,
                               instruction=instruction, in_reply_to=challenge)
        return [Outbound(row.peer, role, wire)]

    # -- sending --------------------------------------------------------

    def nominate(self, aircraft: str, successor: str, now: datetime) -> list[Outbound]:
        """
        Relinquish authority by naming a successor. The station moves its own
        session to handover on transmission.
        """
        row = self.table.get(aircraft)
        if row is None or row.state is not S.State.ESTABLISHED:
            return []
        out = self._issue(row, O.CC_CONTACT, successor, now)
        if out:
            self.table.begin_handover(aircraft, successor, now)
        return out

    def tick(self, now: datetime) -> list[Outbound]:
        """Apply the pending and handover timeouts."""
        self.table.expire(now, handover_timeout=S.DEFAULT_HANDOVER_TIMEOUT)
        return []
