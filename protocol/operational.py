"""
Operational messages and the receipt pipeline (paper, Section 3.3.3).

Three roles travel under the session key, payloads in clear and an Ascon-Mac
tag over the body:

    SA        the aircraft's report: altitude, reference frame, position,
              speed, heading, on-ground
    CC:...    command and control, the subtype qualifying the role
    ACK       the aircraft's confirmation, digesting the body it answers

Every message an aircraft sends in an established session carries LAST_EXEC
and a fresh CHALLENGE. Every CC a ground station sends carries IN_REPLY_TO.

`receive` is the single door. It runs the checks of "On receipt" in the
specified order and raises `Rejected` naming the one that refused:

    1. the message parses, and its ROLE and TO are what they should be
    2. a session exists with the sender
    3. the tag verifies under K_sess
    4. the timestamp lies within Delta t_max of the local clock
    5. a command-bearing message quotes the outstanding challenge
    6. the ROLE lies within the sender's PERMITTED_ROLES, and at a ground
       station the station's own SECTOR covers the airspace the aircraft
       reports
    7. the session's state admits the role

Steps 1 and 2 come before the paper's "verifies the tag" because a receiver
cannot verify a tag before it has parsed the message and found the key. The
order the paper specifies, from the tag onwards, is exactly steps 3 to 7.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from protocol import credentials, encoding, primitives, session as S
from protocol.handshake import DEFAULT_WINDOW, MAC
from protocol.rejection import Rejected, Step

ROLE_SA = "SA"
ROLE_ACK = "ACK"

CC_REQUEST = "CC:REQUEST"
CC_CLEARANCE = "CC:CLEARANCE"
CC_INSTRUCTION = "CC:INSTRUCTION"
CC_CONTACT = "CC:CONTACT"
CC_EMERGENCY = "CC:EMERGENCY"
CC_SYSTEM = "CC:SYSTEM"

#: Vertical reference frames. A report whose ALT_REF is absent or
#: unrecognised is rejected, because the same number denotes materially
#: different vertical positions under different references.
ALT_REFS = frozenset({"BARO_QNH", "BARO_STD", "GEO_WGS84", "GEO_EGM96"})

#: The CC:SYSTEM directive by which an aircraft tells a station that a
#: transfer did not complete (Section 3.3.4). The paper names the message and
#: not the wording; this is the implementation's choice of wording.
TRANSFER_INCOMPLETE = "TRANSFER INCOMPLETE"


@dataclass(frozen=True)
class Received:
    """A message that passed every check."""

    role: str
    sender: str
    fields: list[tuple[str, str]]
    body: bytes
    session: S.Session

    def get(self, name: str) -> str | None:
        return encoding.get(self.fields, name)


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def _finish(row: S.Session, fields: list[tuple[str, str]]) -> bytes:
    body = encoding.encode(fields)
    return body + encoding.encode([(MAC, primitives.b64u(primitives.mac(row.key, body)))])


def build_sa(row: S.Session, kex_secret: bytes, now: datetime, *,
             sender: str, altitude: str, alt_ref: str, position: str,
             speed: str, heading: str, on_ground: str) -> bytes:
    """An aircraft's situational awareness report."""
    if alt_ref not in ALT_REFS:
        raise ValueError(f"unknown ALT_REF: {alt_ref}")
    challenge = S.arm(row, kex_secret, now)
    return _finish(row, [
        ("ROLE", ROLE_SA),
        ("TIMESTAMP", credentials._iso(now)),
        ("FROM", sender),
        ("TO", row.peer),
        ("ALTITUDE", altitude),
        ("ALT_REF", alt_ref),
        ("POSITION", position),
        ("SPEED", speed),
        ("HEADING", heading),
        ("ON_GROUND", on_ground),
        ("LAST_EXEC", primitives.b64u(row.last_exec)),
        ("CHALLENGE", primitives.b64u(challenge)),
    ])


def build_command(row: S.Session, now: datetime, *, sender: str, role: str,
                  instruction: str, in_reply_to: bytes) -> bytes:
    """
    A ground station's CC message, bound to the challenge it answers.

    The station retains it: if the next report shows it was not acted upon,
    the same instruction goes out again bound to the newer challenge.
    """
    wire = _finish(row, [
        ("ROLE", role),
        ("TIMESTAMP", credentials._iso(now)),
        ("FROM", sender),
        ("TO", row.peer),
        ("INSTRUCTION", instruction),
        ("IN_REPLY_TO", primitives.b64u(in_reply_to)),
    ])
    if role in S.COMMAND_ROLES:
        row.command_in_flight = wire
        row.command_challenge = in_reply_to
    return wire


def build_aircraft_cc(row: S.Session, kex_secret: bytes, now: datetime, *,
                      sender: str, role: str, instruction: str) -> bytes:
    """
    A CC an aircraft originates: CC:REQUEST, CC:EMERGENCY, or the CC:SYSTEM
    notification that a transfer did not complete. It carries a challenge
    like any aircraft message, and no IN_REPLY_TO, having nothing to answer.
    """
    challenge = S.arm(row, kex_secret, now)
    return _finish(row, [
        ("ROLE", role),
        ("TIMESTAMP", credentials._iso(now)),
        ("FROM", sender),
        ("TO", row.peer),
        ("INSTRUCTION", instruction),
        ("LAST_EXEC", primitives.b64u(row.last_exec)),
        ("CHALLENGE", primitives.b64u(challenge)),
    ])


def build_ack(row: S.Session, kex_secret: bytes, now: datetime, *,
              sender: str, acknowledged_body: bytes, response: str) -> bytes:
    """
    The aircraft's acknowledgement, digesting the body it answers so that the
    reference is unambiguous when several are outstanding.

    Because it is a message the aircraft sends it carries the next challenge,
    so an acknowledged command re-arms the exchange at once rather than at the
    next report.
    """
    challenge = S.arm(row, kex_secret, now)
    return _finish(row, [
        ("ROLE", ROLE_ACK),
        ("TIMESTAMP", credentials._iso(now)),
        ("FROM", sender),
        ("TO", row.peer),
        ("ACK_HASH", primitives.b64u(primitives.ack_hash(acknowledged_body))),
        ("RESPONSE", response),
        ("LAST_EXEC", primitives.b64u(row.last_exec)),
        ("CHALLENGE", primitives.b64u(challenge)),
    ])


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------

def receive(raw: bytes, table: S.SessionTable, now: datetime, *,
            local: str, as_aircraft: bool,
            window: timedelta = DEFAULT_WINDOW,
            local_sector: str | None = None,
            airspace: str | None = None,
            sector_covers=None) -> Received:
    """
    Verify an operational message and return it, or raise `Rejected`.

    `as_aircraft` selects the two asymmetric checks: only an aircraft gates
    command-bearing messages on its outstanding challenge, and only a ground
    station enforces sector.

    Sector enforcement is ground-side and concerns the station's *own*
    entitlement: `local_sector` is what this station's credential authorises
    it to control, `airspace` is where the aircraft reports being. An
    aircraft's credential carries no SECTOR, so there is nothing of the
    sender's to check here. Mapping a reported position to an airspace needs
    boundary data, so the caller does it and passes the result
    (Section 5.3, "Sector enforcement").
    """
    # 1. structure
    try:
        fields = encoding.parse(raw)
        role = encoding.require(fields, "ROLE")
        sender = encoding.require(fields, "FROM")
        to = encoding.require(fields, "TO")
        ts = encoding.require(fields, "TIMESTAMP")
    except encoding.EncodingError as exc:
        raise Rejected(Step.MALFORMED, str(exc)) from exc

    if role not in _KNOWN_ROLES:
        raise Rejected(Step.ROLE_UNKNOWN, role)
    if to != local:
        raise Rejected(Step.ADDRESSEE, f"addressed to {to}, not {local}")

    # 2. a session with this sender
    row = table.require(sender)

    # 3. the tag, under that session's key
    try:
        body = encoding.authenticated_region(raw, MAC)
        tag = primitives.unb64u(encoding.require(fields, MAC))
    except Exception as exc:
        raise Rejected(Step.MALFORMED, str(exc)) from exc
    if not primitives.verify_mac(row.key, body, tag):
        raise Rejected(Step.TAG, role)

    # 4. the acceptance window
    try:
        sent = credentials._parse_iso(ts)
    except Exception as exc:
        raise Rejected(Step.MALFORMED, f"bad timestamp: {ts}") from exc
    if abs(now - sent) > window:
        raise Rejected(Step.TIMESTAMP_WINDOW, ts)

    # 5. the challenge, for a command the aircraft would act upon
    if as_aircraft and role in S.COMMAND_ROLES:
        quoted = encoding.get(fields, "IN_REPLY_TO")
        try:
            value = primitives.unb64u(quoted) if quoted else None
        except ValueError:
            value = None
        if not S.may_act(row, value):
            raise Rejected(Step.CHALLENGE,
                           "IN_REPLY_TO does not match the outstanding challenge")

    # 6. scope: what the sender's credential permits, and where
    if not row.peer_credential.permits(role):
        raise Rejected(Step.ROLE_NOT_PERMITTED,
                       f"{sender} may not send {role}")
    if not as_aircraft and airspace is not None and local_sector is not None:
        covers = sector_covers or credentials.default_sector_covers
        if not covers(local_sector, airspace):
            raise Rejected(
                Step.SECTOR,
                f"this station's sector {local_sector} does not cover {airspace}")

    # 7. and the state of the session
    if not table.admits(row, role):
        raise Rejected(Step.SESSION_STATE,
                       f"{role} not admitted while {row.state.value}")

    # An SA is only a report if its reference frame is one we know.
    if role == ROLE_SA:
        alt_ref = encoding.get(fields, "ALT_REF")
        if alt_ref not in ALT_REFS:
            raise Rejected(Step.ALT_REF, str(alt_ref))

    return Received(role=role, sender=sender, fields=fields, body=body, session=row)


_KNOWN_ROLES = frozenset({
    ROLE_SA, ROLE_ACK, CC_REQUEST, CC_CLEARANCE, CC_INSTRUCTION,
    CC_CONTACT, CC_EMERGENCY, CC_SYSTEM,
})


def last_exec_of(msg: Received) -> bytes | None:
    """The LAST_EXEC an aircraft message reports, for rule 3."""
    value = msg.get("LAST_EXEC")
    if value is None:
        return None
    try:
        return primitives.unb64u(value)
    except ValueError:
        return None
