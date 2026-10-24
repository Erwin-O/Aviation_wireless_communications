"""
The one vocabulary for refusing a message.

The paper's claim about the implementation is that each rejection test asserts
"not only that the input is refused but that it is refused at the intended
step" (contribution C4). That is only testable if every check in the protocol
names itself, so every refusal anywhere in this package raises `Rejected` with
a `Step`.

The steps are listed in the order a message meets them.
"""

from __future__ import annotations

import enum


class Step(enum.Enum):
    """The check that refused a message."""

    # Structure, before anything is believed
    MALFORMED = "malformed"
    ROLE_UNKNOWN = "role_unknown"
    ADDRESSEE = "addressee"
    TIMESTAMP_WINDOW = "timestamp_window"

    # Credential, in the order of Section 3.3.2
    CREDENTIAL_MALFORMED = "credential_malformed"
    ISSUER_UNKNOWN = "issuer_unknown"
    ISSUER_SIGNATURE = "issuer_signature"
    VALIDITY = "validity"
    SUBJECT = "subject"
    SECTOR = "sector"
    MESSAGE_SIGNATURE = "message_signature"

    # Handshake, on the airspace a ground station claims to be working.
    # SECTOR above is the unconditional check that the claim lies within the
    # issuer's grant; AIRSPACE is the advisory one, made only by an aircraft
    # that holds current published airspace data, that the claim contains
    # where the aircraft actually is (Section 5.3).
    AIRSPACE = "airspace"

    # Handshake
    TRANSCRIPT = "transcript"

    # Operational, under the session key
    SESSION_UNKNOWN = "session_unknown"
    TAG = "tag"
    CHALLENGE = "challenge"
    ROLE_NOT_PERMITTED = "role_not_permitted"
    SESSION_STATE = "session_state"
    ALT_REF = "alt_ref"


class Rejected(Exception):
    """
    Raised wherever a message is discarded, naming the step that discarded it.

    A message refused for the wrong reason demonstrates nothing about the
    check under test, so the step is part of the contract and not a debugging
    aid.
    """

    def __init__(self, step: Step, detail: str = "") -> None:
        super().__init__(f"{step.value}: {detail}" if detail else step.value)
        self.step = step
        self.detail = detail
