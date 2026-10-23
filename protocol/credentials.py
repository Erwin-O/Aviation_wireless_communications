"""
Credentials and the verification order (paper, Section 3.3.2).

A credential is a labelled record in the encoding of `protocol.encoding`,
signed by its issuer, carried inside a message field as Base64. A receiver
holds issuer keys -- trust anchors -- and not a directory of principals, which
is what lets it verify a party it has never heard of.

The verification order is specified and is not an implementation detail:

    1. the issuer signature on the credential, against a key the receiver holds
    2. the validity interval, against the receiver's clock
    3. the subject identity, against the message's FROM field
    4. the sector scope, against the airspace at issue
    5. and only then the message signature, against the credential's VERIFY_KEY

"Failure at any step discards the message. This order is what makes the trust
model work, and it is the point at which an implementation is most likely to
err." So each failure raises `CredentialRejected` carrying the step at which
it occurred, and the test suite asserts the step and not merely the rejection.

OPEN SPEC POINTS, both flagged rather than quietly settled:

  * PERMITTED_ROLES is a list and the paper does not give its separator or
    whether a bare family permits its subtypes. This module uses commas, and
    requires an exact match: a credential must list CC:CLEARANCE to permit a
    clearance, and listing CC permits nothing. The conservative reading,
    since CC:CONTACT is what nominates a successor station.
  * "the SECTOR of the credential must cover the airspace the aircraft
    reports" leaves covering to the deployment. `sector_covers` is the hook;
    the default is exact match or a dotted-prefix containment.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime, timezone

from protocol import encoding, primitives

ISSUER_SIG = "ISSUER_SIG"

#: Field order within a credential record. Order is significant: it is part of
#: what the issuer signs.
FIELDS = (
    "ISSUER",
    "SUBJECT",
    "VERIFY_KEY",
    "NOT_BEFORE",
    "NOT_AFTER",
    "PERMITTED_ROLES",
    "SECTOR",  # ground stations only
)


class Step(enum.Enum):
    """The step of the verification order at which a message was discarded."""

    CREDENTIAL_MALFORMED = "credential_malformed"
    ISSUER_UNKNOWN = "issuer_unknown"
    ISSUER_SIGNATURE = "issuer_signature"
    VALIDITY = "validity"
    SUBJECT = "subject"
    SECTOR = "sector"
    MESSAGE_SIGNATURE = "message_signature"


class CredentialRejected(Exception):
    """Raised when verification fails, carrying the step that failed."""

    def __init__(self, step: Step, detail: str = "") -> None:
        super().__init__(f"{step.value}: {detail}" if detail else step.value)
        self.step = step
        self.detail = detail


@dataclass(frozen=True)
class Credential:
    """A parsed credential. `raw` is the bytes as received, never re-encoded."""

    issuer: str
    subject: str
    verify_key: bytes
    not_before: datetime
    not_after: datetime
    permitted_roles: tuple[str, ...]
    sector: str | None
    raw: bytes

    def permits(self, role: str) -> bool:
        """Whether this credential permits a message of the given ROLE."""
        return role in self.permitted_roles


# ---------------------------------------------------------------------------
# Issuing
# ---------------------------------------------------------------------------

def issue(
    issuer: str,
    subject: str,
    verify_key: bytes,
    not_before: datetime,
    not_after: datetime,
    permitted_roles: tuple[str, ...] | list[str],
    issuer_signing_key: bytes,
    sector: str | None = None,
) -> bytes:
    """Build and sign a credential record. Returns the record bytes."""
    if not_after <= not_before:
        raise ValueError("NOT_AFTER must be later than NOT_BEFORE")
    if not permitted_roles:
        raise ValueError("a credential with no permitted roles permits nothing")

    fields = [
        ("ISSUER", issuer),
        ("SUBJECT", subject),
        ("VERIFY_KEY", primitives.b64u(verify_key)),
        ("NOT_BEFORE", _iso(not_before)),
        ("NOT_AFTER", _iso(not_after)),
        ("PERMITTED_ROLES", ",".join(permitted_roles)),
    ]
    if sector is not None:
        fields.append(("SECTOR", sector))

    body = encoding.encode(fields)
    sig = primitives.sign(issuer_signing_key, body)
    return body + encoding.encode([(ISSUER_SIG, primitives.b64u(sig))])


# ---------------------------------------------------------------------------
# Parsing and the verification order
# ---------------------------------------------------------------------------

def parse(raw: bytes) -> Credential:
    """Parse a credential record. Raises CredentialRejected at step 0."""
    try:
        fields = encoding.parse(raw)
        issuer = encoding.require(fields, "ISSUER")
        subject = encoding.require(fields, "SUBJECT")
        verify_key = primitives.unb64u(encoding.require(fields, "VERIFY_KEY"))
        not_before = _parse_iso(encoding.require(fields, "NOT_BEFORE"))
        not_after = _parse_iso(encoding.require(fields, "NOT_AFTER"))
        roles = tuple(
            r for r in encoding.require(fields, "PERMITTED_ROLES").split(",") if r
        )
        sector = encoding.get(fields, "SECTOR")
        encoding.require(fields, ISSUER_SIG)
    except Exception as exc:
        raise CredentialRejected(Step.CREDENTIAL_MALFORMED, str(exc)) from exc

    if len(verify_key) != 32:
        raise CredentialRejected(Step.CREDENTIAL_MALFORMED, "VERIFY_KEY is not 32 bytes")
    if not roles:
        raise CredentialRejected(Step.CREDENTIAL_MALFORMED, "no permitted roles")

    return Credential(
        issuer=issuer,
        subject=subject,
        verify_key=verify_key,
        not_before=not_before,
        not_after=not_after,
        permitted_roles=roles,
        sector=sector,
        raw=raw,
    )


def verify(
    raw: bytes,
    *,
    trust_anchors: dict[str, bytes],
    now: datetime,
    expect_subject: str,
    airspace: str | None = None,
    signed_message: bytes | None = None,
    message_signature: bytes | None = None,
    sector_covers=None,
) -> Credential:
    """
    Run the verification order of Section 3.3.2 and return the credential.

    Steps 1 to 4 always run. Step 5, the message signature, runs when
    `signed_message` and `message_signature` are given, which is the case for
    KEY and KEYACK. The sector check (step 4) runs when `airspace` is given,
    which is the case at a ground station.

    Raises CredentialRejected, whose `.step` names the step that failed.
    """
    cred = parse(raw)

    # 1. issuer signature against a trust anchor
    anchor = trust_anchors.get(cred.issuer)
    if anchor is None:
        raise CredentialRejected(Step.ISSUER_UNKNOWN, cred.issuer)
    try:
        signed_region = encoding.authenticated_region(raw, ISSUER_SIG)
        sig = primitives.unb64u(
            encoding.require(encoding.parse(raw), ISSUER_SIG)
        )
    except Exception as exc:
        raise CredentialRejected(Step.CREDENTIAL_MALFORMED, str(exc)) from exc
    if not primitives.verify_signature(anchor, signed_region, sig):
        raise CredentialRejected(Step.ISSUER_SIGNATURE, cred.issuer)

    # 2. validity interval against the receiver's clock
    if now < cred.not_before:
        raise CredentialRejected(Step.VALIDITY, "not yet valid")
    if now > cred.not_after:
        raise CredentialRejected(Step.VALIDITY, "expired")

    # 3. subject identity against the FROM field
    if cred.subject != expect_subject:
        raise CredentialRejected(
            Step.SUBJECT, f"credential names {cred.subject}, message says {expect_subject}"
        )

    # 4. sector scope against the airspace at issue
    if airspace is not None:
        covers = sector_covers or default_sector_covers
        if cred.sector is None or not covers(cred.sector, airspace):
            raise CredentialRejected(
                Step.SECTOR, f"credential sector {cred.sector!r} does not cover {airspace!r}"
            )

    # 5. and only then the message signature, under the credential's key
    if signed_message is not None or message_signature is not None:
        if signed_message is None or message_signature is None:
            raise ValueError("both signed_message and message_signature are required")
        if not primitives.verify_signature(
            cred.verify_key, signed_message, message_signature
        ):
            raise CredentialRejected(Step.MESSAGE_SIGNATURE, cred.subject)

    return cred


def default_sector_covers(credential_sector: str, airspace: str) -> bool:
    """
    Whether a credential's SECTOR covers the airspace at issue.

    Exact match, or dotted-prefix containment so that an issuer can delegate a
    region and its subdivisions: "EBBU" covers "EBBU.NORTH". Deployments with
    real airspace boundaries pass their own function to `verify`.
    """
    if credential_sector == airspace:
        return True
    return airspace.startswith(credential_sector + ".")


# ---------------------------------------------------------------------------
# Timestamps: ISO 8601 with an explicit offset (Section 3.3.1)
# ---------------------------------------------------------------------------

def _iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        raise ValueError("timestamps must carry an explicit offset")
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _parse_iso(text: str) -> datetime:
    ts = datetime.fromisoformat(text)
    if ts.tzinfo is None:
        raise ValueError(f"timestamp without an offset: {text}")
    return ts
