"""
The three-message session establishment (paper, Section 3.3.2).

    aircraft  -- KEY -------->  ground station     credential + ephemeral, signed
    aircraft  <-- KEYACK -----  ground station     credential + ephemeral, signed
    aircraft  -- KEYCONFIRM ->  ground station     transcript, tagged under K_sess

Two messages would suffice to agree a key. The third exists to confirm it, and
because the transcript covers both preceding bodies the parties agree on the
whole exchange rather than merely on the key.

This module carries no session state beyond one handshake in flight. What the
endpoints retain afterwards -- pending, established, handover -- belongs to
Section 3.3.4 and to `protocol.session`.

Each message is built once and sent as built; each received message is
verified against the bytes that arrived, never against a re-encoding.

ONE REFINEMENT ON THE PAPER'S ORDER, flagged rather than assumed: the
acceptance-window check on TIMESTAMP runs before the credential order of
Section 3.3.2, so a message outside the window costs a receiver no signature
verification. The relative order the paper specifies -- issuer signature,
validity, subject, sector, message signature -- is preserved within it. A
clause in Section 3.3.2 saying so would close the gap between the text and
any conforming implementation.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from protocol import credentials, encoding, primitives
from protocol.rejection import Rejected, Step

ROLE_KEY = "KEY"
ROLE_KEYACK = "KEYACK"
ROLE_KEYCONFIRM = "KEYCONFIRM"
HANDSHAKE_ROLES = (ROLE_KEY, ROLE_KEYACK, ROLE_KEYCONFIRM)

SIGNATURE = "SIGNATURE"
MAC = "MAC"

#: Acceptance window, Delta t_max (Section 3.3.1).
#:
#: OPEN POINT: the paper names Delta t_max and gives no value. Two minutes is
#: wide enough for an ordinary oscillator over a flight and narrow enough to
#: be worth having. Whatever the paper settles on belongs here.
DEFAULT_WINDOW = timedelta(seconds=120)


@dataclass(frozen=True)
class Session:
    """What a completed handshake yields."""

    local: str
    peer: str
    peer_credential: credentials.Credential
    key: bytes
    transcript: bytes


# ---------------------------------------------------------------------------
# Shared checks
# ---------------------------------------------------------------------------

def _common(raw: bytes, *, expect_role: str, expect_to: str, now: datetime,
            window: timedelta) -> list[tuple[str, str]]:
    """Structure, role, addressee and acceptance window, in that order."""
    try:
        fields = encoding.parse(raw)
    except encoding.EncodingError as exc:
        raise Rejected(Step.MALFORMED, str(exc)) from exc

    try:
        role = encoding.require(fields, "ROLE")
        ts = encoding.require(fields, "TIMESTAMP")
        encoding.require(fields, "FROM")
        to = encoding.require(fields, "TO")
    except encoding.EncodingError as exc:
        raise Rejected(Step.MALFORMED, str(exc)) from exc

    if role != expect_role:
        raise Rejected(Step.ROLE_UNKNOWN, f"expected {expect_role}, got {role}")
    if to != expect_to:
        raise Rejected(Step.ADDRESSEE, f"addressed to {to}, not {expect_to}")

    try:
        sent = credentials._parse_iso(ts)
    except Exception as exc:
        raise Rejected(Step.MALFORMED, f"bad timestamp: {ts}") from exc
    if abs(now - sent) > window:
        raise Rejected(Step.TIMESTAMP_WINDOW, f"{sent.isoformat()} against {now.isoformat()}")

    return fields


def _signed_body(raw: bytes, fields) -> tuple[bytes, bytes]:
    """The region the signature covers, and the signature itself."""
    try:
        region = encoding.authenticated_region(raw, SIGNATURE)
        sig = primitives.unb64u(encoding.require(fields, SIGNATURE))
    except Exception as exc:
        raise Rejected(Step.MALFORMED, str(exc)) from exc
    return region, sig


def _credential_of(fields) -> bytes:
    try:
        return primitives.unb64u(encoding.require(fields, "CREDENTIAL"))
    except Exception as exc:
        raise Rejected(Step.CREDENTIAL_MALFORMED, str(exc)) from exc


def _ephemeral_of(fields) -> bytes:
    try:
        pk = primitives.unb64u(encoding.require(fields, "EPHEMERAL_KEY"))
    except Exception as exc:
        raise Rejected(Step.MALFORMED, str(exc)) from exc
    if len(pk) != 32:
        raise Rejected(Step.MALFORMED, "EPHEMERAL_KEY is not 32 bytes")
    return pk


def _iso(ts: datetime) -> str:
    return credentials._iso(ts)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    """
    Common state: who we are, what we can show for it, and what we sign with.

    `kex_secret` is the long-term key-exchange secret of equation (1). Only its
    private half is ever used, so it appears in no credential.
    """

    identity: str
    credential: bytes
    signing_key: bytes
    kex_secret: bytes
    trust_anchors: dict[str, bytes]
    window: timedelta = DEFAULT_WINDOW

    _scalar: bytes | None = field(default=None, repr=False)

    def _fresh_ephemeral(self) -> bytes:
        """Equation (1). Returns the public value; keeps the scalar."""
        self._scalar = primitives.derive_ephemeral_scalar(
            primitives.random_r(), self.kex_secret
        )
        return primitives.public_from_scalar(self._scalar)

    def _agree(self, peer_public: bytes) -> bytes:
        """Equations (2) and (3), then discard the scalar."""
        if self._scalar is None:
            raise Rejected(Step.MALFORMED, "no ephemeral scalar in flight")
        key = primitives.session_key(primitives.dh(self._scalar, peer_public))
        self._scalar = None  # discarded once K_sess is derived (Section 3.3.2)
        return key


@dataclass
class Initiator(Endpoint):
    """The aircraft side."""

    _m_key: bytes | None = field(default=None, repr=False)
    _m_keyack: bytes | None = field(default=None, repr=False)
    _peer: str | None = field(default=None, repr=False)
    _key: bytes | None = field(default=None, repr=False)
    _peer_credential: credentials.Credential | None = field(default=None, repr=False)

    def build_key(self, to: str, now: datetime) -> bytes:
        """KEY: credential and ephemeral public value, signed."""
        self._peer = to
        body = encoding.encode([
            ("ROLE", ROLE_KEY),
            ("TIMESTAMP", _iso(now)),
            ("FROM", self.identity),
            ("TO", to),
            ("CREDENTIAL", primitives.b64u(self.credential)),
            ("EPHEMERAL_KEY", primitives.b64u(self._fresh_ephemeral())),
        ])
        self._m_key = body
        sig = primitives.sign(self.signing_key, body)
        return body + encoding.encode([(SIGNATURE, primitives.b64u(sig))])

    def handle_keyack(self, raw: bytes, now: datetime,
                      airspace: str | None = None) -> None:
        """
        Verify KEYACK and derive the session key.

        `airspace` is optional: an aircraft may compare the station's sector
        against its own position where it holds the means, but admission does
        not depend on it (Section 3.3.3).
        """
        fields = _common(raw, expect_role=ROLE_KEYACK, expect_to=self.identity,
                         now=now, window=self.window)
        region, sig = _signed_body(raw, fields)
        cred = credentials.verify(
            _credential_of(fields),
            trust_anchors=self.trust_anchors,
            now=now,
            expect_subject=encoding.require(fields, "FROM"),
            airspace=airspace,
            signed_message=region,
            message_signature=sig,
        )
        self._peer = cred.subject
        self._peer_credential = cred
        self._key = self._agree(_ephemeral_of(fields))
        self._m_keyack = region

    def build_keyconfirm(self, now: datetime) -> tuple[bytes, Session]:
        """KEYCONFIRM: the transcript of equation (5), tagged under K_sess."""
        if self._key is None or self._m_key is None:
            raise Rejected(Step.MALFORMED, "no key agreed")
        h = primitives.transcript_hash(self._m_key, self._m_keyack)
        body = encoding.encode([
            ("ROLE", ROLE_KEYCONFIRM),
            ("TIMESTAMP", _iso(now)),
            ("FROM", self.identity),
            ("TO", self._peer),
            ("TRANSCRIPT", primitives.b64u(h)),
        ])
        tag = primitives.mac(self._key, body)
        wire = body + encoding.encode([(MAC, primitives.b64u(tag))])
        session = Session(
            local=self.identity,
            peer=self._peer,
            peer_credential=self._peer_credential,
            key=self._key,
            transcript=h,
        )
        return wire, session


@dataclass
class Responder(Endpoint):
    """The ground station side."""

    _m_key: bytes | None = field(default=None, repr=False)
    _m_keyack: bytes | None = field(default=None, repr=False)
    _peer: str | None = field(default=None, repr=False)
    _peer_ephemeral: bytes | None = field(default=None, repr=False)
    _key: bytes | None = field(default=None, repr=False)
    _peer_credential: credentials.Credential | None = field(default=None, repr=False)

    def handle_key(self, raw: bytes, now: datetime,
                   airspace: str | None = None) -> None:
        """Verify KEY in the order of Section 3.3.2."""
        fields = _common(raw, expect_role=ROLE_KEY, expect_to=self.identity,
                         now=now, window=self.window)
        region, sig = _signed_body(raw, fields)
        cred = credentials.verify(
            _credential_of(fields),
            trust_anchors=self.trust_anchors,
            now=now,
            expect_subject=encoding.require(fields, "FROM"),
            airspace=airspace,
            signed_message=region,
            message_signature=sig,
        )
        self._peer = cred.subject
        self._peer_credential = cred
        self._peer_ephemeral = _ephemeral_of(fields)
        self._m_key = region

    def build_keyack(self, now: datetime) -> bytes:
        """KEYACK, after which the station holds the session pending."""
        if self._m_key is None:
            raise Rejected(Step.MALFORMED, "no KEY processed")
        body = encoding.encode([
            ("ROLE", ROLE_KEYACK),
            ("TIMESTAMP", _iso(now)),
            ("FROM", self.identity),
            ("TO", self._peer),
            ("CREDENTIAL", primitives.b64u(self.credential)),
            ("EPHEMERAL_KEY", primitives.b64u(self._fresh_ephemeral())),
        ])
        self._m_keyack = body
        self._key = self._agree(self._peer_ephemeral)
        sig = primitives.sign(self.signing_key, body)
        return body + encoding.encode([(SIGNATURE, primitives.b64u(sig))])

    def handle_keyconfirm(self, raw: bytes, now: datetime) -> Session:
        """
        Verify the transcript and the tag, and return the established session.

        Failure discards the pending state; the caller holds that state, so it
        simply does not reach `established`.
        """
        if self._key is None:
            raise Rejected(Step.SESSION_UNKNOWN, "no pending session")
        fields = _common(raw, expect_role=ROLE_KEYCONFIRM, expect_to=self.identity,
                         now=now, window=self.window)
        try:
            region = encoding.authenticated_region(raw, MAC)
            tag = primitives.unb64u(encoding.require(fields, MAC))
            claimed = primitives.unb64u(encoding.require(fields, "TRANSCRIPT"))
        except Exception as exc:
            raise Rejected(Step.MALFORMED, str(exc)) from exc

        if not primitives.verify_mac(self._key, region, tag):
            raise Rejected(Step.TAG, "KEYCONFIRM")

        expected = primitives.transcript_hash(self._m_key, self._m_keyack)
        if not _equal(claimed, expected):
            raise Rejected(Step.TRANSCRIPT, "transcript does not match")

        return Session(
            local=self.identity,
            peer=self._peer,
            peer_credential=self._peer_credential,
            key=self._key,
            transcript=expected,
        )


def _equal(a: bytes, b: bytes) -> bool:
    return secrets.compare_digest(a, b)
