"""
Canonical labelled-field encoding (paper, Section 3.3.1).

The design rule this module exists to enforce: *the bytes on the wire are the
bytes that are authenticated*. There is no canonicalisation step. A sender
builds the byte string once, authenticates a prefix of it, and sends it; a
receiver authenticates the prefix of what it received, never a reconstruction.
Every function here therefore works in bytes, and `authenticated_region` slices
the received buffer rather than re-encoding parsed fields.

Wire rules (Section 3.3.1):

  * one field per line: an upper-case NAME, a colon and a space, the value,
    and a line terminator;
  * printable ASCII only; no value contains a line terminator, so field
    boundaries are unambiguous and a message admits exactly one parse;
  * timestamps are ISO 8601 with an explicit offset; binary values are
    URL-safe Base64 without padding.

OPEN SPEC POINT (LINE_TERMINATOR): Section 3.3.1 says each line ends with "a
terminating carriage return", so this module uses a bare CR, exactly as
written. If the intent was CRLF, change the constant here and the sentence in
the paper together -- they must not drift apart.
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence

#: Line terminator. See OPEN SPEC POINT in the module docstring.
LINE_TERMINATOR = b"\r"

#: Separator between a field name and its value.
SEPARATOR = b": "

#: A field name is upper-case ASCII, digits and underscore. The role field
#: carries subtypes as values ("CC:CLEARANCE"), never as names.
_NAME_RE = re.compile(rb"\A[A-Z][A-Z0-9_]*\Z")

#: Values are printable ASCII (0x20-0x7E). Spaces are allowed: station names
#: and positions contain them.
_VALUE_RE = re.compile(rb"\A[\x20-\x7e]*\Z")


class EncodingError(ValueError):
    """Raised when a message cannot be encoded or admits no unambiguous parse."""


Field = tuple[str, str]


def encode(fields: Sequence[Field]) -> bytes:
    """
    Encode an ordered sequence of (name, value) pairs into the wire format.

    Field order is the caller's responsibility and is significant: it is part
    of what gets authenticated.
    """
    out = bytearray()
    seen: set[bytes] = set()
    for name, value in fields:
        n = _as_ascii(name, "field name")
        v = _as_ascii(value, "field value")
        if not _NAME_RE.match(n):
            raise EncodingError(f"invalid field name: {name!r}")
        if not _VALUE_RE.match(v):
            raise EncodingError(f"value is not printable ASCII: {name}")
        if n in seen:
            raise EncodingError(f"duplicate field: {name}")
        seen.add(n)
        out += n + SEPARATOR + v + LINE_TERMINATOR
    return bytes(out)


def parse(data: bytes) -> list[Field]:
    """
    Parse a wire message into an ordered list of (name, value) pairs.

    Strict by intent. A message that is malformed, carries a duplicate field,
    or contains a byte outside printable ASCII is rejected rather than
    repaired: "a message admits exactly one parse" is a security property, not
    a convenience, and a tolerant parser is how two implementations come to
    disagree about what was signed.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise EncodingError("parse() operates on bytes, not str")
    data = bytes(data)
    if data and not data.endswith(LINE_TERMINATOR):
        raise EncodingError("message does not end with a line terminator")

    fields: list[Field] = []
    seen: set[bytes] = set()
    for line in data.split(LINE_TERMINATOR)[:-1]:
        if not line:
            raise EncodingError("empty line")
        if SEPARATOR not in line:
            raise EncodingError(f"no name/value separator in line: {line!r}")
        n, _, v = line.partition(SEPARATOR)
        if not _NAME_RE.match(n):
            raise EncodingError(f"invalid field name: {n!r}")
        if not _VALUE_RE.match(v):
            raise EncodingError(f"value is not printable ASCII: {n!r}")
        if n in seen:
            raise EncodingError(f"duplicate field: {n!r}")
        seen.add(n)
        fields.append((n.decode("ascii"), v.decode("ascii")))
    return fields


def authenticated_region(data: bytes, authenticator: str) -> bytes:
    """
    Return the prefix of `data` that the authenticator covers: every byte
    before the line holding the named field.

    This slices the buffer as received. Nothing is re-encoded, so a sender and
    a receiver that disagree about any detail of the encoding cannot
    accidentally agree about the authenticated bytes.
    """
    marker = authenticator.encode("ascii") + SEPARATOR
    # The field must start a line: either at offset 0 or after a terminator.
    if data.startswith(marker):
        return b""
    needle = LINE_TERMINATOR + marker
    idx = data.find(needle)
    if idx < 0:
        raise EncodingError(f"no {authenticator} field found")
    if data.find(needle, idx + 1) >= 0:
        raise EncodingError(f"more than one {authenticator} field")
    return data[: idx + len(LINE_TERMINATOR)]


def get(fields: Iterable[Field], name: str) -> str | None:
    """Return the value of `name`, or None if the field is absent."""
    for n, v in fields:
        if n == name:
            return v
    return None


def require(fields: Iterable[Field], name: str) -> str:
    """Return the value of `name`, or raise EncodingError if it is absent."""
    v = get(fields, name)
    if v is None:
        raise EncodingError(f"missing required field: {name}")
    return v


def _as_ascii(s: str | bytes, what: str) -> bytes:
    if isinstance(s, bytes):
        return s
    if not isinstance(s, str):
        raise EncodingError(f"{what} must be str, not {type(s).__name__}")
    try:
        return s.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EncodingError(f"{what} is not ASCII: {s!r}") from exc
