"""
Printing messages so a person can read them.

The protocol's own argument for payloads in clear is that the traffic should
be readable without tooling (Section 5.2), so the verbose view prints the
message as it travels, one field per line.

Long Base64 values are elided with their length, because a credential is some
six hundred characters and would bury everything around it. The elision is
display only; nothing in the protocol ever sees it.
"""

from __future__ import annotations

ELIDE_OVER = 56
KEEP = 44


def render(raw: bytes, prefix: str = "    ") -> str:
    """The message as lines, with over-long values shortened."""
    out = []
    for line in raw.decode("ascii", "replace").split("\r\n"):
        if not line:
            continue
        name, sep, value = line.partition(": ")
        if sep and len(value) > ELIDE_OVER:
            value = f"{value[:KEEP]}… ({len(value)} chars)"
        out.append(f"{prefix}{name}{sep}{value}")
    return "\n".join(out)


def banner(direction: str, role: str, peer: str, raw: bytes, topic: str = "") -> str:
    """One header line, then the message."""
    head = f"  {direction} {role:14s} {peer}"
    if topic:
        head += f"   [{topic}]"
    head += f"   {len(raw)} B"
    return head + "\n" + render(raw)
