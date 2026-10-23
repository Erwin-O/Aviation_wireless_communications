"""
The MQTT binding (paper, Section 3.3.1, "The specification is defined against
an abstract transport").

Each role is published to its own topic, so a subscriber may filter without
parsing:

    aviation/<role>/<addressee>          aviation/cc_clearance/OOABC
                                         aviation/sa/EBBR_GND

A node subscribes to everything addressed to it, `aviation/+/<its own name>`.

The rule that makes this a binding rather than part of the protocol: **the
exposed role carries no authority**. A receiver compares the topic against the
authenticated ROLE field and rejects any message where the two disagree. An
adversary may publish anything to any topic; the only thing that decides what
a message is, is the ROLE inside the region the tag covers.

Bindings for other carriers differ in how messages are framed and addressed,
and not at all in what is authenticated.
"""

from __future__ import annotations

import re

from protocol import encoding
from protocol.rejection import Rejected, Step

DEFAULT_BASE = "aviation"


def slug(name: str) -> str:
    """A topic-safe form of a station or aircraft identifier."""
    return re.sub(r"[^A-Za-z0-9_]+", "_", name.strip()).strip("_").upper()


def role_slug(role: str) -> str:
    """A topic-safe form of a role: CC:CLEARANCE -> cc_clearance."""
    return re.sub(r"[^a-z0-9]+", "_", role.strip().lower()).strip("_")


def topic_for(role: str, addressee: str, base: str = DEFAULT_BASE) -> str:
    return f"{base}/{role_slug(role)}/{slug(addressee)}"


def subscription_for(name: str, base: str = DEFAULT_BASE) -> str:
    """Everything addressed to this node, whatever its role."""
    return f"{base}/+/{slug(name)}"


def check_topic(topic: str, raw: bytes) -> str:
    """
    Compare the role the topic advertises with the role the message
    authenticates, and return the authenticated one.

    Raises `Rejected` where they disagree. The topic is routing convenience;
    the ROLE field is inside the authenticated region and is what counts.
    """
    try:
        fields = encoding.parse(raw)
        role = encoding.require(fields, "ROLE")
    except encoding.EncodingError as exc:
        raise Rejected(Step.MALFORMED, str(exc)) from exc

    parts = topic.split("/")
    if len(parts) < 3:
        raise Rejected(Step.MALFORMED, f"unroutable topic: {topic}")
    advertised = parts[-2]
    if advertised != role_slug(role):
        raise Rejected(
            Step.ROLE_UNKNOWN,
            f"topic says {advertised}, message authenticates {role}")
    return role
