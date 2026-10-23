"""Tests for the canonical labelled-field encoding (Section 3.3.1)."""

import unittest

from protocol import encoding
from protocol.encoding import EncodingError


SA_EXAMPLE = [
    ("ROLE", "SA"),
    ("TIMESTAMP", "2025-11-17T04:00:20+00:00"),
    ("FROM", "OOABC"),
    ("TO", "EBBR GND"),
    ("ALTITUDE", "165"),
    ("ALT_REF", "BARO_QNH"),
    ("POSITION", "50.901981 LAT 4.482942 LONG"),
    ("SPEED", "0"),
    ("HEADING", "334"),
    ("ON_GROUND", "1"),
    ("LAST_EXEC", "A" * 43),
    ("CHALLENGE", "7Hq2lP0vZt4rKx9mNcB1QwRtY6uIoP8aSdFgHjKlZx0"),
]


class TestRoundTrip(unittest.TestCase):
    def test_round_trip_preserves_order_and_values(self):
        wire = encoding.encode(SA_EXAMPLE)
        self.assertEqual(encoding.parse(wire), SA_EXAMPLE)

    def test_values_may_contain_spaces(self):
        wire = encoding.encode([("TO", "EBBR GND")])
        self.assertEqual(encoding.parse(wire), [("TO", "EBBR GND")])

    def test_every_line_is_terminated(self):
        wire = encoding.encode([("ROLE", "SA")])
        self.assertTrue(wire.endswith(encoding.LINE_TERMINATOR))


class TestOneParse(unittest.TestCase):
    """"A message admits exactly one parse" is a security property."""

    def test_duplicate_field_is_rejected_on_parse(self):
        wire = b"ROLE: SA\r\nROLE: CC:CLEARANCE\r\n"
        with self.assertRaises(EncodingError):
            encoding.parse(wire)

    def test_duplicate_field_is_rejected_on_encode(self):
        with self.assertRaises(EncodingError):
            encoding.encode([("ROLE", "SA"), ("ROLE", "ACK")])

    def test_unterminated_message_is_rejected(self):
        with self.assertRaises(EncodingError):
            encoding.parse(b"ROLE: SA\r")

    def test_line_without_separator_is_rejected(self):
        with self.assertRaises(EncodingError):
            encoding.parse(b"ROLE SA\r\n")

    def test_lower_case_field_name_is_rejected(self):
        with self.assertRaises(EncodingError):
            encoding.parse(b"role: SA\r\n")

    def test_non_ascii_value_is_rejected(self):
        with self.assertRaises(EncodingError):
            encoding.encode([("FROM", "OOÅBC")])

    def test_embedded_terminator_cannot_forge_a_field(self):
        with self.assertRaises(EncodingError):
            encoding.encode([("TO", "EBBR\r\nROLE: CC:CLEARANCE")])

    def test_parse_rejects_str(self):
        with self.assertRaises(EncodingError):
            encoding.parse("ROLE: SA\r\n")


class TestAuthenticatedRegion(unittest.TestCase):
    """The authenticator covers every preceding line, sliced as received."""

    def test_region_is_everything_before_the_authenticator(self):
        wire = encoding.encode(SA_EXAMPLE) + encoding.encode([("MAC", "deadbeef")])
        region = encoding.authenticated_region(wire, "MAC")
        self.assertEqual(region, encoding.encode(SA_EXAMPLE))

    def test_region_is_a_slice_of_the_input(self):
        wire = encoding.encode(SA_EXAMPLE) + encoding.encode([("MAC", "deadbeef")])
        region = encoding.authenticated_region(wire, "MAC")
        self.assertTrue(wire.startswith(region))

    def test_missing_authenticator_is_rejected(self):
        with self.assertRaises(EncodingError):
            encoding.authenticated_region(encoding.encode(SA_EXAMPLE), "MAC")

    def test_a_value_mentioning_the_authenticator_does_not_split_early(self):
        # A field whose *value* contains "MAC: " must not be mistaken for the
        # authenticator line.
        wire = encoding.encode(
            [("ROLE", "SA"), ("NOTE", "MAC: not a field here")]
        ) + encoding.encode([("MAC", "tag")])
        region = encoding.authenticated_region(wire, "MAC")
        self.assertIn(b"NOTE: MAC: not a field here", region)
        self.assertEqual(region, wire[: wire.rindex(b"MAC: tag")])


if __name__ == "__main__":
    unittest.main()
