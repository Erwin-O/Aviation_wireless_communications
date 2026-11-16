"""
Tests for the MQTT binding (Section 3.3.1).

The binding's one security-relevant claim is that the role a topic advertises
carries no authority: where the topic disagrees with the ROLE inside the
authenticated region, the message is refused. Table 5's "Role agreement" row
is this check.
"""

import unittest

from protocol import encoding, mqtt_binding
from protocol.rejection import Rejected, Step


def _body(role: str) -> bytes:
    return encoding.encode([
        ("ROLE", role),
        ("TIMESTAMP", "2025-11-17T04:00:20+00:00"),
        ("FROM", "EBBR_GND"),
        ("TO", "OOABC"),
    ])


class TestTopicConstruction(unittest.TestCase):
    def test_role_and_addressee_are_slugged(self):
        self.assertEqual("aviation/cc_clearance/OOABC",
                         mqtt_binding.topic_for("CC:CLEARANCE", "OOABC"))

    def test_a_name_with_a_space_is_routable(self):
        self.assertEqual("aviation/sa/EBBR_GND",
                         mqtt_binding.topic_for("SA", "EBBR GND"))

    def test_a_node_subscribes_to_every_role_addressed_to_it(self):
        self.assertEqual("aviation/+/OOABC",
                         mqtt_binding.subscription_for("OOABC"))


class TestRoleAgreement(unittest.TestCase):
    """The topic is routing convenience; the authenticated ROLE decides."""

    def _step(self, topic: str, raw: bytes) -> Step:
        with self.assertRaises(Rejected) as caught:
            mqtt_binding.check_topic(topic, raw)
        return caught.exception.step

    def test_agreeing_topic_returns_the_authenticated_role(self):
        raw = _body("CC:CLEARANCE")
        self.assertEqual(
            "CC:CLEARANCE",
            mqtt_binding.check_topic("aviation/cc_clearance/OOABC", raw))

    def test_a_topic_disagreeing_with_the_body_is_refused(self):
        # An adversary may publish anything to any topic. Presenting a
        # situational awareness report on a clearance topic does not make it
        # a clearance, and the disagreement is itself grounds for refusal.
        raw = _body("SA")
        self.assertEqual(
            Step.ROLE_UNKNOWN,
            self._step("aviation/cc_clearance/OOABC", raw))

    def test_a_clearance_hidden_on_a_report_topic_is_refused(self):
        raw = _body("CC:CLEARANCE")
        self.assertEqual(Step.ROLE_UNKNOWN,
                         self._step("aviation/sa/OOABC", raw))

    def test_an_unroutable_topic_is_malformed(self):
        raw = _body("SA")
        self.assertEqual(Step.MALFORMED, self._step("aviation", raw))

    def test_a_body_that_does_not_parse_is_malformed(self):
        self.assertEqual(Step.MALFORMED,
                         self._step("aviation/sa/OOABC", b"not an encoding"))

    def test_a_body_without_a_role_is_malformed(self):
        raw = encoding.encode([("FROM", "EBBR_GND"), ("TO", "OOABC")])
        self.assertEqual(Step.MALFORMED, self._step("aviation/sa/OOABC", raw))


if __name__ == "__main__":
    unittest.main()
