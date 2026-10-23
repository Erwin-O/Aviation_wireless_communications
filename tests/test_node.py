"""
End-to-end behaviour over an in-process network (Sections 3.3.2 to 3.3.4).

No transport, no broker: messages are handed straight between nodes, so what
these tests exercise is the protocol and not the plumbing.
"""

import unittest
from datetime import timedelta

from protocol import encoding, identity as I, node as N, operational as O
from protocol import primitives as P, session as S
from protocol.rejection import Rejected, Step
from tests.test_handshake import authority, party, AIRCRAFT_ROLES, GROUND_ROLES, NOW

MIN = timedelta(minutes=1)

REPORT = dict(altitude="165", alt_ref="BARO_QNH",
              position="50.901981 LAT 4.482942 LONG",
              speed="420", heading="334", on_ground="0")


def make_identity(ca, name, roles, sector=None):
    kw = party(ca, name, roles, sector=sector)
    return I.Identity(name=name, credential=kw["credential"],
                      signing_key=kw["signing_key"], kex_secret=kw["kex_secret"])


class Net:
    """Routes what nodes return back into the nodes they are addressed to."""

    def __init__(self, ca=None):
        self.ca = ca or authority()
        self.anchors = self.ca["anchors"]
        self.nodes: dict[str, object] = {}
        self.log: list[tuple[str, str, str]] = []
        self.dropped: list[str] = []

    def aircraft(self, name="OOABC"):
        node = N.Aircraft(make_identity(self.ca, name, AIRCRAFT_ROLES), self.anchors)
        self.nodes[name] = node
        return node

    def station(self, name, sector="EBBU"):
        node = N.Station(make_identity(self.ca, name, GROUND_ROLES, sector=sector),
                         self.anchors, sector=sector)
        self.nodes[name] = node
        return node

    def deliver(self, outbound, now, drop=(), airspace=None):
        """Deliver messages, following whatever they provoke, to quiescence."""
        queue = list(outbound)
        while queue:
            m = queue.pop(0)
            sender = "?"
            self.log.append((sender, m.to, m.role))
            if m.role in drop:
                self.dropped.append(m.role)
                continue
            node = self.nodes[m.to]
            queue += node.handle(m.raw, now, airspace=airspace)
        return self.log

    def roles(self):
        return [r for _, _, r in self.log]


class TestSessionLifecycle(unittest.TestCase):
    def setUp(self):
        self.net = Net()
        self.ac = self.net.aircraft()
        self.gs = self.net.station("EBBR GND", sector="EBBU")

    def test_a_session_is_established_in_three_messages(self):
        self.net.deliver(self.ac.connect("EBBR GND", NOW), NOW)
        self.assertEqual(self.net.roles(), ["KEY", "KEYACK", "KEYCONFIRM"])
        self.assertEqual(self.ac.table.get("EBBR GND").state, S.State.ESTABLISHED)
        self.assertEqual(self.gs.table.get("OOABC").state, S.State.ESTABLISHED)

    def test_both_sides_hold_the_same_key(self):
        self.net.deliver(self.ac.connect("EBBR GND", NOW), NOW)
        self.assertEqual(self.ac.table.get("EBBR GND").key,
                         self.gs.table.get("OOABC").key)

    def test_the_station_holds_the_session_pending_until_keyconfirm(self):
        out = self.ac.connect("EBBR GND", NOW)
        keyack = self.gs.handle(out[0].raw, NOW)
        self.assertEqual(self.gs.table.get("OOABC").state, S.State.PENDING)
        self.assertFalse(self.gs.table.get("OOABC").is_operational())
        self.ac.handle(keyack[0].raw, NOW)
        self.assertEqual(self.gs.table.get("OOABC").state, S.State.PENDING)


class TestCommandAndAcknowledgement(unittest.TestCase):
    def setUp(self):
        self.net = Net()
        self.ac = self.net.aircraft()
        self.gs = self.net.station("EBBR GND", sector="EBBU")
        self.net.deliver(self.ac.connect("EBBR GND", NOW), NOW)
        self.net.log.clear()

    def test_a_queued_instruction_follows_a_report_and_is_acknowledged(self):
        self.gs.enqueue("OOABC", O.CC_CLEARANCE, "DESCEND FL100")
        self.net.deliver(self.ac.report(NOW, **REPORT), NOW)
        self.assertEqual(self.net.roles(), ["SA", "CC:CLEARANCE", "ACK"])
        self.assertNotEqual(self.ac.table.get("EBBR GND").last_exec,
                            P.ZERO_CHALLENGE)

    def test_nothing_is_issued_without_a_challenge_to_answer(self):
        self.gs.enqueue("OOABC", O.CC_CLEARANCE, "DESCEND FL100")
        self.assertEqual(self.gs.tick(NOW), [])
        self.assertEqual(self.net.roles(), [])

    def test_a_lost_command_is_resent_on_the_next_report(self):
        self.gs.enqueue("OOABC", O.CC_CLEARANCE, "DESCEND FL100")
        self.net.deliver(self.ac.report(NOW, **REPORT), NOW, drop=("CC:CLEARANCE",))
        self.assertEqual(self.net.dropped, ["CC:CLEARANCE"])
        self.net.log.clear()
        self.net.deliver(self.ac.report(NOW + MIN, **REPORT), NOW + MIN)
        self.assertEqual(self.net.roles(), ["SA", "CC:CLEARANCE", "ACK"])

    def test_an_executed_command_is_not_resent(self):
        self.gs.enqueue("OOABC", O.CC_CLEARANCE, "DESCEND FL100")
        self.net.deliver(self.ac.report(NOW, **REPORT), NOW)
        self.net.log.clear()
        self.net.deliver(self.ac.report(NOW + MIN, **REPORT), NOW + MIN)
        self.assertEqual(self.net.roles(), ["SA"])

    def test_an_acknowledgement_re_arms_the_exchange_at_once(self):
        """
        Section 3.3.3: the ACK carries the next challenge, "so an acknowledged
        command re-arms the exchange at once rather than at the next report".
        Two queued instructions therefore both go out on one report, each
        bound to the challenge the previous acknowledgement supplied.
        """
        self.gs.enqueue("OOABC", O.CC_CLEARANCE, "DESCEND FL100")
        self.gs.enqueue("OOABC", O.CC_INSTRUCTION, "TURN LEFT HDG 270")
        self.net.deliver(self.ac.report(NOW, **REPORT), NOW)
        self.assertEqual(
            self.net.roles(),
            ["SA", "CC:CLEARANCE", "ACK", "CC:INSTRUCTION", "ACK"])

    def test_each_command_is_bound_to_a_different_challenge(self):
        self.gs.enqueue("OOABC", O.CC_CLEARANCE, "DESCEND FL100")
        self.gs.enqueue("OOABC", O.CC_INSTRUCTION, "TURN LEFT HDG 270")
        sent = []
        queue = list(self.ac.report(NOW, **REPORT))
        while queue:
            m = queue.pop(0)
            if m.role in S.COMMAND_ROLES:
                sent.append(encoding.require(encoding.parse(m.raw), "IN_REPLY_TO"))
            queue += self.net.nodes[m.to].handle(m.raw, NOW)
        self.assertEqual(len(sent), 2)
        self.assertNotEqual(sent[0], sent[1])

    def test_a_replayed_command_is_refused(self):
        self.gs.enqueue("OOABC", O.CC_CLEARANCE, "DESCEND FL100")
        out = self.ac.report(NOW, **REPORT)
        command = self.gs.handle(out[0].raw, NOW)[0]
        self.ac.handle(command.raw, NOW)
        with self.assertRaises(Rejected) as cm:
            self.ac.handle(command.raw, NOW)
        self.assertEqual(cm.exception.step, Step.CHALLENGE)


class TestTransferOfControl(unittest.TestCase):
    def setUp(self):
        self.net = Net()
        self.ac = self.net.aircraft()
        self.g1 = self.net.station("EBBR GND", sector="EBBU")
        self.g2 = self.net.station("BRUACC", sector="EBBU")
        self.net.deliver(self.ac.connect("EBBR GND", NOW), NOW)
        self.net.deliver(self.ac.report(NOW, **REPORT), NOW)
        self.net.log.clear()

    def test_a_nomination_carries_the_aircraft_to_the_successor(self):
        self.net.deliver(self.g1.nominate("OOABC", "BRUACC", NOW), NOW)
        self.assertEqual(self.net.roles(),
                         ["CC:CONTACT", "ACK", "KEY", "KEYACK", "KEYCONFIRM"])
        self.assertEqual(self.ac.table.get("BRUACC").state, S.State.ESTABLISHED)

    def test_the_old_session_ends_when_the_successor_is_established(self):
        self.net.deliver(self.g1.nominate("OOABC", "BRUACC", NOW), NOW)
        self.assertIsNone(self.ac.table.get("EBBR GND"))

    def test_the_outgoing_station_relinquishes_on_transmission(self):
        self.net.deliver(self.g1.nominate("OOABC", "BRUACC", NOW), NOW)
        self.assertEqual(self.g1.table.get("OOABC").state, S.State.HANDOVER)

    def test_the_outgoing_station_can_no_longer_be_obeyed(self):
        out = self.g1.nominate("OOABC", "BRUACC", NOW)
        self.g1.enqueue("OOABC", O.CC_CLEARANCE, "CLIMB FL200")
        self.net.deliver(out, NOW)
        # Its session is in handover, so nothing further is issued at all.
        self.net.log.clear()
        self.assertEqual(self.g1.tick(NOW), [])

    def test_nothing_crosses_the_transfer(self):
        self.net.deliver(self.g1.nominate("OOABC", "BRUACC", NOW), NOW)
        row = self.ac.table.get("BRUACC")
        self.assertEqual(row.last_exec, P.ZERO_CHALLENGE)

    def test_the_successor_takes_over_issuing(self):
        self.net.deliver(self.g1.nominate("OOABC", "BRUACC", NOW), NOW)
        self.g2.enqueue("OOABC", O.CC_CLEARANCE, "DESCEND FL080")
        self.net.log.clear()
        self.net.deliver(self.ac.report(NOW + MIN, **REPORT), NOW + MIN)
        self.assertEqual(self.net.roles(), ["SA", "CC:CLEARANCE", "ACK"])

    def test_a_station_interposing_itself_is_refused(self):
        """
        Section 3.3.4: where the aircraft elects to proceed with the nominated
        station, the credential that answers must name it, "so a party
        interposing itself in place of the nominated successor is refused even
        though its own credential may be valid".

        The aircraft is waiting on BRUACC. EDGG CTR answers instead, with a
        credential that is genuine, unexpired and issued by the same
        authority. It is refused on subject alone.
        """
        self.net.deliver(self.g1.nominate("OOABC", "BRUACC", NOW), NOW,
                         drop=("KEY",))
        self.assertEqual(self.ac.table.get("EBBR GND").state, S.State.HANDOVER)

        # A well-formed KEYACK from a station that is not the one named.
        impostor = self.net.station("EDGG CTR", sector="EDGG")
        other = self.net.aircraft("OOXYZ")
        key = other.connect("EDGG CTR", NOW)[0]
        keyack = impostor.handle(key.raw, NOW)[0]

        with self.assertRaises(Rejected) as cm:
            self.ac.handle(keyack.raw, NOW)
        self.assertEqual(cm.exception.step, Step.SUBJECT)

    def test_a_handover_that_never_completes_reverts(self):
        contact = self.g1.nominate("OOABC", "BRUACC", NOW)
        # Deliver the nomination but drop the KEY, so no successor session.
        self.net.deliver(contact, NOW, drop=("KEY",))
        self.assertEqual(self.ac.table.get("EBBR GND").state, S.State.HANDOVER)
        late = NOW + timedelta(minutes=5)
        out = self.ac.tick(late)
        self.assertEqual([m.role for m in out], [O.CC_SYSTEM])
        self.assertEqual(self.ac.table.get("EBBR GND").state, S.State.ESTABLISHED)

    def test_the_reversion_notice_reaches_the_station(self):
        contact = self.g1.nominate("OOABC", "BRUACC", NOW)
        self.net.deliver(contact, NOW, drop=("KEY",))
        late = NOW + timedelta(minutes=5)
        notice = self.ac.tick(late)
        self.net.log.clear()
        self.net.deliver(notice, late)
        self.assertEqual(self.net.roles(), [O.CC_SYSTEM])


if __name__ == "__main__":
    unittest.main()
