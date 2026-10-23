"""
Tests for operational messages, the challenge exchange and the three session
states (Sections 3.3.3 and 3.3.4).
"""

import unittest
from datetime import datetime, timedelta, timezone

from protocol import credentials as C
from protocol import encoding, handshake as H, operational as O
from protocol import primitives as P, session as S
from protocol.rejection import Rejected, Step
from tests.test_handshake import authority, party, AIRCRAFT_ROLES, GROUND_ROLES, NOW, HOUR

MIN = timedelta(minutes=1)


class Fixture:
    """Two endpoints with an established session, from a real handshake."""

    def __init__(self, ca=None, station="EBBR GND", sector="EBBU"):
        self.ca = ca or authority()
        self.ac_kw = party(self.ca, "OOABC", AIRCRAFT_ROLES)
        self.gs_kw = party(self.ca, station, GROUND_ROLES, sector=sector)
        ac = H.Initiator(**self.ac_kw)
        gs = H.Responder(**self.gs_kw)

        m1 = ac.build_key(station, NOW)
        gs.handle_key(m1, NOW)
        m2 = gs.build_keyack(NOW)
        ac.handle_keyack(m2, NOW)
        m3, ac_sess = ac.build_keyconfirm(NOW)
        gs_sess = gs.handle_keyconfirm(m3, NOW)

        self.station = station
        self.air_table, self.gnd_table = S.SessionTable(), S.SessionTable()
        self.air = self.air_table.open_pending(station, ac_sess.key,
                                               ac_sess.peer_credential, NOW)
        self.gnd = self.gnd_table.open_pending("OOABC", gs_sess.key,
                                               gs_sess.peer_credential, NOW)
        self.air_table.establish(station, NOW)
        self.gnd_table.establish("OOABC", NOW)
        self.ac_kex = self.ac_kw["kex_secret"]

    def report(self, now=NOW, **over):
        kw = dict(sender="OOABC", altitude="165", alt_ref="BARO_QNH",
                  position="50.901981 LAT 4.482942 LONG", speed="0",
                  heading="334", on_ground="1")
        kw.update(over)
        return O.build_sa(self.air, self.ac_kex, now, **kw)

    def gnd_receives(self, raw, now=NOW, **kw):
        return O.receive(raw, self.gnd_table, now, local=self.station,
                         as_aircraft=False, **kw)

    def air_receives(self, raw, now=NOW, **kw):
        return O.receive(raw, self.air_table, now, local="OOABC",
                         as_aircraft=True, **kw)

    def command(self, in_reply_to, now=NOW, role=O.CC_CLEARANCE,
                instruction="DESCEND FL100"):
        return O.build_command(self.gnd, now, sender=self.station, role=role,
                               instruction=instruction, in_reply_to=in_reply_to)


class TestTheRoundTrip(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def test_a_report_reaches_the_station(self):
        msg = self.f.gnd_receives(self.f.report())
        self.assertEqual(msg.role, "SA")
        self.assertEqual(msg.sender, "OOABC")
        self.assertEqual(msg.get("ALTITUDE"), "165")

    def test_a_report_carries_last_exec_and_a_fresh_challenge(self):
        msg = self.f.gnd_receives(self.f.report())
        self.assertEqual(O.last_exec_of(msg), P.ZERO_CHALLENGE)
        self.assertEqual(len(P.unb64u(msg.get("CHALLENGE"))), P.CHALLENGE_BYTES)

    def test_successive_reports_carry_different_challenges(self):
        a = self.f.gnd_receives(self.f.report()).get("CHALLENGE")
        b = self.f.gnd_receives(self.f.report(now=NOW + MIN), now=NOW + MIN).get("CHALLENGE")
        self.assertNotEqual(a, b)

    def test_a_command_quoting_the_outstanding_challenge_is_acted_upon(self):
        report = self.f.gnd_receives(self.f.report())
        c = P.unb64u(report.get("CHALLENGE"))
        cmd = self.f.command(c)
        msg = self.f.air_receives(cmd)
        self.assertEqual(msg.get("INSTRUCTION"), "DESCEND FL100")
        self.assertEqual(S.record_execution(self.f.air), c)
        self.assertEqual(self.f.air.last_exec, c)
        self.assertIsNone(self.f.air.outstanding)

    def test_the_acknowledgement_re_arms_at_once(self):
        report = self.f.gnd_receives(self.f.report())
        c = P.unb64u(report.get("CHALLENGE"))
        cmd = self.f.command(c)
        msg = self.f.air_receives(cmd)
        S.record_execution(self.f.air)
        ack = O.build_ack(self.f.air, self.f.ac_kex, NOW, sender="OOABC",
                          acknowledged_body=msg.body, response="WILCO")
        seen = self.f.gnd_receives(ack)
        self.assertEqual(seen.role, "ACK")
        self.assertEqual(O.last_exec_of(seen), c)
        self.assertIsNotNone(self.f.air.outstanding)

    def test_the_acknowledgement_names_the_body_it_answers(self):
        report = self.f.gnd_receives(self.f.report())
        cmd = self.f.command(P.unb64u(report.get("CHALLENGE")))
        msg = self.f.air_receives(cmd)
        S.record_execution(self.f.air)
        ack = O.build_ack(self.f.air, self.f.ac_kex, NOW, sender="OOABC",
                          acknowledged_body=msg.body, response="WILCO")
        seen = self.f.gnd_receives(ack)
        self.assertEqual(P.unb64u(seen.get("ACK_HASH")), P.ack_hash(msg.body))


class TestReplayAndOrdering(unittest.TestCase):
    """Section 3.3.3: not twice, and not out of turn."""

    def setUp(self):
        self.f = Fixture()
        report = self.f.gnd_receives(self.f.report())
        self.c1 = P.unb64u(report.get("CHALLENGE"))

    def test_the_same_command_cannot_be_acted_upon_twice(self):
        cmd = self.f.command(self.c1)
        self.f.air_receives(cmd)
        S.record_execution(self.f.air)
        with self.assertRaises(Rejected) as cm:
            self.f.air_receives(cmd)
        self.assertEqual(cm.exception.step, Step.CHALLENGE)

    def test_a_command_bound_to_a_retired_challenge_is_refused(self):
        self.f.report(now=NOW + MIN)          # aircraft sends again, retiring c1
        with self.assertRaises(Rejected) as cm:
            self.f.air_receives(self.f.command(self.c1), now=NOW + MIN)
        self.assertEqual(cm.exception.step, Step.CHALLENGE)

    def test_a_command_bound_to_no_challenge_is_refused(self):
        wire = O.build_command(self.f.gnd, NOW, sender=self.f.station,
                               role=O.CC_CLEARANCE, instruction="TURN LEFT",
                               in_reply_to=bytes(P.CHALLENGE_BYTES))
        with self.assertRaises(Rejected) as cm:
            self.f.air_receives(wire)
        self.assertEqual(cm.exception.step, Step.CHALLENGE)

    def test_a_later_command_overtaking_an_earlier_one_is_refused(self):
        """
        Two commands bound to successive challenges. The aircraft acts on the
        first; the second, bound to a challenge now retired, is refused.
        """
        first = self.f.command(self.c1)
        self.f.air_receives(first)
        S.record_execution(self.f.air)
        later = self.f.report(now=NOW + MIN)
        c2 = P.unb64u(encoding.require(encoding.parse(later), "CHALLENGE"))
        second = self.f.command(c2, now=NOW + MIN)
        self.f.air_receives(second, now=NOW + MIN)       # in turn: accepted
        S.record_execution(self.f.air)
        with self.assertRaises(Rejected) as cm:          # again: refused
            self.f.air_receives(second, now=NOW + MIN)
        self.assertEqual(cm.exception.step, Step.CHALLENGE)


class TestLossTolerance(unittest.TestCase):
    """LAST_EXEC informs the station's decision; it never gates acceptance."""

    def setUp(self):
        self.f = Fixture()

    def test_a_lost_report_changes_nothing(self):
        self.f.report()                 # never delivered
        later = self.f.report(now=NOW + MIN)
        msg = self.f.gnd_receives(later, now=NOW + MIN)
        self.assertEqual(O.last_exec_of(msg), P.ZERO_CHALLENGE)

    def test_a_lost_command_shows_up_in_the_next_report(self):
        first = self.f.gnd_receives(self.f.report())
        self.f.command(P.unb64u(first.get("CHALLENGE")))      # never delivered
        nxt = self.f.gnd_receives(self.f.report(now=NOW + MIN), now=NOW + MIN)
        self.assertTrue(S.station_should_resend(self.f.gnd, O.last_exec_of(nxt)))

    def test_an_executed_command_lets_the_station_advance(self):
        first = self.f.gnd_receives(self.f.report())
        c = P.unb64u(first.get("CHALLENGE"))
        cmd = self.f.command(c)
        self.f.air_receives(cmd)
        S.record_execution(self.f.air)
        nxt = self.f.gnd_receives(self.f.report(now=NOW + MIN), now=NOW + MIN)
        self.assertFalse(S.station_should_resend(self.f.gnd, O.last_exec_of(nxt)))

    def test_a_resent_command_is_bound_to_the_newer_challenge(self):
        first = self.f.gnd_receives(self.f.report())
        self.f.command(P.unb64u(first.get("CHALLENGE")))      # lost
        nxt = self.f.gnd_receives(self.f.report(now=NOW + MIN), now=NOW + MIN)
        resend = self.f.command(P.unb64u(nxt.get("CHALLENGE")), now=NOW + MIN)
        msg = self.f.air_receives(resend, now=NOW + MIN)
        self.assertEqual(msg.get("INSTRUCTION"), "DESCEND FL100")

    def test_the_aircraft_owes_a_message_every_delta_t_rep(self):
        self.f.report()
        self.assertFalse(S.overdue(self.f.air, NOW + timedelta(seconds=10)))
        self.assertTrue(S.overdue(self.f.air, NOW + timedelta(seconds=90)))


class TestSessionStates(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def test_pending_passes_no_operational_traffic(self):
        table = S.SessionTable()
        row = table.open_pending("OOABC", self.f.gnd.key,
                                 self.f.gnd.peer_credential, NOW)
        self.assertFalse(row.is_operational())
        for role in ("SA", "ACK", O.CC_CLEARANCE, O.CC_SYSTEM):
            self.assertFalse(table.admits(row, role), role)

    def test_established_admits_everything(self):
        for role in ("SA", "ACK", O.CC_CLEARANCE, O.CC_CONTACT, O.CC_SYSTEM):
            self.assertTrue(self.f.air_table.admits(self.f.air, role), role)

    def test_handover_refuses_commands_and_keeps_the_channel(self):
        self.f.air_table.begin_handover(self.f.station, "EDGG GND", NOW)
        for role in (O.CC_CLEARANCE, O.CC_INSTRUCTION, O.CC_CONTACT):
            self.assertFalse(self.f.air_table.admits(self.f.air, role), role)
        for role in (O.CC_SYSTEM, O.CC_EMERGENCY, "SA", "ACK"):
            self.assertTrue(self.f.air_table.admits(self.f.air, role), role)

    def test_a_command_in_handover_is_refused_at_the_state_check(self):
        report = self.f.gnd_receives(self.f.report())
        c = P.unb64u(report.get("CHALLENGE"))
        cmd = self.f.command(c)
        self.f.air_table.begin_handover(self.f.station, "EDGG GND", NOW)
        with self.assertRaises(Rejected) as cm:
            self.f.air_receives(cmd)
        self.assertEqual(cm.exception.step, Step.SESSION_STATE)

    def test_handover_cannot_start_from_pending(self):
        table = S.SessionTable()
        table.open_pending("EBBR GND", b"\x00" * 32,
                           self.f.air.peer_credential, NOW)
        with self.assertRaises(Rejected) as cm:
            table.begin_handover("EBBR GND", "EDGG GND", NOW)
        self.assertEqual(cm.exception.step, Step.SESSION_STATE)

    def test_establishing_the_successor_ends_the_handover_session(self):
        self.f.air_table.begin_handover(self.f.station, "EDGG GND", NOW)
        self.f.air_table.open_pending("EDGG GND", b"\x01" * 32,
                                      self.f.air.peer_credential, NOW)
        self.f.air_table.establish("EDGG GND", NOW)
        self.assertIsNone(self.f.air_table.get(self.f.station))
        self.assertEqual(self.f.air_table.get("EDGG GND").state, S.State.ESTABLISHED)

    def test_reverting_restores_authority(self):
        self.f.air_table.begin_handover(self.f.station, "EDGG GND", NOW)
        row = self.f.air_table.revert(self.f.station, NOW + MIN)
        self.assertEqual(row.state, S.State.ESTABLISHED)
        self.assertIsNone(row.nominated_successor)
        self.assertTrue(self.f.air_table.admits(row, O.CC_CLEARANCE))

    def test_a_pending_session_is_discarded_on_timeout(self):
        table = S.SessionTable()
        table.open_pending("OOXYZ", b"\x00" * 32, self.f.gnd.peer_credential, NOW)
        self.assertEqual(table.expire(NOW + MIN), [("OOXYZ", "pending_discarded")])
        self.assertEqual(len(table), 0)

    def test_a_handover_expires_at_the_station(self):
        self.f.gnd_table.begin_handover("OOABC", "EDGG GND", NOW)
        events = self.f.gnd_table.expire(NOW + timedelta(minutes=5))
        self.assertEqual(events, [("OOABC", "handover_expired")])

    def test_nothing_crosses_a_transfer(self):
        """
        Section 3.3.3: a new session begins with LAST_EXEC at zero and no
        challenge outstanding, so a successor inherits nothing.
        """
        report = self.f.gnd_receives(self.f.report())
        cmd = self.f.command(P.unb64u(report.get("CHALLENGE")))
        self.f.air_receives(cmd)
        S.record_execution(self.f.air)
        self.assertNotEqual(self.f.air.last_exec, P.ZERO_CHALLENGE)

        successor = self.f.air_table.open_pending(
            "EDGG GND", b"\x02" * 32, self.f.air.peer_credential, NOW)
        self.assertEqual(successor.last_exec, P.ZERO_CHALLENGE)
        self.assertIsNone(successor.outstanding)


class TestReceiptOrder(unittest.TestCase):
    """Each check refuses what it is meant to, and in the specified order."""

    def setUp(self):
        self.f = Fixture()

    def _step(self, fn, *a, **kw):
        with self.assertRaises(Rejected) as cm:
            fn(*a, **kw)
        return cm.exception.step

    def test_unknown_session(self):
        empty = S.SessionTable()
        self.assertEqual(
            Step.SESSION_UNKNOWN,
            self._step(O.receive, self.f.report(), empty, NOW,
                       local=self.f.station, as_aircraft=False))

    def test_altered_payload_fails_the_tag(self):
        raw = self.f.report().replace(b"ALTITUDE: 165", b"ALTITUDE: 950")
        self.assertEqual(Step.TAG, self._step(self.f.gnd_receives, raw))

    def test_tag_from_another_session_is_refused(self):
        other = Fixture(ca=self.f.ca)
        self.assertEqual(Step.TAG, self._step(self.f.gnd_receives, other.report()))

    def test_timestamp_outside_the_window(self):
        self.assertEqual(
            Step.TIMESTAMP_WINDOW,
            self._step(self.f.gnd_receives, self.f.report(), NOW + HOUR))

    def test_role_outside_the_credential(self):
        """A station permitted to clear is not thereby permitted to report."""
        wire = O.build_command(self.f.gnd, NOW, sender=self.f.station,
                               role=O.CC_REQUEST, instruction="X",
                               in_reply_to=bytes(P.CHALLENGE_BYTES))
        self.assertEqual(Step.ROLE_NOT_PERMITTED,
                         self._step(self.f.air_receives, wire))

    def test_a_station_refuses_an_aircraft_outside_its_own_sector(self):
        """
        Section 5.3: sector enforcement is the ground station's obligation and
        concerns its own entitlement. EBBR GND is credentialled for EBBU; an
        aircraft reporting itself in EDGG is not its to serve.
        """
        self.assertEqual(
            Step.SECTOR,
            self._step(self.f.gnd_receives, self.f.report(), NOW,
                       local_sector="EBBU", airspace="EDGG"))

    def test_a_station_accepts_an_aircraft_inside_its_own_sector(self):
        msg = self.f.gnd_receives(self.f.report(), NOW,
                                  local_sector="EBBU", airspace="EBBU.NORTH")
        self.assertEqual(msg.role, "SA")

    def test_an_aircraft_does_not_enforce_sector(self):
        """
        Section 5.3: requiring it would oblige every aircraft to carry current
        airspace boundary data, so the aircraft side ignores these arguments.
        """
        report = self.f.gnd_receives(self.f.report())
        cmd = self.f.command(P.unb64u(report.get("CHALLENGE")))
        msg = self.f.air_receives(cmd, NOW, local_sector="EBBU", airspace="EDGG")
        self.assertEqual(msg.role, O.CC_CLEARANCE)

    def test_unknown_role(self):
        row = self.f.air
        body = encoding.encode([
            ("ROLE", "CC:LAND_NOW"), ("TIMESTAMP", C._iso(NOW)),
            ("FROM", self.f.station), ("TO", "OOABC"),
        ])
        wire = body + encoding.encode([(H.MAC, P.b64u(P.mac(row.key, body)))])
        self.assertEqual(Step.ROLE_UNKNOWN, self._step(self.f.air_receives, wire))

    def test_missing_alt_ref(self):
        with self.assertRaises(ValueError):
            self.f.report(alt_ref="")

    def test_unrecognised_alt_ref_on_the_wire(self):
        raw = self.f.report().replace(b"ALT_REF: BARO_QNH", b"ALT_REF: BARO_XXXX")
        # the tag covers ALT_REF, so forge a consistent message instead
        body = encoding.encode([
            ("ROLE", "SA"), ("TIMESTAMP", C._iso(NOW)), ("FROM", "OOABC"),
            ("TO", self.f.station), ("ALTITUDE", "165"), ("ALT_REF", "BARO_XXXX"),
            ("POSITION", "0 LAT 0 LONG"), ("SPEED", "0"), ("HEADING", "0"),
            ("ON_GROUND", "1"),
            ("LAST_EXEC", P.b64u(P.ZERO_CHALLENGE)),
            ("CHALLENGE", P.b64u(P.new_challenge(self.f.ac_kex))),
        ])
        wire = body + encoding.encode([(H.MAC, P.b64u(P.mac(self.f.air.key, body)))])
        self.assertEqual(Step.ALT_REF, self._step(self.f.gnd_receives, wire))

    def test_tag_is_checked_before_the_window(self):
        raw = self.f.report().replace(b"ALTITUDE: 165", b"ALTITUDE: 950")
        self.assertEqual(Step.TAG, self._step(self.f.gnd_receives, raw, NOW + HOUR))

    def test_window_is_checked_before_the_challenge(self):
        report = self.f.gnd_receives(self.f.report())
        cmd = self.f.command(P.unb64u(report.get("CHALLENGE")))
        self.f.air_receives(cmd)
        S.record_execution(self.f.air)       # retires the challenge
        self.assertEqual(Step.TIMESTAMP_WINDOW,
                         self._step(self.f.air_receives, cmd, NOW + HOUR))

    def test_challenge_is_checked_before_the_state(self):
        report = self.f.gnd_receives(self.f.report())
        cmd = self.f.command(P.unb64u(report.get("CHALLENGE")))
        self.f.air_receives(cmd)
        S.record_execution(self.f.air)
        self.f.air_table.begin_handover(self.f.station, "EDGG GND", NOW)
        self.assertEqual(Step.CHALLENGE, self._step(self.f.air_receives, cmd))


if __name__ == "__main__":
    unittest.main()
