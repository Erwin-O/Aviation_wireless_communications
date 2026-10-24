"""
Tests for the three-message session establishment (Section 3.3.2).

The positive path, then one test per way the exchange can be refused, each
asserting the step that refused it.
"""

import unittest
from datetime import datetime, timedelta, timezone

from protocol import credentials as C
from protocol import encoding, handshake as H, primitives as P
from protocol.rejection import Rejected, Step

NOW = datetime(2025, 11, 17, 4, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)

AIRCRAFT_ROLES = ["KEY", "KEYCONFIRM", "SA", "ACK",
                  "CC:REQUEST", "CC:EMERGENCY", "CC:SYSTEM"]
GROUND_ROLES = ["KEYACK", "CC:CLEARANCE", "CC:INSTRUCTION", "CC:CONTACT", "CC:SYSTEM"]


def authority(name="BE CAA"):
    sk, pk = P.generate_signing_key()
    return {"name": name, "sk": sk, "anchors": {name: pk}}


def party(ca, identity, roles, sector=None, anchors=None, window=None):
    sign_sk, sign_pk = P.generate_signing_key()
    kex_sk, _ = P.generate_kex_key()
    raw = C.issue(
        issuer=ca["name"], subject=identity, verify_key=sign_pk,
        not_before=NOW - HOUR, not_after=NOW + HOUR,
        permitted_roles=roles, issuer_signing_key=ca["sk"], sector=sector,
    )
    kw = dict(identity=identity, credential=raw, signing_key=sign_sk,
              kex_secret=kex_sk, trust_anchors=anchors or ca["anchors"])
    if window is not None:
        kw["window"] = window
    return kw


def aircraft(ca, identity="OOABC", **kw):
    return H.Initiator(**party(ca, identity, AIRCRAFT_ROLES, **kw))


def ground(ca, identity="EBBR GND", sector="EBBU", **kw):
    return H.Responder(**party(ca, identity, GROUND_ROLES, sector=sector, **kw))


class _OverclaimingStation(H.Responder):
    """
    A station that states more airspace than its credential grants.

    Reaching this through the public interface is impossible, because
    `build_keyack` refuses it. The subclass exists to produce a correctly
    signed KEYACK carrying an over-broad claim, which is what an aircraft has
    to refuse on its own.
    """

    def _claimed_airspace(self) -> str:
        return "EDGG"


def run(ac, gs, now=NOW, airspace=None):
    """Drive a full exchange, returning both sides' sessions."""
    m1 = ac.build_key(gs.identity, now)
    gs.handle_key(m1, now)
    m2 = gs.build_keyack(now)
    ac.handle_keyack(m2, now, airspace=airspace)
    m3, ac_session = ac.build_keyconfirm(now)
    gs_session = gs.handle_keyconfirm(m3, now)
    return ac_session, gs_session, (m1, m2, m3)


class TestPositivePath(unittest.TestCase):
    def setUp(self):
        self.ca = authority()
        self.ac, self.gs = aircraft(self.ca), ground(self.ca)

    def test_both_sides_reach_the_same_key(self):
        a, g, _ = run(self.ac, self.gs)
        self.assertEqual(a.key, g.key)
        self.assertEqual(len(a.key), P.SESSION_KEY_BYTES)

    def test_both_sides_agree_on_the_transcript(self):
        a, g, _ = run(self.ac, self.gs)
        self.assertEqual(a.transcript, g.transcript)

    def test_both_sides_agree_on_the_claimed_airspace(self):
        """
        The claim is in the KEYACK body, which the transcript of equation (5)
        covers, so completing the handshake means the parties agreed on the
        airspace and not merely on the key.
        """
        a, g, _ = run(self.ac, self.gs)
        self.assertEqual(a.airspace, "EBBU")
        self.assertEqual(g.airspace, a.airspace)

    def test_each_side_learns_the_other_identity_from_the_credential(self):
        a, g, _ = run(self.ac, self.gs)
        self.assertEqual(a.peer, "EBBR GND")
        self.assertEqual(g.peer, "OOABC")
        self.assertEqual(g.peer_credential.subject, "OOABC")

    def test_messages_carry_the_specified_roles_and_fields(self):
        _, _, (m1, m2, m3) = run(self.ac, self.gs)
        f1, f2, f3 = (encoding.parse(m) for m in (m1, m2, m3))
        self.assertEqual(encoding.get(f1, "ROLE"), "KEY")
        self.assertEqual(encoding.get(f2, "ROLE"), "KEYACK")
        self.assertEqual(encoding.get(f3, "ROLE"), "KEYCONFIRM")
        for f in (f1, f2):
            for name in ("ROLE", "TIMESTAMP", "FROM", "TO", "CREDENTIAL",
                         "EPHEMERAL_KEY", "SIGNATURE"):
                self.assertIsNotNone(encoding.get(f, name), name)
        self.assertIsNotNone(encoding.get(f2, H.AIRSPACE))
        self.assertIsNotNone(encoding.get(f3, "TRANSCRIPT"))
        self.assertIsNotNone(encoding.get(f3, "MAC"))

    def test_keyack_carries_its_fields_in_the_specified_order(self):
        """
        Field order is part of what the signature covers, so the body the
        paper specifies and the body built here must be the same sequence.
        """
        _, _, (_, m2, _) = run(self.ac, self.gs)
        self.assertEqual(
            [name for name, _ in encoding.parse(m2)],
            ["ROLE", "TIMESTAMP", "FROM", "TO", "CREDENTIAL",
             "EPHEMERAL_KEY", H.AIRSPACE, "SIGNATURE"])

    def test_no_session_identifier_appears_anywhere(self):
        """Section 3.3.2: the key distinguishes sessions, no field names them."""
        _, _, msgs = run(self.ac, self.gs)
        for m in msgs:
            self.assertNotIn(b"SESSION_ID", m)
            self.assertNotIn(b"SESSION ID", m)

    def test_ephemeral_scalars_are_discarded_once_the_key_is_derived(self):
        run(self.ac, self.gs)
        self.assertIsNone(self.ac._scalar)
        self.assertIsNone(self.gs._scalar)

    def test_two_sessions_do_not_share_a_key(self):
        a1, _, _ = run(aircraft(self.ca), ground(self.ca))
        a2, _, _ = run(aircraft(self.ca), ground(self.ca))
        self.assertNotEqual(a1.key, a2.key)

    def test_the_same_pair_gets_a_fresh_key_each_time(self):
        """Ephemerals are fresh per session, so compromise of one exposes no other."""
        ca = self.ca
        a1, _, _ = run(aircraft(ca), ground(ca))
        a2, _, _ = run(aircraft(ca), ground(ca))
        self.assertNotEqual(a1.key, a2.key)

    def test_handshake_roles_are_not_subject_to_role_admission(self):
        """
        Section 3.3.1: "any principal holding a valid credential may establish
        a session". A station whose credential permits no CC subtype at all
        still completes the handshake.
        """
        ca = self.ca
        gs = H.Responder(**party(ca, "EBBR GND", ["KEYACK"], sector="EBBU"))
        a, g, _ = run(aircraft(ca), gs)
        self.assertEqual(a.key, g.key)


class TestRefusals(unittest.TestCase):
    def setUp(self):
        self.ca = authority()
        self.ac, self.gs = aircraft(self.ca), ground(self.ca)

    def _rejects(self, step, fn, *a, **kw):
        with self.assertRaises(Rejected) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.step, step)
        return cm.exception

    def test_malformed_message(self):
        self._rejects(Step.MALFORMED, self.gs.handle_key, b"garbage", NOW)

    def test_wrong_role(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self._rejects(Step.ROLE_UNKNOWN, self.ac.handle_keyack, m1, NOW)

    def test_message_addressed_to_someone_else(self):
        m1 = self.ac.build_key("EDGG GND", NOW)
        self._rejects(Step.ADDRESSEE, self.gs.handle_key, m1, NOW)

    def test_timestamp_outside_the_window(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self._rejects(Step.TIMESTAMP_WINDOW, self.gs.handle_key, m1, NOW + HOUR)

    def test_timestamp_in_the_future_outside_the_window(self):
        m1 = self.ac.build_key(self.gs.identity, NOW + HOUR)
        self._rejects(Step.TIMESTAMP_WINDOW, self.gs.handle_key, m1, NOW)

    def test_credential_from_an_unknown_issuer(self):
        other = authority("XX CAA")
        stranger = H.Initiator(**party(other, "OOXYZ", AIRCRAFT_ROLES))
        m1 = stranger.build_key(self.gs.identity, NOW)
        self._rejects(Step.ISSUER_UNKNOWN, self.gs.handle_key, m1, NOW)

    def test_expired_credential(self):
        ca = self.ca
        old = H.Initiator(**party(ca, "OOABC", AIRCRAFT_ROLES))
        m1 = old.build_key(self.gs.identity, NOW)
        # Two hours on, both the message window and the credential have gone;
        # the window is checked first, so widen it to reach the credential.
        self.gs.window = timedelta(days=1)
        self._rejects(Step.VALIDITY, self.gs.handle_key, m1, NOW + 2 * HOUR)

    def test_credential_naming_a_different_subject(self):
        ca = self.ca
        imposter = H.Initiator(**party(ca, "OOXYZ", AIRCRAFT_ROLES))
        m1 = imposter.build_key(self.gs.identity, NOW)
        m1 = m1.replace(b"FROM: OOXYZ", b"FROM: OOABC")
        self._rejects(Step.SUBJECT, self.gs.handle_key, m1, NOW)

    def test_altered_body_fails_the_message_signature(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        tampered = m1.replace(b"ROLE: KEY", b"ROLE: KEY")  # same length, no change
        tampered = tampered.replace(b"TO: EBBR GND", b"TO: EBBR TWR")
        # Addressee is checked before the signature, so address it correctly
        # and alter something the signature covers but no earlier check reads.
        m1b = self.ac.build_key(self.gs.identity, NOW)
        m1b = m1b.replace(b"EPHEMERAL_KEY: ", b"EPHEMERAL_KEY: ", 1)
        fields = encoding.parse(m1b)
        eph = encoding.require(fields, "EPHEMERAL_KEY")
        forged = P.b64u(bytes(32))
        m1b = m1b.replace(eph.encode(), forged.encode())
        self._rejects(Step.MESSAGE_SIGNATURE, self.gs.handle_key, m1b, NOW)

    # -- the airspace claim -------------------------------------------
    #
    # Two checks, different in kind. SECTOR is unconditional: the airspace a
    # station claims to be working must lie within the SECTOR its issuer
    # granted, and an aircraft establishes that from the message alone.
    # AIRSPACE is advisory: an aircraft holding published airspace data also
    # requires that the claim contain where it is.

    def test_keyack_states_the_airspace_the_station_works(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        self.assertEqual(
            encoding.require(encoding.parse(m2), H.AIRSPACE), "EBBU")

    def test_a_claim_beyond_the_grant_is_refused_without_any_airspace_data(self):
        """The property the design exists for: no equipage, still checked."""
        gs = _OverclaimingStation(
            **party(self.ca, "EBBR GND", GROUND_ROLES, sector="EBBU"))
        m1 = self.ac.build_key(gs.identity, NOW)
        gs.handle_key(m1, NOW)
        m2 = gs.build_keyack(NOW)
        self._rejects(Step.SECTOR, self.ac.handle_keyack, m2, NOW)

    def test_a_station_asked_to_claim_beyond_its_grant_refuses_to_answer(self):
        gs = H.Responder(airspace="EBBU",
                         **party(self.ca, "EBBR GND", GROUND_ROLES,
                                 sector="EBBU.NORTH"))
        m1 = self.ac.build_key(gs.identity, NOW)
        gs.handle_key(m1, NOW)
        self._rejects(Step.SECTOR, gs.build_keyack, NOW)

    def test_a_station_may_claim_less_than_its_grant(self):
        gs = ground(self.ca, sector="EBBU")
        gs.airspace = "EBBU.NORTH"
        m1 = self.ac.build_key(gs.identity, NOW)
        gs.handle_key(m1, NOW)
        m2 = gs.build_keyack(NOW)
        self.assertEqual(
            encoding.require(encoding.parse(m2), H.AIRSPACE), "EBBU.NORTH")
        self.ac.handle_keyack(m2, NOW, airspace="EBBU.NORTH.LOW")

    def test_a_claim_not_containing_the_aircraft_is_refused_where_it_can_tell(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        self._rejects(Step.AIRSPACE, self.ac.handle_keyack, m2, NOW, "EDGG")

    def test_the_advisory_check_is_not_made_without_airspace_data(self):
        """An aircraft that cannot place itself does not refuse on that."""
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        self.ac.handle_keyack(m2, NOW)  # no airspace argument

    def test_a_claim_containing_the_aircraft_is_accepted(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        self.ac.handle_keyack(m2, NOW, airspace="EBBU.NORTH")

    def test_keyack_without_a_claim_is_malformed(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        stripped = m2.replace(b"AIRSPACE: EBBU\r\n", b"")
        self._rejects(Step.MALFORMED, self.ac.handle_keyack, stripped, NOW)

    def test_a_claim_widened_in_transit_is_refused_before_the_signature(self):
        """
        Step 4 precedes step 5, so a claim altered to exceed the grant costs
        the receiver no signature verification. Both paths close; they close
        at different steps, and which step matters.
        """
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        forged = m2.replace(b"AIRSPACE: EBBU\r\n", b"AIRSPACE: EDGG\r\n")
        self.assertNotEqual(forged, m2)
        self._rejects(Step.SECTOR, self.ac.handle_keyack, forged, NOW)

    def test_a_claim_narrowed_in_transit_fails_the_message_signature(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        forged = m2.replace(b"AIRSPACE: EBBU\r\n", b"AIRSPACE: EBBU.SOUTH\r\n")
        self.assertNotEqual(forged, m2)
        self._rejects(Step.MESSAGE_SIGNATURE, self.ac.handle_keyack, forged, NOW)

    def test_keyconfirm_under_the_wrong_key_fails_the_tag(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        self.ac.handle_keyack(m2, NOW)
        m3, _ = self.ac.build_keyconfirm(NOW)
        # Re-tag the body under an unrelated key.
        body = encoding.authenticated_region(m3, H.MAC)
        forged = body + encoding.encode(
            [(H.MAC, P.b64u(P.mac(P.session_key(b"\x09" * 32), body)))]
        )
        self._rejects(Step.TAG, self.gs.handle_keyconfirm, forged, NOW)

    def test_keyconfirm_with_a_wrong_transcript_is_refused(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        self.ac.handle_keyack(m2, NOW)
        # A transcript the aircraft computes over a different first message:
        # correctly tagged under the agreed key, but not the exchange that ran.
        body = encoding.encode([
            ("ROLE", H.ROLE_KEYCONFIRM),
            ("TIMESTAMP", C._iso(NOW)),
            ("FROM", "OOABC"),
            ("TO", "EBBR GND"),
            ("TRANSCRIPT", P.b64u(P.transcript_hash(b"other", b"exchange"))),
        ])
        wire = body + encoding.encode(
            [(H.MAC, P.b64u(P.mac(self.ac._key, body)))]
        )
        self._rejects(Step.TRANSCRIPT, self.gs.handle_keyconfirm, wire, NOW)

    def test_keyconfirm_before_any_keyack(self):
        fresh = ground(self.ca)
        self._rejects(Step.SESSION_UNKNOWN, fresh.handle_keyconfirm, b"x", NOW)

    def test_a_substituted_ephemeral_breaks_the_confirmation(self):
        """
        Section 3.3.2: "an adversary substituting a different acknowledgement
        with a different ephemeral produces a transcript the station does not
        recognise." Here the adversary runs its own exchange with the station
        and relays its KEYCONFIRM; the station's transcript does not match.
        """
        ca = self.ca
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        self.ac.handle_keyack(m2, NOW)

        # A second, parallel exchange with the same station object is not
        # possible, so use a second station and relay its confirmation.
        gs2 = ground(ca)
        ac2 = aircraft(ca)
        n1 = ac2.build_key(gs2.identity, NOW)
        gs2.handle_key(n1, NOW)
        n2 = gs2.build_keyack(NOW)
        ac2.handle_keyack(n2, NOW)
        n3, _ = ac2.build_keyconfirm(NOW)
        self._rejects(Step.TAG, self.gs.handle_keyconfirm, n3, NOW)


class TestOrderOfChecks(unittest.TestCase):
    """The specified order is load-bearing: the earliest failure is reported."""

    def setUp(self):
        self.ca = authority()
        self.ac, self.gs = aircraft(self.ca), ground(self.ca)

    def test_window_is_checked_before_the_credential(self):
        other = authority("XX CAA")
        stranger = H.Initiator(**party(other, "OOXYZ", AIRCRAFT_ROLES))
        m1 = stranger.build_key(self.gs.identity, NOW)
        with self.assertRaises(Rejected) as cm:
            self.gs.handle_key(m1, NOW + HOUR)
        self.assertEqual(cm.exception.step, Step.TIMESTAMP_WINDOW)

    def test_role_is_checked_before_the_window(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        with self.assertRaises(Rejected) as cm:
            self.ac.handle_keyack(m1, NOW + HOUR)
        self.assertEqual(cm.exception.step, Step.ROLE_UNKNOWN)

    def test_tag_is_checked_before_the_transcript(self):
        m1 = self.ac.build_key(self.gs.identity, NOW)
        self.gs.handle_key(m1, NOW)
        m2 = self.gs.build_keyack(NOW)
        self.ac.handle_keyack(m2, NOW)
        body = encoding.encode([
            ("ROLE", H.ROLE_KEYCONFIRM),
            ("TIMESTAMP", C._iso(NOW)),
            ("FROM", "OOABC"),
            ("TO", "EBBR GND"),
            ("TRANSCRIPT", P.b64u(b"\x00" * 32)),
        ])
        wire = body + encoding.encode([(H.MAC, P.b64u(b"\x00" * 16))])
        with self.assertRaises(Rejected) as cm:
            self.gs.handle_keyconfirm(wire, NOW)
        self.assertEqual(cm.exception.step, Step.TAG)


if __name__ == "__main__":
    unittest.main()
