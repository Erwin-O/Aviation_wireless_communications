"""
Tests for credentials and the verification order (Section 3.3.2).

The order is specified, and the paper says it "is the point at which an
implementation is most likely to err". So these tests assert the step at which
a message is discarded, not merely that it is discarded: a credential refused
for the wrong reason demonstrates nothing about the check under test.
"""

import unittest
from datetime import datetime, timedelta, timezone

from protocol import credentials as C
from protocol import encoding, primitives as P

NOW = datetime(2025, 11, 17, 4, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


def _authority():
    sk, pk = P.generate_signing_key()
    return {"issuer": "BE CAA", "sk": sk, "anchors": {"BE CAA": pk}}


def _subject(authority, name, roles, sector=None, not_before=None, not_after=None):
    sign_sk, sign_pk = P.generate_signing_key()
    raw = C.issue(
        issuer=authority["issuer"],
        subject=name,
        verify_key=sign_pk,
        not_before=not_before or (NOW - HOUR),
        not_after=not_after or (NOW + HOUR),
        permitted_roles=roles,
        issuer_signing_key=authority["sk"],
        sector=sector,
    )
    return {"name": name, "sk": sign_sk, "pk": sign_pk, "raw": raw}


class TestIssuing(unittest.TestCase):
    def test_a_credential_parses_and_carries_its_fields(self):
        ca = _authority()
        ac = _subject(ca, "OOABC", ["KEY", "KEYCONFIRM", "SA", "ACK", "CC:REQUEST"])
        cred = C.parse(ac["raw"])
        self.assertEqual(cred.issuer, "BE CAA")
        self.assertEqual(cred.subject, "OOABC")
        self.assertEqual(cred.verify_key, ac["pk"])
        self.assertIn("SA", cred.permitted_roles)
        self.assertIsNone(cred.sector)

    def test_a_ground_credential_carries_a_sector(self):
        ca = _authority()
        gs = _subject(ca, "EBBR GND", ["KEYACK", "CC:CLEARANCE"], sector="EBBU")
        self.assertEqual(C.parse(gs["raw"]).sector, "EBBU")

    def test_an_empty_role_list_is_refused_at_issue(self):
        ca = _authority()
        with self.assertRaises(ValueError):
            _subject(ca, "OOABC", [])

    def test_an_inverted_validity_interval_is_refused_at_issue(self):
        ca = _authority()
        with self.assertRaises(ValueError):
            _subject(ca, "OOABC", ["SA"], not_before=NOW + HOUR, not_after=NOW - HOUR)


class TestVerificationOrder(unittest.TestCase):
    """One test per step, each asserting the step it is meant to fail at."""

    def setUp(self):
        self.ca = _authority()
        self.other_ca = _authority()
        self.ac = _subject(self.ca, "OOABC", ["KEY", "SA", "ACK", "CC:REQUEST"])
        self.body = encoding.encode([("ROLE", "KEY"), ("FROM", "OOABC")])
        self.sig = P.sign(self.ac["sk"], self.body)

    def _verify(self, **over):
        raw = over.pop("raw", self.ac["raw"])
        kw = dict(
            trust_anchors=self.ca["anchors"],
            now=NOW,
            expect_subject="OOABC",
            signed_message=self.body,
            message_signature=self.sig,
        )
        kw.update(over)
        return C.verify(raw, **kw)

    def test_a_good_credential_verifies(self):
        cred = self._verify()
        self.assertEqual(cred.subject, "OOABC")

    def test_malformed_credential_fails_first(self):
        with self.assertRaises(C.CredentialRejected) as cm:
            C.verify(
                b"not a credential",
                trust_anchors=self.ca["anchors"],
                now=NOW,
                expect_subject="OOABC",
            )
        self.assertEqual(cm.exception.step, C.Step.CREDENTIAL_MALFORMED)

    def test_unknown_issuer_fails_at_step_one(self):
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(trust_anchors={})
        self.assertEqual(cm.exception.step, C.Step.ISSUER_UNKNOWN)

    def test_credential_signed_by_the_wrong_authority_fails_at_step_one(self):
        # Same issuer name, different key: the name is not the anchor.
        forged = _subject(
            {"issuer": "BE CAA", "sk": self.other_ca["sk"]}, "OOABC", ["SA"]
        )
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(raw=forged["raw"])
        self.assertEqual(cm.exception.step, C.Step.ISSUER_SIGNATURE)

    def test_altered_credential_fails_at_step_one(self):
        tampered = self.ac["raw"].replace(b"SUBJECT: OOABC", b"SUBJECT: OOXYZ")
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(raw=tampered, expect_subject="OOXYZ")
        self.assertEqual(cm.exception.step, C.Step.ISSUER_SIGNATURE)

    def test_expired_credential_fails_at_step_two(self):
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(now=NOW + 2 * HOUR)
        self.assertEqual(cm.exception.step, C.Step.VALIDITY)

    def test_not_yet_valid_credential_fails_at_step_two(self):
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(now=NOW - 2 * HOUR)
        self.assertEqual(cm.exception.step, C.Step.VALIDITY)

    def test_wrong_subject_fails_at_step_three(self):
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(expect_subject="OOXYZ")
        self.assertEqual(cm.exception.step, C.Step.SUBJECT)

    def test_sector_outside_scope_fails_at_step_four(self):
        ca = _authority()
        gs = _subject(ca, "EBBR GND", ["KEYACK", "CC:CLEARANCE"], sector="EBBU")
        body = encoding.encode([("ROLE", "KEYACK"), ("FROM", "EBBR GND")])
        with self.assertRaises(C.CredentialRejected) as cm:
            C.verify(
                gs["raw"],
                trust_anchors=ca["anchors"],
                now=NOW,
                expect_subject="EBBR GND",
                airspace="EDGG",
                signed_message=body,
                message_signature=P.sign(gs["sk"], body),
            )
        self.assertEqual(cm.exception.step, C.Step.SECTOR)

    def test_bad_message_signature_fails_at_step_five(self):
        other_sk, _ = P.generate_signing_key()
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(message_signature=P.sign(other_sk, self.body))
        self.assertEqual(cm.exception.step, C.Step.MESSAGE_SIGNATURE)

    def test_expiry_is_checked_before_the_subject(self):
        """
        The order is load-bearing, so a message failing two checks must report
        the earlier one. An expired credential with the wrong subject is
        rejected as expired.
        """
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(now=NOW + 2 * HOUR, expect_subject="OOXYZ")
        self.assertEqual(cm.exception.step, C.Step.VALIDITY)

    def test_subject_is_checked_before_the_message_signature(self):
        other_sk, _ = P.generate_signing_key()
        with self.assertRaises(C.CredentialRejected) as cm:
            self._verify(
                expect_subject="OOXYZ", message_signature=P.sign(other_sk, self.body)
            )
        self.assertEqual(cm.exception.step, C.Step.SUBJECT)


class TestRoleAdmission(unittest.TestCase):
    def test_permitted_role_is_admitted(self):
        ca = _authority()
        gs = _subject(ca, "EBBR GND", ["KEYACK", "CC:CLEARANCE"], sector="EBBU")
        self.assertTrue(C.parse(gs["raw"]).permits("CC:CLEARANCE"))

    def test_unpermitted_subtype_is_refused(self):
        """A station permitted to clear is not thereby permitted to nominate."""
        ca = _authority()
        gs = _subject(ca, "EBBR GND", ["KEYACK", "CC:CLEARANCE"], sector="EBBU")
        self.assertFalse(C.parse(gs["raw"]).permits("CC:CONTACT"))

    def test_the_family_does_not_imply_its_subtypes(self):
        ca = _authority()
        gs = _subject(ca, "EBBR GND", ["CC"], sector="EBBU")
        self.assertFalse(C.parse(gs["raw"]).permits("CC:CLEARANCE"))


class TestSectorCovering(unittest.TestCase):
    def test_exact_match_covers(self):
        self.assertTrue(C.default_sector_covers("EBBU", "EBBU"))

    def test_subdivision_is_covered(self):
        self.assertTrue(C.default_sector_covers("EBBU", "EBBU.NORTH"))

    def test_a_neighbour_is_not_covered(self):
        self.assertFalse(C.default_sector_covers("EBBU", "EDGG"))

    def test_a_prefix_without_the_separator_is_not_covered(self):
        self.assertFalse(C.default_sector_covers("EBB", "EBBU"))


if __name__ == "__main__":
    unittest.main()
