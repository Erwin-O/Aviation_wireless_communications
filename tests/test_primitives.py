"""Tests for the primitives, against the equations of Sections 3.3.1-3.3.3."""

import unittest

from protocol import primitives as P


class TestBase64(unittest.TestCase):
    def test_round_trip_without_padding(self):
        raw = bytes(range(32))
        text = P.b64u(raw)
        self.assertNotIn("=", text)
        self.assertEqual(P.unb64u(text), raw)

    def test_non_canonical_encoding_is_rejected(self):
        # Padding re-added by hand is not what the encoder produces.
        with self.assertRaises(ValueError):
            P.unb64u(P.b64u(b"\x00" * 16) + "=")

    def test_zero_challenge_matches_the_example_width(self):
        # The SA example in Section 3.3.1 prints a 22-character LAST_EXEC.
        self.assertEqual(len(P.b64u(P.ZERO_CHALLENGE)), 22)


class TestSignatures(unittest.TestCase):
    def test_sign_and_verify(self):
        sk, pk = P.generate_signing_key()
        msg = b"ROLE: KEY\r"
        self.assertTrue(P.verify_signature(pk, msg, P.sign(sk, msg)))

    def test_verification_fails_on_a_changed_message(self):
        sk, pk = P.generate_signing_key()
        sig = P.sign(sk, b"ROLE: KEY\r")
        self.assertFalse(P.verify_signature(pk, b"ROLE: KEYACK\r", sig))

    def test_verification_returns_false_rather_than_raising(self):
        _, pk = P.generate_signing_key()
        self.assertFalse(P.verify_signature(pk, b"x", b"not a signature"))


class TestEphemeralDerivation(unittest.TestCase):
    """Equation (1), and the property that makes G9 attainable."""

    def test_derivation_is_deterministic(self):
        r, sk = P.random_r(), P.generate_kex_key()[0]
        self.assertEqual(
            P.derive_ephemeral_scalar(r, sk), P.derive_ephemeral_scalar(r, sk)
        )

    def test_scalar_is_a_valid_x25519_key(self):
        scalar = P.derive_ephemeral_scalar(P.random_r(), P.generate_kex_key()[0])
        self.assertEqual(len(scalar), 32)
        self.assertEqual(len(P.public_from_scalar(scalar)), 32)

    def test_known_r_does_not_determine_the_scalar(self):
        # An adversary predicting r in full still cannot predict the scalar
        # without the long-term secret.
        r = P.random_r()
        a = P.derive_ephemeral_scalar(r, P.generate_kex_key()[0])
        b = P.derive_ephemeral_scalar(r, P.generate_kex_key()[0])
        self.assertNotEqual(a, b)

    def test_r_must_be_256_bits(self):
        with self.assertRaises(ValueError):
            P.derive_ephemeral_scalar(b"\x00" * 16, b"\x01" * 32)


class TestKeyAgreement(unittest.TestCase):
    """Equations (2) and (3)."""

    def setUp(self):
        self.a = P.derive_ephemeral_scalar(P.random_r(), P.generate_kex_key()[0])
        self.b = P.derive_ephemeral_scalar(P.random_r(), P.generate_kex_key()[0])

    def test_both_parties_reach_the_same_shared_value(self):
        A, B = P.public_from_scalar(self.a), P.public_from_scalar(self.b)
        self.assertEqual(P.dh(self.a, B), P.dh(self.b, A))

    def test_session_keys_agree_and_have_the_stated_length(self):
        A, B = P.public_from_scalar(self.a), P.public_from_scalar(self.b)
        k = P.session_key(P.dh(self.a, B))
        self.assertEqual(k, P.session_key(P.dh(self.b, A)))
        self.assertEqual(len(k), P.SESSION_KEY_BYTES)

    def test_a_different_session_yields_a_different_key(self):
        c = P.derive_ephemeral_scalar(P.random_r(), P.generate_kex_key()[0])
        k1 = P.session_key(P.dh(self.a, P.public_from_scalar(self.b)))
        k2 = P.session_key(P.dh(self.a, P.public_from_scalar(c)))
        self.assertNotEqual(k1, k2)


class TestDomainSeparation(unittest.TestCase):
    """The same hash applied to two purposes must not produce a shared value."""

    def test_ephemeral_and_challenge_differ_on_the_same_inputs(self):
        r, sk = P.random_r(), P.generate_kex_key()[0]
        self.assertNotEqual(
            P.derive_ephemeral_scalar(r, sk)[: P.CHALLENGE_BYTES],
            P.derive_challenge(r, sk),
        )

    def test_labels_are_prefix_free(self):
        labels = [P.L_EPH, P.L_CH, P.L_TR, P.L_ACK]
        for i, x in enumerate(labels):
            for j, y in enumerate(labels):
                if i != j:
                    self.assertFalse(x.startswith(y), f"{x!r} starts with {y!r}")


class TestMac(unittest.TestCase):
    def test_tag_verifies(self):
        key = P.session_key(b"\x01" * 32)
        body = b"ROLE: SA\r"
        self.assertTrue(P.verify_mac(key, body, P.mac(key, body)))

    def test_tag_is_the_stated_width(self):
        key = P.session_key(b"\x01" * 32)
        self.assertEqual(len(P.mac(key, b"x")), P.TAG_BYTES)

    def test_tag_fails_under_another_session_key(self):
        body = b"ROLE: SA\r"
        k1, k2 = P.session_key(b"\x01" * 32), P.session_key(b"\x02" * 32)
        self.assertFalse(P.verify_mac(k2, body, P.mac(k1, body)))

    def test_tag_fails_on_a_changed_body(self):
        key = P.session_key(b"\x01" * 32)
        tag = P.mac(key, b"ROLE: SA\r")
        self.assertFalse(P.verify_mac(key, b"ROLE: ACK\r", tag))


class TestChallenge(unittest.TestCase):
    """Equation (6)."""

    def test_challenges_are_fresh(self):
        sk = P.generate_kex_key()[0]
        self.assertNotEqual(P.new_challenge(sk), P.new_challenge(sk))

    def test_challenge_width_matches_the_example(self):
        sk = P.generate_kex_key()[0]
        self.assertEqual(len(P.b64u(P.new_challenge(sk))), 22)

    def test_known_r_does_not_determine_the_challenge(self):
        r = P.random_r()
        self.assertNotEqual(
            P.derive_challenge(r, P.generate_kex_key()[0]),
            P.derive_challenge(r, P.generate_kex_key()[0]),
        )


class TestTranscript(unittest.TestCase):
    """Equation (5): h covers both preceding bodies, so order matters."""

    def test_transcript_is_order_sensitive(self):
        self.assertNotEqual(
            P.transcript_hash(b"A", b"B"), P.transcript_hash(b"B", b"A")
        )

    def test_boundary_between_the_two_bodies_is_ambiguous(self):
        """
        KNOWN SPEC ISSUE, documented here rather than silently patched.

        Equation (5) concatenates the two bodies with no length prefix and no
        separator, so h(x, yz) == h(xy, z): the split between m_KEY and
        m_KEYACK is not determined by the hash input. Each body is a complete
        encoded message, which makes a shuffle hard to realise, but it is not
        excluded by the construction, and the confirmation is supposed to tie
        the parties to *the whole exchange*.

        The fix is one line in both the paper and `transcript_hash`: prefix
        each body with its length, or separate them with a reserved byte. This
        test asserts the current, specified behaviour so that changing the
        construction fails here and the paper gets changed with it.
        """
        self.assertEqual(
            P.transcript_hash(b"KEY", b"ACKBODY"),
            P.transcript_hash(b"KEYACK", b"BODY"),
        )


if __name__ == "__main__":
    unittest.main()
