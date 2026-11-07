"""Scoring tests.

The score is a product decision, so the tests pin the behaviour that matters:
a credential-style look-alike that also shares the brand's IP must outrank a
plain parked typo, and an unresolvable host must never score as high as a
live one.
"""

import unittest

from dwatch.permute import Candidate
from dwatch.resolver import Resolution
from dwatch.score import (
    SUSPICIOUS_TLDS,
    band_for,
    score_candidate,
)


def res(domain, a=(), aaaa=(), mx=(), ns=()):
    return Resolution(domain=domain, a=tuple(a), aaaa=tuple(aaaa),
                      mx=tuple(mx), ns=tuple(ns))


class TestBandThresholds(unittest.TestCase):
    def test_low(self):
        self.assertEqual(band_for(1), "low")
        self.assertEqual(band_for(39), "low")

    def test_medium(self):
        self.assertEqual(band_for(40), "medium")
        self.assertEqual(band_for(69), "medium")

    def test_high(self):
        self.assertEqual(band_for(70), "high")
        self.assertEqual(band_for(500), "high")

    def test_zero_is_info(self):
        self.assertEqual(band_for(0), "info")


class TestScoreSignals(unittest.TestCase):
    def test_unresolvable_scores_zero(self):
        score = score_candidate(Candidate("examp1e.com", "homoglyph"), None)
        # The rule still counts even without resolution.
        self.assertEqual(score.score, 18)
        self.assertEqual([n for n, _ in score.reasons], ["look-alike rule (homoglyph)"])

    def test_nxdomain_resolution_contributes_nothing(self):
        score = score_candidate(Candidate("x.com", "omission"),
                                Resolution(domain="x.com", error="nxdomain"))
        self.assertNotIn("resolves", [n for n, _ in score.reasons])

    def test_resolves_adds_weight(self):
        plain = score_candidate(Candidate("x.com", "omission"), None)
        live = score_candidate(Candidate("x.com", "omission"), res("x.com", a=["1.2.3.4"]))
        self.assertEqual(live.score - plain.score, 20)

    def test_mx_is_a_stronger_signal_than_mere_resolution(self):
        a_only = score_candidate(Candidate("x.com", "omission"), res("x.com", a=["1.2.3.4"]))
        with_mx = score_candidate(Candidate("x.com", "omission"),
                                  res("x.com", a=["1.2.3.4"], mx=["10 mail.x.com"]))
        self.assertGreater(with_mx.score, a_only.score)

    def test_shared_ip_with_original(self):
        original = frozenset({"93.184.216.34"})
        shared = score_candidate(Candidate("x.com", "omission"),
                                 res("x.com", a=["93.184.216.34"]),
                                 original_ips=original)
        other = score_candidate(Candidate("x.com", "omission"),
                                res("x.com", a=["45.33.32.156"]),
                                original_ips=original)
        self.assertEqual(shared.score - other.score, 15)

    def test_ipv6_only_flagged(self):
        score = score_candidate(Candidate("x.com", "omission"),
                                res("x.com", aaaa=["2606:2800::1"]))
        self.assertIn("ipv6-only", [n for n, _ in score.reasons])

    def test_credential_rule_outweighs_typo_rule(self):
        homoglyph = score_candidate(Candidate("x.com", "homoglyph"),
                                    res("x.com", a=["1.2.3.4"]))
        transposition = score_candidate(Candidate("x.com", "transposition"),
                                        res("x.com", a=["1.2.3.4"]))
        self.assertGreater(homoglyph.score, transposition.score)

    def test_suspicious_tld(self):
        tld = sorted(SUSPICIOUS_TLDS)[0]
        score = score_candidate(Candidate(f"acme.{tld}", "tld-swap"),
                                res(f"acme.{tld}", a=["1.2.3.4"]))
        self.assertTrue(any("tld" in name for name, _ in score.reasons))

    def test_reputable_tld_not_flagged(self):
        score = score_candidate(Candidate("acme.co.uk", "tld-swap"),
                                res("acme.co.uk", a=["1.2.3.4"]))
        self.assertFalse(any("tld ." in name for name, _ in score.reasons))


class TestHighestRiskCombination(unittest.TestCase):
    def test_homoglyph_on_real_ip_is_high(self):
        """The scenario the tool exists to surface."""
        score = score_candidate(
            Candidate("examp1e.com", "homoglyph"),
            res("examp1e.com", a=["93.184.216.34"], mx=["10 mx.examp1e.com"]),
            original_ips=frozenset({"93.184.216.34"}),
        )
        self.assertEqual(score.band, "high", score.explain())

    def test_parked_typo_stays_low(self):
        score = score_candidate(Candidate("exampel.com", "transposition"),
                                res("exampel.com", a=["45.33.32.156"]))
        self.assertEqual(score.band, "low", score.explain())

    def test_explain_lists_every_reason(self):
        score = score_candidate(
            Candidate("examp1e.com", "homoglyph"),
            res("examp1e.com", a=["93.184.216.34"], mx=["10 mx.x"]),
            original_ips=frozenset({"93.184.216.34"}),
        )
        text = score.explain()
        self.assertIn("resolves", text)
        self.assertIn("homoglyph", text)
        # resolves, mx, shared ip, credential rule, impersonation kit
        self.assertEqual(len(score.reasons), 5)

    def test_empty_explain(self):
        score = score_candidate(Candidate("x.com", "unknown-rule"), None)
        self.assertEqual(score.explain(), "no signals")


class TestImpersonationKitRule(unittest.TestCase):
    """The combination signal: misreadable + live + wired to the brand."""

    def test_credential_rule_alone_does_not_fire(self):
        score = score_candidate(Candidate("examp1e.com", "homoglyph"),
                                res("examp1e.com", a=["45.33.32.156"]))
        self.assertNotIn("impersonation", score.explain())

    def test_credential_plus_shared_ip_fires(self):
        score = score_candidate(
            Candidate("examp1e.com", "homoglyph"),
            res("examp1e.com", a=["93.184.216.34"]),
            original_ips=frozenset({"93.184.216.34"}),
        )
        self.assertIn("impersonation kit", score.explain())

    def test_credential_plus_mx_fires(self):
        score = score_candidate(
            Candidate("examp1e.com", "homoglyph"),
            res("examp1e.com", a=["45.33.32.156"], mx=["10 mx.examp1e.com"]),
        )
        self.assertIn("impersonation kit", score.explain())

    def test_typo_rule_plus_mx_does_not_fire(self):
        # A typo domain with mail is normal squatter behaviour, not a kit.
        score = score_candidate(
            Candidate("exampel.com", "transposition"),
            res("exampel.com", a=["45.33.32.156"], mx=["10 mx.exampel.com"]),
        )
        self.assertNotIn("impersonation kit", score.explain())


class TestEditDistanceGate(unittest.TestCase):
    def test_single_character_away_is_bonused(self):
        score = score_candidate(Candidate("exampl3.com", "replacement"),
                                res("exampl3.com", a=["1.2.3.4"]),
                                original_label="example")
        self.assertIn("single character away", [n for n, _ in score.reasons])

    def test_longer_distance_not_bonused(self):
        score = score_candidate(Candidate("exampl3x.com", "addition"),
                                res("exampl3x.com", a=["1.2.3.4"]),
                                original_label="example")
        self.assertNotIn("single character away", [n for n, _ in score.reasons])


if __name__ == "__main__":
    unittest.main()
