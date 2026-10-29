"""Permutation rule tests.

Every rule is a pure function over a label, so these assert exact output
rather than "returns something". That is the whole reason the engine was
pulled out of the original single-file script.
"""

import unittest

from dwatch.permute import (
    ALL_RULES,
    Candidate,
    Permuter,
    RULE_TABLE,
    addition,
    bitsquatting,
    dedupe_sorted,
    dictionary,
    hyphenation,
    omission,
    plural,
    repetition,
    split_hostname,
    transposition,
    vowel_swap,
)


class TestSplitHostname(unittest.TestCase):
    def test_simple(self):
        s = split_hostname("example.com")
        self.assertEqual((s.subdomain, s.label, s.tld), ("", "example", "com"))

    def test_subdomain_preserved(self):
        s = split_hostname("mail.example.com")
        self.assertEqual((s.subdomain, s.label, s.tld), ("mail", "example", "com"))

    def test_compound_suffix_not_eaten(self):
        # `co.uk` must stay together or `example` becomes the TLD.
        s = split_hostname("shop.example.co.uk")
        self.assertEqual((s.subdomain, s.label, s.tld), ("shop", "example", "co.uk"))

    def test_deep_subdomain(self):
        s = split_hostname("a.b.example.com")
        self.assertEqual((s.subdomain, s.label, s.tld), ("a.b", "example", "com"))

    def test_uppercase_and_trailing_dot(self):
        s = split_hostname("Example.COM.")
        self.assertEqual((s.subdomain, s.label, s.tld), ("", "example", "com"))

    def test_rejects_bare_label(self):
        with self.assertRaises(ValueError):
            split_hostname("localhost")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            split_hostname("")

    def test_join_roundtrip(self):
        s = split_hostname("mail.example.co.uk")
        self.assertEqual(s.join(), "mail.example.co.uk")


class TestBitsquatting(unittest.TestCase):
    def test_single_bit_flip_produces_expected(self):
        # 'a' is 0x61; flipping bit 1 gives 0x60 ('`') which is invalid,
        # flipping bit 2 gives 0x63 ('c').
        out = set(bitsquatting("a"))
        self.assertIn("c", out)
        self.assertIn("e", out)  # 0x61 ^ 4 = 0x65

    def test_never_emits_non_alnum(self):
        for text in ("example", "acme-corp", "site123"):
            for candidate in bitsquatting(text):
                self.assertTrue(all(ch.isalnum() or ch == "-" for ch in candidate),
                                f"{candidate!r} from {text!r}")

    def test_same_length(self):
        for candidate in bitsquatting("example"):
            self.assertEqual(len(candidate), len("example"))

    def test_differs_in_exactly_one_position(self):
        base = "example"
        for candidate in bitsquatting(base):
            diffs = [i for i, (a, b) in enumerate(zip(base, candidate)) if a != b]
            self.assertEqual(len(diffs), 1)


class TestSimpleRules(unittest.TestCase):
    def test_omission_count(self):
        # One deletion per position.
        self.assertEqual(len(list(omission("abc"))), 3)
        self.assertIn("bc", set(omission("abc")))

    def test_repetition(self):
        self.assertIn("aabc", set(repetition("abc")))
        self.assertEqual(len(list(repetition("abc"))), 3)

    def test_transposition(self):
        self.assertIn("bac", set(transposition("abc")))

    def test_transposition_adjacent_only(self):
        for candidate in transposition("abcdef"):
            diffs = [i for i, (a, b) in enumerate(zip("abcdef", candidate)) if a != b]
            self.assertEqual(len(diffs), 2)
            self.assertEqual(diffs[1] - diffs[0], 1)

    def test_hyphenation_positions(self):
        out = set(hyphenation("abcd"))
        self.assertEqual(out, {"a-bcd", "ab-cd", "abc-d"})

    def test_vowel_swap_keeps_non_vowels(self):
        for candidate in vowel_swap("banana"):
            for i, ch in enumerate("banana"):
                if ch not in "aeiou":
                    self.assertEqual(candidate[i], ch)

    def test_vowel_swap_excludes_original_vowel(self):
        self.assertNotIn("a", set(vowel_swap("a")))

    def test_plural_appends_suffix(self):
        self.assertEqual(set(plural("example")), {"examples"})

    def test_plural_es_for_sibilant(self):
        self.assertEqual(set(plural("box")), {"boxes"})
        self.assertEqual(set(plural("class")), {"classes"})

    def test_plural_inflects_each_hyphenated_part(self):
        # Whole label -> `acme-corps`; per-part -> `acmes-corp` (the second
        # part lands on the same string as the whole-label form).
        self.assertEqual(set(plural("acme-corp")), {"acme-corps", "acmes-corp"})

    def test_addition_appends_every_alnum(self):
        out = set(addition("ab"))
        self.assertIn("ab0", out)
        self.assertIn("abz", out)
        self.assertEqual(len(out), 36)

    def test_addition_infixes_into_hyphenated(self):
        out = set(addition("a-b"))
        self.assertTrue(any(c.startswith("a") and c[1] != "-" for c in out), out)


class TestDictionary(unittest.TestCase):
    def test_glues_on_both_sides(self):
        out = set(dictionary("acme", words=("login",)))
        self.assertEqual(out, {"acme-login", "acmelogin", "login-acme", "loginacme"})

    def test_skips_word_equal_to_label(self):
        self.assertEqual(set(dictionary("acme", words=("acme",))), set())

    def test_skips_when_label_wraps_word(self):
        # 'acmeacme' already starts and ends with the word.
        self.assertEqual(set(dictionary("acmeacme", words=("acme",))), set())

    def test_empty_word_ignored(self):
        self.assertEqual(set(dictionary("acme", words=("",))), set())

    def test_hyphenated_label_uses_parts(self):
        out = set(dictionary("acme-corp", words=("login",)))
        self.assertIn("acme-login", out)
        self.assertIn("login-corp", out)


class TestPermuter(unittest.TestCase):
    def test_original_is_included_first(self):
        cands = Permuter("example.com").generate(["original"])
        self.assertEqual([c.domain for c in cands], ["example.com"])
        self.assertEqual(cands[0].rule, "original")

    def test_single_rule(self):
        cands = Permuter("example.com").generate(["omission"])
        self.assertTrue(all(c.rule == "omission" for c in cands))
        self.assertIn("xample.com", {c.domain for c in cands})

    def test_unknown_rule_raises(self):
        with self.assertRaises(ValueError) as ctx:
            Permuter("example.com").generate(["nope"])
        self.assertIn("nope", str(ctx.exception))

    def test_no_self_reference(self):
        for candidate in Permuter("example.com").generate():
            self.assertNotEqual(candidate.domain, "example.com")

    def test_bare_label_filtered(self):
        # `subdomain` can produce a bare label like `exa.mple` which, joined,
        # is still a valid FQDN, but the rule must never emit one-label hosts.
        for candidate in Permuter("example.com").generate(["subdomain"]):
            self.assertGreaterEqual(candidate.domain.count("."), 1)

    def test_deterministic_across_runs(self):
        first = [c.domain for c in Permuter("example.com").generate()]
        second = [c.domain for c in Permuter("example.com").generate()]
        self.assertEqual(first, second)

    def test_sorted_output(self):
        cands = [c.domain for c in Permuter("example.com").generate()]
        self.assertEqual(cands, sorted(cands))

    def test_tld_swap_respects_pool(self):
        cands = Permuter("example.com", tld_pool=("net", "org")).generate(["tld-swap"])
        self.assertEqual({c.domain for c in cands}, {"example.net", "example.org"})

    def test_tld_swap_excludes_current(self):
        cands = Permuter("example.com", tld_pool=("com", "net")).generate(["tld-swap"])
        self.assertNotIn("example.com", {c.domain for c in cands})

    def test_subdomain_preserved_in_output(self):
        cands = Permuter("mail.example.com").generate(["omission"])
        self.assertTrue(all(c.domain.startswith("mail.") for c in cands))

    def test_all_rules_produce_output(self):
        cands = Permuter("example.com", words=("login",), tld_pool=("net",)).generate()
        produced = {c.rule for c in cands}
        # `cyrillic` only fires when a Latin letter has a Cyrillic twin.
        self.assertTrue(set(ALL_RULES) - {"cyrillic"} <= produced, set(ALL_RULES) - produced)
        self.assertIn("cyrillic", produced)

    def test_every_rule_callable_standalone(self):
        for name, func in RULE_TABLE.items():
            with self.subTest(rule=name):
                kwargs = {"label": "example", "tld": "com", "words": ("x",),
                          "tld_pool": ("net",)}
                list(func(**kwargs))  # must not raise


class TestDedupe(unittest.TestCase):
    def test_first_rule_wins_by_name(self):
        cands = [Candidate("a.com", "omission"), Candidate("a.com", "addition")]
        out = dedupe_sorted(cands)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rule, "addition")  # alphabetically first

    def test_preserves_distinct(self):
        cands = [Candidate("a.com", "omission"), Candidate("b.com", "omission")]
        self.assertEqual(len(dedupe_sorted(cands)), 2)

    def test_sorted(self):
        cands = [Candidate("c.com", "x"), Candidate("a.com", "x"), Candidate("b.com", "x")]
        self.assertEqual([c.domain for c in dedupe_sorted(cands)],
                         ["a.com", "b.com", "c.com"])


class TestCandidateSetShape(unittest.TestCase):
    def test_size_is_stable(self):
        # Guards against a rule becoming non-deterministic or exploding.
        count = len(Permuter("example.com", words=("login", "secure"),
                             tld_pool=("net", "org", "co")).generate())
        self.assertGreater(count, 200)
        self.assertLess(count, 2000)
        self.assertEqual(
            count,
            len(Permuter("example.com", words=("login", "secure"),
                         tld_pool=("net", "org", "co")).generate()),
        )

    def test_short_domain_does_not_crash(self):
        for domain in ("ab.io", "a.co", "xy.dev"):
            with self.subTest(domain=domain):
                list(Permuter(domain).generate())


if __name__ == "__main__":
    unittest.main()
