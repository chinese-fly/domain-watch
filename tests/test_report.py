"""Report rendering and end-to-end scanner tests."""

import tempfile
import unittest
from pathlib import Path

from dwatch.report import Row, render_json, render_markdown, render_table
from dwatch.resolver import FakeResolver
from dwatch.scanner import Scanner
from dwatch.store import Store


def row(domain, score=50, band="medium", rule="homoglyph", ips=("1.2.3.4",), reasons=("resolves",)):
    return Row(domain=domain, rule=rule, score=score, band=band,
               ips=tuple(ips), reasons=tuple(reasons))


class TestTableRender(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(render_table([]), "no resolving look-alikes")

    def test_sorted_by_score_desc(self):
        out = render_table([row("a.com", 10), row("b.com", 90, "high")])
        self.assertLess(out.index("b.com"), out.index("a.com"))

    def test_limit_applied_after_sort(self):
        rows = [row("low.com", 5), row("high.com", 95, "high")]
        out = render_table(rows, limit=1)
        self.assertIn("high.com", out)
        self.assertNotIn("low.com", out)

    def test_high_band_marked(self):
        out = render_table([row("bad.com", 80, "high")])
        self.assertIn("!!", out)

    def test_missing_ips_rendered_as_dash(self):
        out = render_table([row("x.com", ips=())])
        self.assertIn("-", out)

    def test_separator_matches_header_width(self):
        out = render_table([row("short.com"), row("a-much-longer-domain.com")])
        header, separator = out.splitlines()[0], out.splitlines()[1]
        self.assertEqual(len(separator), len(header))
        self.assertTrue(set(separator) == {"-"})

    def test_domain_column_starts_same_place(self):
        # The free-form ADDRESSES column can be shorter than the header, so
        # alignment is asserted on where the columns begin, not on line length.
        out = render_table([row("short.com"), row("a-much-longer-domain.com")])
        lines = out.splitlines()
        rule_col = [line.index("homoglyph") for line in lines[2:]]
        self.assertEqual(len(set(rule_col)), 1, lines)


class TestMarkdownRender(unittest.TestCase):
    def test_counts_in_header(self):
        out = render_markdown([row("a.com", 80, "high"), row("b.com", 50)], domain="example.com")
        self.assertIn("Resolving look-alikes: **2**", out)
        self.assertIn("High risk: **1**", out)
        self.assertIn("Medium risk: **1**", out)

    def test_empty_has_explicit_caveat(self):
        out = render_markdown([], domain="example.com")
        self.assertIn("not proof of safety", out)

    def test_table_rows_present(self):
        out = render_markdown([row("bad.com", 90, "high")], domain="example.com")
        self.assertIn("| 90 | `bad.com` |", out)

    def test_diff_section_when_provided(self):
        from dwatch.store import Diff, Observation
        appeared = Observation("new.com", "homoglyph", 80, "high", (), (), ())
        diff = Diff(appeared=[appeared], disappeared=[], rescored=[])
        out = render_markdown([row("new.com", 80, "high")], domain="example.com", diff=diff)
        self.assertIn("Changes since the previous run", out)
        self.assertIn("`new.com` appeared", out)

    def test_empty_diff_says_nothing_changed(self):
        from dwatch.store import Diff
        out = render_markdown([row("a.com")], domain="example.com",
                              diff=Diff([], [], []))
        self.assertIn("Nothing changed.", out)


class TestJsonRender(unittest.TestCase):
    def test_shape(self):
        payload = render_json([row("a.com", 80, "high")], domain="example.com")
        self.assertEqual(payload["domain"], "example.com")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["findings"][0]["domain"], "a.com")
        self.assertEqual(payload["findings"][0]["band"], "high")

    def test_no_changes_key_without_diff(self):
        self.assertNotIn("changes", render_json([row("a.com")], domain="x.com"))

    def test_changes_key_with_diff(self):
        from dwatch.store import Diff, Observation
        o = Observation("n.com", "homoglyph", 90, "high", (), (), ())
        payload = render_json([], domain="x.com", diff=Diff([o], [], []))
        self.assertEqual(payload["changes"]["appeared"], ["n.com"])


class TestScannerEndToEnd(unittest.TestCase):
    def test_only_resolving_filters_dead(self):
        resolver = FakeResolver({"examp1e.com": ("1.2.3.4",)})
        result = Scanner("example.com", resolver=resolver, rules=("homoglyph", "omission")).run()
        self.assertTrue(all(r.ips for r in result.rows))
        self.assertLess(len(result.rows), result.candidates)

    def test_include_dead_keeps_everything(self):
        resolver = FakeResolver({"examp1e.com": ("1.2.3.4",)})
        live = Scanner("example.com", resolver=resolver, rules=("omission",)).run()
        dead = Scanner("example.com", resolver=resolver, rules=("omission",),
                       only_resolving=False).run()
        self.assertGreater(len(dead.rows), len(live.rows))
        self.assertEqual(len(dead.rows), dead.candidates)

    def test_high_band_detected_for_impersonation(self):
        resolver = FakeResolver({
            "example.com": ("93.184.216.34",),
            "examp1e.com": ("93.184.216.34",),
        })
        result = Scanner("example.com", resolver=resolver, rules=("homoglyph",)).run()
        highs = [r for r in result.rows if r.band == "high"]
        self.assertEqual(len(highs), 1)
        self.assertEqual(highs[0].domain, "examp1e.com")

    def test_max_candidates_caps_work(self):
        resolver = FakeResolver({})
        result = Scanner("example.com", resolver=resolver, max_candidates=5,
                         only_resolving=False).run()
        self.assertEqual(result.candidates, 5)
        self.assertEqual(len(result.rows), 5)

    def test_scan_result_renders_all_formats(self):
        resolver = FakeResolver({"example.com": ("1.2.3.4",), "xample.com": ("5.6.7.8",)})
        result = Scanner("example.com", resolver=resolver, rules=("omission",)).run()
        self.assertIn("SCORE", result.table())
        self.assertIn("# Look-alike domain report", result.markdown())
        self.assertIn("findings", result.json())


class TestScannerWithStore(unittest.TestCase):
    def test_second_run_produces_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "h.sqlite3"
            rules = ("omission",)

            with Store(db) as store:
                Scanner("example.com", resolver=FakeResolver({"xample.com": ("1.2.3.4",)}),
                        rules=rules, store=store).run()

            with Store(db) as store:
                result = Scanner("example.com",
                                 resolver=FakeResolver({"xample.com": ("1.2.3.4",),
                                                        "eample.com": ("5.6.7.8",)}),
                                 rules=rules, store=store).run()
                self.assertIsNotNone(result.diff)
                appeared = [o.domain for o in result.diff.appeared]
                self.assertIn("eample.com", appeared)

    def test_first_run_has_no_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            with Store(Path(tmp) / "h.sqlite3") as store:
                result = Scanner("example.com",
                                 resolver=FakeResolver({"xample.com": ("1.2.3.4",)}),
                                 rules=("omission",), store=store).run()
                # One run recorded, so there is nothing to compare against yet.
                self.assertIsNone(result.diff)


if __name__ == "__main__":
    unittest.main()
