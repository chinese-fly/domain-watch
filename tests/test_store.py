"""Storage tests -- the history/diff behaviour that a cron job depends on."""

import tempfile
import unittest
from pathlib import Path

from dwatch.store import Observation, Store, Diff


def obs(domain, score=50, rule="homoglyph", band="medium", ips=("1.2.3.4",)):
    return Observation(domain=domain, rule=rule, score=score, band=band,
                       reasons=("resolves +20",), ips=tuple(ips), mx=())


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "test.sqlite3"
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()
        self._tmp.cleanup()


class TestRecording(StoreTestCase):
    def test_record_and_read_back(self):
        run_id = self.store.record_run("example.com", ("homoglyph",), 10,
                                       [obs("examp1e.com")])
        self.assertGreater(run_id, 0)
        found = self.store.observations_for(run_id)
        self.assertIn("examp1e.com", found)
        self.assertEqual(found["examp1e.com"].score, 50)

    def test_roundtrips_reasons_and_ips(self):
        run_id = self.store.record_run("example.com", ("homoglyph",), 1,
                                       [obs("examp1e.com", ips=("1.2.3.4", "5.6.7.8"))])
        found = self.store.observations_for(run_id)["examp1e.com"]
        self.assertEqual(found.reasons, ("resolves +20",))
        self.assertEqual(found.ips, ("1.2.3.4", "5.6.7.8"))

    def test_multiple_runs_accumulate(self):
        for _ in range(3):
            self.store.record_run("example.com", ("omission",), 5, [obs("xample.com")])
        self.assertEqual(self.store.domain_count(), 3)

    def test_latest_runs_newest_first(self):
        first = self.store.record_run("example.com", ("a",), 1, [])
        second = self.store.record_run("example.com", ("b",), 2, [])
        runs = self.store.latest_runs("example.com", limit=2)
        self.assertEqual([r.id for r in runs], [second, first])

    def test_latest_runs_scoped_to_domain(self):
        self.store.record_run("a.com", ("a",), 1, [])
        self.store.record_run("b.com", ("a",), 1, [])
        self.assertEqual(len(self.store.latest_runs("a.com", limit=10)), 1)

    def test_rules_roundtrip(self):
        run_id = self.store.record_run("example.com", ("omission", "homoglyph"), 1, [])
        run = self.store.latest_runs("example.com", limit=1)[0]
        self.assertEqual(run.id, run_id)
        self.assertEqual(run.rules, ("omission", "homoglyph"))


class TestPrune(StoreTestCase):
    def test_keeps_newest_n(self):
        ids = [self.store.record_run("example.com", ("a",), 1, []) for _ in range(5)]
        removed = self.store.prune("example.com", keep=2)
        self.assertEqual(removed, 3)
        remaining = [r.id for r in self.store.latest_runs("example.com", limit=10)]
        self.assertEqual(sorted(remaining), sorted(ids[-2:]))

    def test_noop_when_under_limit(self):
        self.store.record_run("example.com", ("a",), 1, [])
        self.assertEqual(self.store.prune("example.com", keep=5), 0)

    def test_prune_removes_observations_too(self):
        old = self.store.record_run("example.com", ("a",), 1, [obs("x.com")])
        self.store.record_run("example.com", ("a",), 1, [obs("y.com")])
        self.store.record_run("example.com", ("a",), 1, [obs("z.com")])
        self.store.prune("example.com", keep=1)
        self.assertEqual(self.store.observations_for(old), {})


class TestDiff(StoreTestCase):
    def test_requires_two_runs(self):
        self.store.record_run("example.com", ("a",), 1, [obs("x.com")])
        self.assertIsNone(self.store.diff("example.com"))

    def test_empty_when_identical(self):
        for _ in range(2):
            self.store.record_run("example.com", ("a",), 1, [obs("x.com")])
        diff = self.store.diff("example.com")
        self.assertIsNotNone(diff)
        self.assertTrue(diff.empty)

    def test_detects_appearance(self):
        self.store.record_run("example.com", ("a",), 1, [obs("x.com")])
        self.store.record_run("example.com", ("a",), 2, [obs("x.com"), obs("y.com")])
        diff = self.store.diff("example.com")
        self.assertEqual([o.domain for o in diff.appeared], ["y.com"])
        self.assertEqual(diff.disappeared, [])

    def test_detects_disappearance(self):
        self.store.record_run("example.com", ("a",), 2, [obs("x.com"), obs("y.com")])
        self.store.record_run("example.com", ("a",), 1, [obs("x.com")])
        diff = self.store.diff("example.com")
        self.assertEqual([o.domain for o in diff.disappeared], ["y.com"])

    def test_detects_rescore(self):
        self.store.record_run("example.com", ("a",), 1, [obs("x.com", score=30)])
        self.store.record_run("example.com", ("a",), 1, [obs("x.com", score=75, band="high")])
        diff = self.store.diff("example.com")
        self.assertEqual(len(diff.rescored), 1)
        before, after = diff.rescored[0]
        self.assertEqual((before.score, after.score), (30, 75))

    def test_unchanged_score_is_not_a_change(self):
        self.store.record_run("example.com", ("a",), 1, [obs("x.com", score=30)])
        self.store.record_run("example.com", ("a",), 1, [obs("x.com", score=30)])
        self.assertTrue(self.store.diff("example.com").empty)


class TestPersistence(unittest.TestCase):
    def test_survives_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "s.sqlite3"
            with Store(db) as store:
                store.record_run("example.com", ("a",), 1, [obs("x.com")])
            with Store(db) as store:
                self.assertEqual(store.domain_count(), 1)
                self.assertEqual(len(store.latest_runs("example.com")), 1)

    def test_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "nested" / "deeper" / "s.sqlite3"
            with Store(db):
                pass
            self.assertTrue(db.exists())


if __name__ == "__main__":
    unittest.main()
