"""SQLite-backed run history so a scan can be diffed against the last one.

This is the piece that turns a one-shot script into something you can run on
a cron. dnstwist has no persistence at all -- you get a table on stdout and
that is the end of it. Without history, "did anything change overnight" is
unanswerable, which is the only question a monitoring job actually has to
answer.

Schema is deliberately narrow: one row per (run, domain) observation, plus a
runs table for the metadata. Old runs are pruned, not vacuumed, so the file
does not grow without bound.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    domain      TEXT NOT NULL,
    rules       TEXT NOT NULL,
    candidates  INTEGER NOT NULL,
    resolving   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    domain      TEXT NOT NULL,
    rule        TEXT NOT NULL,
    score       INTEGER NOT NULL,
    band        TEXT NOT NULL,
    reasons     TEXT NOT NULL,
    ips         TEXT NOT NULL,
    mx          TEXT NOT NULL,
    PRIMARY KEY (run_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_obs_domain ON observations(domain);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Observation:
    domain: str
    rule: str
    score: int
    band: str
    reasons: tuple[str, ...]
    ips: tuple[str, ...]
    mx: tuple[str, ...]


@dataclass
class RunRecord:
    id: int
    started_at: str
    domain: str
    rules: tuple[str, ...]
    candidates: int
    resolving: int


@dataclass
class Diff:
    """What changed between two runs of the same domain."""

    appeared: list[Observation]
    disappeared: list[Observation]
    rescored: list[tuple[Observation, Observation]]  # (before, after)

    @property
    def empty(self) -> bool:
        return not (self.appeared or self.disappeared or self.rescored)


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # -- writes -----------------------------------------------------------

    def record_run(self, domain: str, rules: Sequence[str],
                   candidates: int, observations: Iterable[Observation]) -> int:
        obs = list(observations)
        cur = self._conn.execute(
            "INSERT INTO runs (started_at, domain, rules, candidates, resolving) "
            "VALUES (?, ?, ?, ?, ?)",
            (utcnow(), domain, ",".join(rules), candidates, len(obs)),
        )
        run_id = int(cur.lastrowid)
        self._conn.executemany(
            "INSERT INTO observations (run_id, domain, rule, score, band, reasons, ips, mx) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (run_id, o.domain, o.rule, o.score, o.band,
                 json.dumps(list(o.reasons)), json.dumps(list(o.ips)), json.dumps(list(o.mx)))
                for o in obs
            ],
        )
        self._conn.commit()
        return run_id

    def prune(self, domain: str, keep: int = 20) -> int:
        """Drop all but the newest `keep` runs for `domain`."""
        rows = self._conn.execute(
            "SELECT id FROM runs WHERE domain = ? ORDER BY id DESC", (domain,)
        ).fetchall()
        stale = [r["id"] for r in rows[keep:]]
        if not stale:
            return 0
        placeholders = ",".join("?" * len(stale))
        self._conn.execute(f"DELETE FROM observations WHERE run_id IN ({placeholders})", stale)
        self._conn.execute(f"DELETE FROM runs WHERE id IN ({placeholders})", stale)
        self._conn.commit()
        return len(stale)

    # -- reads ------------------------------------------------------------

    def latest_runs(self, domain: str, limit: int = 2) -> list[RunRecord]:
        rows = self._conn.execute(
            "SELECT * FROM runs WHERE domain = ? ORDER BY id DESC LIMIT ?", (domain, limit)
        ).fetchall()
        return [
            RunRecord(
                id=r["id"], started_at=r["started_at"], domain=r["domain"],
                rules=tuple(r["rules"].split(",")) if r["rules"] else (),
                candidates=r["candidates"], resolving=r["resolving"],
            )
            for r in rows
        ]

    def observations_for(self, run_id: int) -> dict[str, Observation]:
        rows = self._conn.execute(
            "SELECT * FROM observations WHERE run_id = ?", (run_id,)
        ).fetchall()
        out: dict[str, Observation] = {}
        for r in rows:
            out[r["domain"]] = Observation(
                domain=r["domain"], rule=r["rule"], score=r["score"], band=r["band"],
                reasons=tuple(json.loads(r["reasons"])), ips=tuple(json.loads(r["ips"])),
                mx=tuple(json.loads(r["mx"])),
            )
        return out

    def diff(self, domain: str) -> Diff | None:
        """Compare the two newest runs. Returns None when there is nothing to compare."""
        runs = self.latest_runs(domain, limit=2)
        if len(runs) < 2:
            return None
        after = self.observations_for(runs[0].id)
        before = self.observations_for(runs[1].id)
        appeared = [after[d] for d in sorted(after) if d not in before]
        disappeared = [before[d] for d in sorted(before) if d not in after]
        rescored = [
            (before[d], after[d])
            for d in sorted(after)
            if d in before and before[d].score != after[d].score
        ]
        return Diff(appeared=appeared, disappeared=disappeared, rescored=rescored)

    def domain_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0])
