"""Scan orchestration: permute -> resolve -> score -> store -> report."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .permute import ALL_RULES, Candidate, Permuter, dedupe_sorted, split_hostname
from .report import Row, render_json, render_markdown, render_table
from .resolver import DnsResolver, Resolver
from .score import score_candidate
from .store import Observation, Store, utcnow


@dataclass
class ScanResult:
    domain: str
    rules: tuple[str, ...]
    candidates: int
    rows: list[Row]
    run_id: int | None = None
    diff = None  # set by Scanner when history exists

    @property
    def high(self) -> list[Row]:
        return [r for r in self.rows if r.band == "high"]

    def table(self, limit: int = 0) -> str:
        return render_table(self.rows, limit=limit)

    def markdown(self) -> str:
        return render_markdown(self.rows, domain=self.domain, diff=self.diff,
                               generated_at=utcnow())

    def json(self) -> dict:
        return render_json(self.rows, domain=self.domain, diff=self.diff)


@dataclass
class Scanner:
    """Runs one scan. Nothing here writes to stdout."""

    domain: str
    words: tuple[str, ...] = ()
    tld_pool: tuple[str, ...] = ()
    rules: tuple[str, ...] = ALL_RULES
    resolver: Resolver | None = None
    store: Store | None = None
    only_resolving: bool = True
    max_candidates: int = 0
    _result: ScanResult | None = field(default=None, init=False, repr=False)

    def _candidates(self) -> list[Candidate]:
        permuter = Permuter(self.domain, words=self.words, tld_pool=self.tld_pool)
        produced = permuter.generate(self.rules)
        if self.max_candidates:
            produced = produced[:self.max_candidates]
        return dedupe_sorted(produced)

    def run(self) -> ScanResult:
        candidates = self._candidates()
        resolver = self.resolver or DnsResolver()

        # The root domain is resolved alongside the candidates even though it
        # is usually not one of them -- without its addresses we cannot tell a
        # parked look-alike from one that points at the real infrastructure.
        lookups = list(dict.fromkeys([self.domain, *(c.domain for c in candidates)]))
        resolutions = resolver.resolve_many(lookups)

        original = resolutions.get(self.domain)
        original_ips = frozenset(original.a) if original else frozenset()
        # Needed by the edit-distance signal: a candidate that is one
        # character away from the brand label is worth more than one that is
        # four characters away, and without this the score ignores that.
        original_label = split_hostname(self.domain).label

        observations: list[Observation] = []
        rows: list[Row] = []

        for candidate in candidates:
            resolution = resolutions.get(candidate.domain)
            if self.only_resolving and (resolution is None or not resolution.resolves):
                continue
            risk = score_candidate(candidate, resolution,
                                   original_label=original_label,
                                   original_ips=original_ips)
            ips = resolution.a if resolution else ()
            mx = resolution.mx if resolution else ()
            observations.append(Observation(
                domain=candidate.domain, rule=candidate.rule, score=risk.score,
                band=risk.band, reasons=tuple(f"{n} +{p}" for n, p in risk.reasons),
                ips=ips, mx=mx,
            ))
            rows.append(Row(domain=candidate.domain, rule=candidate.rule,
                            score=risk.score, band=risk.band, ips=ips,
                            reasons=tuple(n for n, _ in risk.reasons)))

        result = ScanResult(domain=self.domain, rules=tuple(self.rules),
                            candidates=len(candidates), rows=rows)

        if self.store is not None:
            result.run_id = self.store.record_run(
                self.domain, self.rules, len(candidates), observations
            )
            result.diff = self.store.diff(self.domain)
            self.store.prune(self.domain, keep=20)

        self._result = result
        return result
