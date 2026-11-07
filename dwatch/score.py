"""Risk scoring for a resolving look-alike domain.

dnstwist prints a table and leaves the judgement to the reader. A monitoring
job cannot do that -- it needs a number so it can page someone at 3am without
waking them for a parked domain. The score here is intentionally small and
auditable rather than a black box: every point is traceable to one signal,
and `explain()` returns the breakdown so a report can show its work.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .permute import Candidate
from .resolver import Resolution

# Weights are ordinal, not calibrated. They answer "which of these two should
# I look at first", not "this domain has a 62% chance of being malicious".
WEIGHTS = {
    "resolves": 20,
    "has_aaaa_only": 5,
    "mx_present": 15,
    "credential_rule": 18,
    "idn_rule": 22,
    "typo_rule": 8,
    "low_edit_distance": 10,
    "suspicious_tld": 12,
    "shared_ip_with_original": 15,
    # Not a signal on its own: this fires only when a credential-style
    # look-alike is ALSO live and pointed at real infrastructure, i.e. the
    # full phishing setup. Summing the parts under-counts that case -- it
    # lands just under `high` -- and the whole point of the tool is to rank
    # that configuration first.
    "impersonation_kit": 20,
}

# Rules that exist specifically to make a human misread the hostname. These
# are worth more than an addition rule because there is no benign reason to
# register one.
CREDENTIAL_RULES = frozenset({"homoglyph", "cyrillic", "bitsquatting"})
TYPO_RULES = frozenset({"omission", "insertion", "replacement", "transposition",
                        "repetition", "hyphenation", "vowel-swap", "plural"})

# TLDs with a reputation for cheap throwaway registrations. This is a prior,
# not evidence; it never outweighs a real signal on its own.
SUSPICIOUS_TLDS = frozenset({"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
                             "work", "link", "surf", "rest", "buzz", "cyou"})


@dataclass
class RiskScore:
    score: int
    band: str
    reasons: list[tuple[str, int]] = field(default_factory=list)

    def explain(self) -> str:
        if not self.reasons:
            return "no signals"
        return ", ".join(f"{name} +{points}" for name, points in self.reasons)


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance, iterative with two rows."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,          # deletion
                current[j - 1] + 1,       # insertion
                previous[j - 1] + (ca != cb),  # substitution
            ))
        previous = current
    return previous[-1]


def band_for(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def score_candidate(
    candidate: Candidate,
    resolution: Resolution | None,
    *,
    original_label: str = "",
    original_ips: frozenset[str] = frozenset(),
) -> RiskScore:
    """Score one look-alike. `resolution` may be None for an unresolvable host."""
    reasons: list[tuple[str, int]] = []
    fired: list[str] = []  # WEIGHTS keys, so the combination rule can look back

    def add(name: str, base: str) -> None:
        reasons.append((name, WEIGHTS[base]))
        fired.append(base)

    if resolution is not None and resolution.resolves:
        add("resolves", "resolves")
        if not resolution.a and resolution.aaaa:
            add("ipv6-only", "has_aaaa_only")
        if resolution.mx:
            add("accepts mail", "mx_present")
        if original_ips and set(resolution.a) & original_ips:
            add("shares origin IP", "shared_ip_with_original")

    if candidate.rule in CREDENTIAL_RULES:
        add(f"look-alike rule ({candidate.rule})", "credential_rule")
    elif candidate.rule in TYPO_RULES:
        add(f"typo rule ({candidate.rule})", "typo_rule")

    tld = candidate.domain.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        add(f"tld .{tld}", "suspicious_tld")

    if original_label and candidate.rule not in ("tld-swap", "original"):
        label = candidate.domain.split(".")[0] if candidate.domain.count(".") == 1 else ""
        if label and len(label) == len(original_label) and _edit_distance(label, original_label) == 1:
            add("single character away", "low_edit_distance")

    total = sum(points for _name, points in reasons)

    # Combination rule: a look-alike built to be misread, that is live, and
    # that is wired to the brand's own address or to a mail exchanger. Each
    # part alone is survivable; together it is a ready-to-run phishing kit.
    if "credential_rule" in fired and ({"shared_ip_with_original", "mx_present"} & set(fired)):
        points = WEIGHTS["impersonation_kit"]
        total += points
        reasons.append(("impersonation kit (look-alike + live mail/origin)", points))

    return RiskScore(score=total, band=band_for(total), reasons=reasons)
