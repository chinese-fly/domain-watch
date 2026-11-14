"""Report rendering: table for a terminal, Markdown for a ticket.

Kept as pure functions over data so the output can be snapshot-tested without
capturing stdout.
"""

from __future__ import annotations

from dataclasses import dataclass

from .score import RiskScore
from .store import Diff, Observation


@dataclass
class Row:
    domain: str
    rule: str
    score: int
    band: str
    ips: tuple[str, ...]
    reasons: tuple[str, ...]

    @classmethod
    def from_observation(cls, obs: Observation) -> "Row":
        return cls(domain=obs.domain, rule=obs.rule, score=obs.score, band=obs.band,
                   ips=obs.ips, reasons=obs.reasons)


BAND_MARK = {"high": "!!", "medium": "! ", "low": "  ", "info": "  "}


def render_table(rows: list[Row], limit: int = 0) -> str:
    """Fixed-width table. `limit` truncates after the highest scores."""
    if not rows:
        return "no resolving look-alikes"

    ordered = sorted(rows, key=lambda r: (-r.score, r.domain))
    if limit:
        ordered = ordered[:limit]

    width = max(len(r.domain) for r in ordered)
    # The ADDRESSES column is free-form, so the rule is only applied to the
    # fixed-width part. The separator has to match the header it underlines,
    # not the longest body row.
    header = f"{'':2} {'SCORE':>5}  {'DOMAIN':<{width}}  {'RULE':<13}  ADDRESSES"
    lines = [header, "-" * len(header)]
    for row in ordered:
        addrs = ", ".join(row.ips) if row.ips else "-"
        lines.append(f"{BAND_MARK.get(row.band, '  ')} {row.score:>5}  "
                     f"{row.domain:<{width}}  {row.rule:<13}  {addrs}")
    return "\n".join(lines)


def render_markdown(rows: list[Row], *, domain: str, diff: Diff | None = None,
                    generated_at: str = "") -> str:
    """Markdown body suitable for pasting into a ticket or a client report."""
    ordered = sorted(rows, key=lambda r: (-r.score, r.domain))
    high = [r for r in ordered if r.band == "high"]
    medium = [r for r in ordered if r.band == "medium"]

    out = [f"# Look-alike domain report: {domain}", ""]
    if generated_at:
        out += [f"Generated {generated_at}", ""]

    out += [
        f"- Resolving look-alikes: **{len(ordered)}**",
        f"- High risk: **{len(high)}**",
        f"- Medium risk: **{len(medium)}**",
        "",
    ]

    if diff is not None:
        out += ["## Changes since the previous run", ""]
        if diff.empty:
            out += ["Nothing changed.", ""]
        else:
            out += [f"- New: **{len(diff.appeared)}**",
                    f"- Gone: **{len(diff.disappeared)}**",
                    f"- Score changed: **{len(diff.rescored)}**", ""]
            for obs in diff.appeared:
                out.append(f"- `{obs.domain}` appeared (score {obs.score})")
            for obs in diff.disappeared:
                out.append(f"- `{obs.domain}` disappeared (was {obs.score})")
            for before, after in diff.rescored:
                arrow = "up" if after.score > before.score else "down"
                out.append(f"- `{after.domain}` scored {arrow}: {before.score} -> {after.score}")
            out.append("")

    out += ["## Findings", ""]
    if not ordered:
        out += ["No look-alike domains resolved. That is not proof of safety -- "
                "it only means none of the generated candidates are currently live.", ""]
        return "\n".join(out)

    out += ["| Score | Domain | Rule | Addresses | Why |", "|---:|---|---|---|---|"]
    for row in ordered:
        why = "; ".join(row.reasons) if row.reasons else "-"
        addrs = ", ".join(row.ips) if row.ips else "-"
        out.append(f"| {row.score} | `{row.domain}` | {row.rule} | {addrs} | {why} |")
    out.append("")
    return "\n".join(out)


def render_json(rows: list[Row], *, domain: str, diff: Diff | None = None) -> dict:
    payload: dict = {
        "domain": domain,
        "count": len(rows),
        "findings": [
            {
                "domain": r.domain,
                "rule": r.rule,
                "score": r.score,
                "band": r.band,
                "addresses": list(r.ips),
                "reasons": list(r.reasons),
            }
            for r in sorted(rows, key=lambda x: (-x.score, x.domain))
        ],
    }
    if diff is not None:
        payload["changes"] = {
            "appeared": [o.domain for o in diff.appeared],
            "disappeared": [o.domain for o in diff.disappeared],
            "rescored": [
                {"domain": a.domain, "before": b.score, "after": a.score}
                for b, a in diff.rescored
            ],
        }
    return payload
