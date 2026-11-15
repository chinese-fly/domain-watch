"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .permute import ALL_RULES
from .scanner import Scanner
from .store import Store

DEFAULT_DB = "dwatch.sqlite3"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dwatch",
        description="Monitor look-alike domains: generate, resolve, score, diff.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run a scan")
    scan.add_argument("domain", help="root domain, e.g. example.com")
    scan.add_argument("--db", default=DEFAULT_DB, help=f"history database (default {DEFAULT_DB})")
    scan.add_argument("--no-store", action="store_true", help="do not write history")
    scan.add_argument("--rules", default="", help=f"comma separated, default: all ({len(ALL_RULES)} rules)")
    scan.add_argument("--words", default="", help="comma separated words for the dictionary rule")
    scan.add_argument("--tld-pool", default="", help="comma separated TLDs for tld-swap")
    scan.add_argument("--format", choices=("table", "markdown", "json"), default="table")
    scan.add_argument("--limit", type=int, default=0, help="show only the top N by score")
    scan.add_argument("--include-dead", action="store_true",
                      help="also report candidates that do not resolve")
    scan.add_argument("--max-candidates", type=int, default=0,
                      help="cap the candidate set (useful while tuning rules)")

    hist = sub.add_parser("history", help="show stored runs for a domain")
    hist.add_argument("domain")
    hist.add_argument("--db", default=DEFAULT_DB)
    hist.add_argument("--limit", type=int, default=10)

    diff = sub.add_parser("diff", help="compare the two newest runs")
    diff.add_argument("domain")
    diff.add_argument("--db", default=DEFAULT_DB)

    rules = sub.add_parser("rules", help="list available permutation rules")
    rules.add_argument("--format", choices=("text", "json"), default="text")

    return p


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def cmd_scan(args: argparse.Namespace) -> int:
    rules = _split_csv(args.rules) or ALL_RULES
    unknown = [r for r in rules if r not in ALL_RULES and r != "original"]
    if unknown:
        print(f"unknown rule(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"available: {', '.join(ALL_RULES)}", file=sys.stderr)
        return 2

    store = None
    if not args.no_store:
        store = Store(Path(args.db))

    try:
        scanner = Scanner(
            domain=args.domain,
            words=_split_csv(args.words),
            tld_pool=_split_csv(args.tld_pool),
            rules=tuple(rules),
            store=store,
            only_resolving=not args.include_dead,
            max_candidates=args.max_candidates,
        )
        result = scanner.run()
    finally:
        if store is not None:
            store.close()

    if args.format == "json":
        print(json.dumps(result.json(), indent=2))
    elif args.format == "markdown":
        print(result.markdown())
    else:
        print(result.table(limit=args.limit))
        print()
        print(f"{result.candidates} candidates generated, {len(result.rows)} resolving")
        if result.diff is not None and not result.diff.empty:
            print(f"changed since last run: +{len(result.diff.appeared)} "
                  f"-{len(result.diff.disappeared)} ~{len(result.diff.rescored)}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    with Store(Path(args.db)) as store:
        runs = store.latest_runs(args.domain, limit=args.limit)
    if not runs:
        print(f"no recorded runs for {args.domain}")
        return 0
    print(f"{'RUN':>4}  {'STARTED':<21}  {'CANDIDATES':>10}  {'RESOLVING':>9}  RULES")
    for run in runs:
        print(f"{run.id:>4}  {run.started_at:<21}  {run.candidates:>10}  "
              f"{run.resolving:>9}  {len(run.rules)} rules")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    with Store(Path(args.db)) as store:
        diff = store.diff(args.domain)
    if diff is None:
        print("need at least two recorded runs to diff")
        return 1
    if diff.empty:
        print("no changes")
        return 0
    for obs in diff.appeared:
        print(f"+ {obs.domain} (score {obs.score})")
    for obs in diff.disappeared:
        print(f"- {obs.domain} (was {obs.score})")
    for before, after in diff.rescored:
        print(f"~ {after.domain} {before.score} -> {after.score}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    if args.format == "json":
        print(json.dumps(list(ALL_RULES), indent=2))
    else:
        for name in ALL_RULES:
            print(name)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"scan": cmd_scan, "history": cmd_history,
                "diff": cmd_diff, "rules": cmd_rules}
    return handlers[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
