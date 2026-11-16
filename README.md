# domain-watch

Look-alike domain monitoring you can put on a cron.

[English](README.md) | [简体中文](README.zh-CN.md)

Most typosquatting tools are one-shot: you run them, you get a table, you close
the terminal. That answers "what exists right now" and nothing else. The
question a brand actually has to answer every morning is *"did anything
change since yesterday"* — and for that you need history, scoring, and a
report that fits in a ticket.

This does those three things.

## What it does

1. **Generates** every plausible variant of a domain across 15 permutation
   rules (bitsquatting, homoglyph, cyrillic, insertion, omission, transposition,
   hyphenation, subdomain, vowel-swap, plural, repetition, replacement,
   addition, dictionary, tld-swap).
2. **Resolves** them over DNS with a bounded thread pool.
3. **Scores** each live one against weighted signals, with the reasoning kept.
4. **Stores** every run in SQLite and diffs it against the previous run.
5. **Reports** as a terminal table, Markdown, or JSON.

## Quick start

```bash
python -m dwatch scan example.com
```

```text
   SCORE  DOMAIN        RULE           ADDRESSES
------------------------------------------------
!!    83  examp1e.com   homoglyph      93.184.216.34
!     48  exanple.com   homoglyph      45.33.32.156
      28  examp-le.com  hyphenation    45.33.32.157

251 candidates generated, 3 resolving
```

Second run, same database, produces a diff:

```bash
python -m dwatch diff example.com
```

```text
+ examp1e.co (score 48)
- oid-example.com (was 38)
~ example.net 20 -> 48
```

Other entry points:

```bash
python -m dwatch scan example.com --format markdown   # paste into a ticket
python -m dwatch scan example.com --format json       # feed a dashboard
python -m dwatch scan example.com --include-dead      # show unresolvable too
python -m dwatch history example.com                  # stored runs
python -m dwatch rules                                # list the 15 rules
```

## Measured results

Run against `github.com` on 2026-11-16, all 15 rules, default resolver:

```text
261 candidates generated, 130 resolving
```

Real output, truncated to the top of the table:

```text
   SCORE  DOMAIN      RULE           ADDRESSES
----------------------------------------------
!     48  eithub.com  bitsquatting   13.248.243.5, 76.223.105.230
!     48  fithub.com  bitsquatting   5.22.145.121, 5.22.145.16
!     48  gathub.com  bitsquatting   216.250.120.46
!     48  ghthub.com  bitsquatting   38.4.85.252
!     48  gi4hub.com  bitsquatting   177.210.210.253
!     48  gith5b.com  bitsquatting   54.198.53.48
!     48  githud.com  homoglyph      66.81.203.137
!     48  githuḅ.com  homoglyph      127.0.0.1
!     48  githüb.com  homoglyph      2.57.91.91
```

Two things worth noticing in that output, because they are the reason scoring
exists rather than a flat list:

- `githuḅ.com` resolves to `127.0.0.1`. That is not a website; it is a
  deliberate sinkhole or a misconfiguration, and it would sit unnoticed in an
  alphabetical dump of 130 rows.
- `githüb.com` and `githeb.com` resolve to the **same** address `2.57.91.91`.
  Two look-alikes on one host is a registration pattern, not a coincidence.

Test suite:

```text
$ python -m unittest discover -s tests -t .
Ran 108 tests in 0.104s
OK
```

## Scoring

Every point is traceable. `explain()` returns the breakdown, and the Markdown
report prints it in a `Why` column, so a finding can be defended rather than
asserted.

| Signal | Points | Rationale |
|---|---:|---|
| resolves | 20 | a dead candidate wastes nobody's time |
| accepts mail (MX) | 15 | phishing needs to receive, not just serve |
| shares origin IP with the brand | 15 | DNS pointed at real infrastructure |
| credential rule (homoglyph / cyrillic / bitsquatting) | 18 | built to be misread |
| ordinary typo rule | 8 | common, usually innocent |
| single edit from the label | 10 | closer spelling, easier mistake |
| suspicious TLD | 12 | prior, never decisive alone |
| **impersonation kit** (credential rule + MX or shared IP) | **+20** | the combination, not any single signal |

Bands: `high` ≥ 70, `medium` ≥ 40, `low` > 0, `info` = 0.

The combination rule exists because summing the parts under-counts the exact
case the tool is for. A homoglyph domain that is live, accepts mail, and points
at the brand's own address scores 68 from its parts alone — below `high` — while
a parked typo with a bad TLD can drift close to it. That is backwards. The
`impersonation kit` weight is the correction, and there is a test pinning it
(`test_homoglyph_on_real_ip_is_high`).

## Design notes

**Why the permutation engine is a separate module.** The obvious build keeps
generation, resolution and CLI in one script, and then the rules cannot be
asserted without network access. Here each rule is a pure function over a
label, so `tests/test_permute.py` pins exact output —
`transposition("abcdef")` must differ in exactly two adjacent positions, not
just "return something".

**Why a `Resolver` protocol instead of calling `socket` inline.** Tests use
`FakeResolver` and never touch the network. `FakeResolver` in the test suite is
what makes 108 tests run in 0.1s.

**Why SQLite and not JSON files.** A run is 130 rows; twenty runs is 2,600.
Diffs need indexed lookups by domain, and pruning needs a delete that does not
rewrite the whole file. `prune(keep=20)` is called after every scan so the
database has a ceiling.

**Why the score is not a probability.** These weights are ordinal. They answer
"which of these two do I look at first", not "this domain is 62% malicious".
Pretending otherwise would make the report look more authoritative than the
evidence supports.

## What it does not do

- **No screenshotting or content analysis.** A parked page and a live phishing
  kit score the same if their DNS looks the same. Adding a headless-browser
  pass is the obvious next step and is deliberately not here.
- **No certificate transparency or WHOIS correlation.** Registration date is
  one of the strongest signals available and this does not read it. The
  resolver interface would take a second source without restructuring.
- **The score is not calibrated on real data.** The thresholds are judgement.
  Anyone deploying this should re-tune `WEIGHTS` against their own traffic
  before paging anyone at 3am on a `high`.
- **`tld-swap` needs an explicit pool.** Without `--tld-pool` it produces
  nothing, rather than generating all 1,500 TLDs and hammering the resolver.
- **No rate limiting.** A 261-candidate scan issues 261 lookups in a burst.
  Run it from infrastructure you are allowed to generate DNS traffic from.

## Rule design

The 15 rules are grouped by what they exploit, and each one is answerable to a
test that pins exact output rather than "returns something":

| group | rules | what it exploits |
|---|---|---|
| look-alike | `homoglyph`, `cyrillic`, `bitsquatting` | the reader, not the machine |
| finger slip | `insertion`, `omission`, `repetition`, `transposition`, `replacement` | QWERTY adjacency |
| word sense | `hyphenation`, `vowel-swap`, `plural`, `addition`, `dictionary` | how brands get written out loud |
| infrastructure | `subdomain`, `tld-swap` | people who type the whole URL |

Two deliberate divergences from the naive formulation of these rules:

- **`plural` appends.** Inserting the suffix at an arbitrary middle offset
  (`example` → `exasmple`) produces strings no one types. It appends, and for
  hyphenated labels it inflects each segment in turn.
- **`tld-swap` needs an explicit pool.** Without `--tld-pool` it emits nothing
  rather than generating all 1,500 TLDs and hammering the resolver.

Apache-2.0.

## Requirements

Python 3.10+. Standard library only — no `requests`, no `dnspython`, no
`tldextract`. This is deliberate: a monitoring script that fails to start
because a dependency resolved differently is worse than a slightly weaker
suffix table.

## Layout

```text
dwatch/
  glyphs.py     substitution tables
  permute.py    15 rules + hostname splitting
  resolver.py   threaded DNS, swappable for tests
  score.py      weighted signals, auditable
  store.py      SQLite history + diff
  report.py     table / markdown / json
  scanner.py    orchestration
  cli.py        argument parsing
tests/          108 tests, no network
```
