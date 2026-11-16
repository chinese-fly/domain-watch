"""Domain permutation engine.

Every rule here is a pure function over a label, which is the whole point:
generation is the part that has to be right, and it is also the part that is
impossible to assert if generation, resolution and CLI live in one module.
With the split, `tests/test_permute.py` can pin exact output for each rule and
run 46 cases in a tenth of a second without touching a socket.

One design note that cost a test to find: iterating keyboard layouts in the
outer loop and characters in the inner loop yields the same domain more than
once when two layouts share a key. Each rule deduplicates its own output
instead of relying on a set at the end, so a rule's output size is
deterministic and can be asserted.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from .glyphs import (
    GLYPHS_ASCII,
    GLYPHS_IDN_BY_TLD,
    GLYPHS_UNICODE,
    KEYBOARDS,
    LATIN_TO_CYRILLIC,
)

# A hostname that a registry would plausibly accept. Deliberately loose: this
# runs before punycode encoding, so it must let non-ASCII labels through.
_FQDN = re.compile(r"^(?!-)[\w\-]{1,63}(?<!-)(\.(?!-)[\w\-]{1,63}(?<!-))+$", re.UNICODE)

_ALNUM_DASH = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_DIGIT_AND_LOWER = tuple(chr(c) for c in (*range(48, 58), *range(97, 123)))


@dataclass(frozen=True)
class Candidate:
    """One generated domain plus the rule that produced it."""

    domain: str
    rule: str

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.domain


@dataclass
class Split:
    """A hostname broken into the three parts the rules operate on."""

    subdomain: str
    label: str
    tld: str

    def join(self, label: str | None = None, tld: str | None = None) -> str:
        parts = [self.subdomain, label if label is not None else self.label,
                 tld if tld is not None else self.tld]
        return ".".join(p for p in parts if p)


# --------------------------------------------------------------------------
# hostname splitting
# --------------------------------------------------------------------------

# Second-level labels that are really part of the public suffix. A full PSL
# would be the correct answer; this covers the ccTLD shapes that show up in
# practice without pulling in a dependency.
_COMPOUND_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.br", "net.br", "org.br",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za",
    "co.in", "net.in", "org.in",
    "com.mx", "com.tr", "com.sg", "com.hk", "com.tw", "com.ar",
    "co.kr", "or.kr", "co.il", "com.my", "com.ph", "com.vn", "com.pk",
    "com.ua", "com.pl", "com.es", "com.pt", "com.ru",
}


def split_hostname(host: str) -> Split:
    """Split `host` into (subdomain, registrable label, public suffix).

    >>> split_hostname("mail.example.co.uk")
    Split(subdomain='mail', label='example', tld='co.uk')
    """
    host = host.strip().strip(".").lower()
    if not host:
        raise ValueError("empty hostname")

    labels = host.split(".")
    if len(labels) < 2:
        raise ValueError(f"not a hostname: {host!r}")

    # Longest public suffix match, capped at three labels.
    for size in (3, 2):
        if len(labels) > size:
            suffix = ".".join(labels[-size:])
            if suffix in _COMPOUND_SUFFIX:
                return Split(".".join(labels[:-size - 1]), labels[-size - 1], suffix)

    return Split(".".join(labels[:-2]), labels[-2], labels[-1])


# --------------------------------------------------------------------------
# individual rules -- each one is a pure function
# --------------------------------------------------------------------------

def bitsquatting(label: str, **_kw) -> Iterator[str]:
    """Flip a single bit of one character. Catches memory-corruption style typos."""
    for index, char in enumerate(label):
        for mask in (1, 2, 4, 8, 16, 32, 64, 128):
            flipped = chr(ord(char) ^ mask)
            if flipped in _ALNUM_DASH:
                yield label[:index] + flipped + label[index + 1:]


def homoglyph(label: str, tld: str = "", **_kw) -> Iterator[str]:
    """Swap characters for visually identical ones from other scripts."""
    table: dict[str, Iterable[str]] = {}
    for source in (GLYPHS_ASCII, GLYPHS_IDN_BY_TLD.get(tld, GLYPHS_UNICODE)):
        for key, values in source.items():
            table.setdefault(key, [])
            table[key] = list(dict.fromkeys([*table[key], *values]))

    def swaps(text: str) -> Iterator[str]:
        for index, char in enumerate(text):
            for glyph in table.get(char, ()):
                yield text[:index] + glyph + text[index + 1:]
        # Two-character look-alikes ("rn" -> "m") need a windowed pass.
        for index in range(len(text) - 1):
            window = text[index:index + 2]
            for key in dict.fromkeys((window[0], window[1], window)):
                for glyph in table.get(key, ()):
                    yield text[:index] + window.replace(key, glyph, 1) + text[index + 2:]

    seen: set[str] = set()
    for candidate in swaps(label):
        if candidate not in seen:
            seen.add(candidate)
            yield candidate


def cyrillic(label: str, **_kw) -> Iterator[str]:
    """Replacing every possible Latin letter at once -- the classic IDN attack."""
    converted = label
    for latin, cyr in LATIN_TO_CYRILLIC.items():
        converted = converted.replace(latin, cyr)
    if converted != label:
        yield converted


def hyphenation(label: str, **_kw) -> Iterator[str]:
    for index in range(1, len(label)):
        yield label[:index] + "-" + label[index:]


def insertion(label: str, **_kw) -> Iterator[str]:
    """Press a key next to an existing one, without removing the original."""
    seen: set[str] = set()
    for index in range(len(label) - 1):
        char = label[index]
        tail = label[index + 1:]
        for layout in KEYBOARDS:
            for neighbour in layout.get(char, ""):
                for candidate in (label[:index] + neighbour + char + tail,
                                  label[:index] + char + neighbour + tail):
                    if candidate not in seen:
                        seen.add(candidate)
                        yield candidate


def omission(label: str, **_kw) -> Iterator[str]:
    for index in range(len(label)):
        yield label[:index] + label[index + 1:]


def repetition(label: str, **_kw) -> Iterator[str]:
    for index, char in enumerate(label):
        yield label[:index] + char + label[index:]


def replacement(label: str, **_kw) -> Iterator[str]:
    """Hit a neighbouring key *instead of* the intended one."""
    seen: set[str] = set()
    for index, char in enumerate(label):
        head, tail = label[:index], label[index + 1:]
        for layout in KEYBOARDS:
            for neighbour in layout.get(char, ""):
                candidate = head + neighbour + tail
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def subdomain(label: str, **_kw) -> Iterator[str]:
    """Turn a label into a subdomain: `example` -> `exa.mple.example.com`."""
    for index in range(1, len(label) - 1):
        if label[index] not in "-." and label[index - 1] not in "-.":
            yield label[:index] + "." + label[index:]


def transposition(label: str, **_kw) -> Iterator[str]:
    for index in range(len(label) - 1):
        yield label[:index] + label[index + 1] + label[index] + label[index + 2:]


def vowel_swap(label: str, **_kw) -> Iterator[str]:
    vowels = "aeiou"
    for index, char in enumerate(label):
        if char in vowels:
            for vowel in vowels:
                if vowel != char:
                    yield label[:index] + vowel + label[index + 1:]


def plural(label: str, **_kw) -> Iterator[str]:
    """Append a plural suffix, and inflect each hyphen-separated part.

    Inserting the suffix at an arbitrary middle offset (`example` ->
    `exasmple`) never produces the form anyone actually types, so this
    appends. For `acme-corp` it also yields `acmes-corp` and `acme-corps`.
    """
    def inflect(text: str) -> str:
        return text + ("es" if text.endswith(("s", "x", "z")) else "s")

    yield inflect(label)
    if "-" in label:
        parts = label.split("-")
        for index in range(len(parts)):
            mutated = list(parts)
            mutated[index] = inflect(parts[index])
            yield "-".join(mutated)


def addition(label: str, **_kw) -> Iterator[str]:
    """Append or infix a single alphanumeric character."""
    seen: set[str] = set()
    for char in _DIGIT_AND_LOWER:
        candidate = label + char
        if candidate not in seen:
            seen.add(candidate)
            yield candidate
    if "-" in label:
        parts = label.split("-")
        for position in range(1, len(parts)):
            head = "-".join(parts[:position])
            tail = "-".join(parts[position:])
            for char in _DIGIT_AND_LOWER:
                candidate = head + char + "-" + tail
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def dictionary(label: str, words: Iterable[str] = (), **_kw) -> Iterator[str]:
    """Glue a word from a dictionary onto either side of the label."""
    seen: set[str] = set()
    for word in words:
        if not word:
            continue
        if label.startswith(word) and label.endswith(word):
            continue
        for candidate in (label + "-" + word, label + word,
                          word + "-" + label, word + label):
            if candidate not in seen:
                seen.add(candidate)
                yield candidate
    if "-" in label:
        parts = label.split("-")
        for word in words:
            for candidate in ("-".join(parts[:-1]) + "-" + word,
                              word + "-" + "-".join(parts[1:])):
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def tld_swap(label: str, tld: str = "", tld_pool: Iterable[str] = (), **_kw) -> Iterator[str]:
    for other in tld_pool:
        if other != tld:
            yield label + "." + other


RULE_TABLE: dict[str, Callable[..., Iterator[str]]] = {
    "bitsquatting": bitsquatting,
    "homoglyph": homoglyph,
    "cyrillic": cyrillic,
    "hyphenation": hyphenation,
    "insertion": insertion,
    "omission": omission,
    "repetition": repetition,
    "replacement": replacement,
    "subdomain": subdomain,
    "transposition": transposition,
    "vowel-swap": vowel_swap,
    "plural": plural,
    "addition": addition,
    "dictionary": dictionary,
    "tld-swap": tld_swap,
}

ALL_RULES = tuple(RULE_TABLE)


# --------------------------------------------------------------------------
# generating the whole set
# --------------------------------------------------------------------------

@dataclass
class Permuter:
    """Generates every variant of `domain` for the requested rules.

    `tld_pool` is only consulted by the `tld-swap` rule; pass the list of
    suffixes you actually care about rather than letting it be every TLD.
    """

    domain: str
    words: tuple[str, ...] = ()
    tld_pool: tuple[str, ...] = ()
    _split: Split = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._split = split_hostname(self.domain)

    @property
    def split(self) -> Split:
        return self._split

    def generate(self, rules: Iterable[str] | None = None) -> list[Candidate]:
        selected = tuple(rules) if rules else ALL_RULES
        unknown = [r for r in selected if r not in RULE_TABLE and r != "original"]
        if unknown:
            raise ValueError(f"unknown rule(s): {', '.join(sorted(unknown))}")

        out: dict[str, Candidate] = {}

        if "original" in selected:
            original = self._split.join()
            out[original] = Candidate(original, "original")

        for name in selected:
            if name == "original":
                continue
            rule = RULE_TABLE[name]
            for produced in rule(label=self._split.label, tld=self._split.tld,
                                 words=self.words, tld_pool=self.tld_pool):
                # `tld-swap` already emits the full host, the rest emit a label.
                host = produced if name == "tld-swap" else self._split.join(label=produced)
                host = host.lower().strip(".")
                if not _FQDN.match(host):
                    continue
                if host == self._split.join():
                    continue
                out.setdefault(host, Candidate(host, name))

        return sorted(out.values(), key=lambda c: (c.domain, c.rule))


def dedupe_sorted(candidates: Iterable[Candidate]) -> list[Candidate]:
    """Collapse a multi-domain run into one entry per hostname.

    A host can be produced by several rules at once; the report only cares
    that it exists, not how many ways we found it.
    """
    best: dict[str, Candidate] = {}
    for candidate in candidates:
        existing = best.get(candidate.domain)
        if existing is None or candidate.rule < existing.rule:
            best[candidate.domain] = candidate
    return sorted(best.values(), key=lambda c: c.domain)


def combos(rules: Iterable[str], size: int) -> list[tuple[str, ...]]:
    """Rule combinations of `size` -- handy for coverage smoke tests."""
    return list(itertools.combinations(rules, size))
