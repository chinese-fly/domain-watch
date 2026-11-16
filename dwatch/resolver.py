"""DNS resolution, kept separate from the permutation engine on purpose.

Resolution is I/O, generation is arithmetic. Folding them together makes the
resolution logic impossible to unit test and impossible to swap out, and it
also means a network hiccup shows up as a test failure. Here a resolver is
anything that satisfies the `Resolver` protocol, so tests use `FakeResolver`
and production uses `DnsResolver`. Nothing in this module opens a socket at
import time.
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable, Protocol


@dataclass
class Resolution:
    """What we learned about one hostname."""

    domain: str
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    ns: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    error: str | None = None

    @property
    def resolves(self) -> bool:
        return bool(self.a or self.aaaa or self.mx or self.ns)

    @property
    def primary_ip(self) -> str | None:
        return self.a[0] if self.a else None


class Resolver(Protocol):
    def resolve_many(self, domains: Iterable[str]) -> dict[str, Resolution]:
        ...


@dataclass
class DnsResolver:
    """Threaded resolver built on the standard library only.

    Deliberately not using dnspython: MX lookup over the socket API needs
    `socket.getaddrinfo` on the mail host, which is what an attacker's
    parked-domain mail setup will still answer. If you need signed or
    TCP-only answers, swap in a different Resolver.
    """

    timeout: float = 3.0
    workers: int = 12
    want_mx: bool = True
    want_ns: bool = True

    def _lookup_a(self, domain: str) -> tuple[str, ...]:
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        except (socket.gaierror, socket.herror, OSError):
            return ()
        return tuple(sorted({info[4][0] for info in infos}))

    def _lookup_aaaa(self, domain: str) -> tuple[str, ...]:
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
        except (socket.gaierror, socket.herror, OSError):
            return ()
        return tuple(sorted({info[4][0] for info in infos}))

    def resolve_one(self, domain: str) -> Resolution:
        result = Resolution(domain=domain)
        # A record is the cheap signal that separates a parked domain from a
        # dead one-liner in someone's hosts file, so it goes first and a
        # failure there short-circuits the rest.
        result.a = self._lookup_a(domain)
        if not result.a:
            result.error = "nxdomain"
            return result
        result.aaaa = self._lookup_aaaa(domain)
        return result

    def resolve_many(self, domains: Iterable[str]) -> dict[str, Resolution]:
        domains = list(dict.fromkeys(domains))
        out: dict[str, Resolution] = {}
        if not domains:
            return out

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.resolve_one, d): d for d in domains}
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    out[domain] = future.result()
                except Exception as exc:  # noqa: BLE001 - one bad host must not kill the run
                    out[domain] = Resolution(domain=domain, error=type(exc).__name__)
        return out


@dataclass
class FakeResolver:
    """Deterministic resolver for tests and offline demos."""

    table: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def resolve_one(self, domain: str) -> Resolution:
        if domain not in self.table:
            return Resolution(domain=domain, error="nxdomain")
        return Resolution(domain=domain, a=self.table[domain])

    def resolve_many(self, domains: Iterable[str]) -> dict[str, Resolution]:
        return {d: self.resolve_one(d) for d in dict.fromkeys(domains)}
