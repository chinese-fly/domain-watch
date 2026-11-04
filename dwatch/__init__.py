"""dwatch -- look-alike domain monitoring."""

from .permute import ALL_RULES, Candidate, Permuter, split_hostname
from .resolver import DnsResolver, FakeResolver, Resolution

__version__ = "0.5.0"

__all__ = [
    "ALL_RULES", "Candidate", "Permuter", "split_hostname",
    "DnsResolver", "FakeResolver", "Resolution", "__version__",
]
