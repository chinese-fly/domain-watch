"""dwatch -- look-alike domain monitoring."""

from .permute import ALL_RULES, Candidate, Permuter, split_hostname
from .resolver import DnsResolver, FakeResolver, Resolution
from .score import RiskScore, score_candidate

__version__ = "0.6.0"

__all__ = [
    "ALL_RULES", "Candidate", "Permuter", "split_hostname",
    "DnsResolver", "FakeResolver", "Resolution",
    "RiskScore", "score_candidate", "__version__",
]
