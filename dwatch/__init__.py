"""dwatch -- look-alike domain monitoring."""

from .permute import ALL_RULES, Candidate, Permuter, split_hostname
from .resolver import DnsResolver, FakeResolver, Resolution
from .score import RiskScore, score_candidate
from .store import Observation, Store, utcnow

__version__ = "0.8.0"

__all__ = [
    "ALL_RULES", "Candidate", "Permuter", "split_hostname",
    "DnsResolver", "FakeResolver", "Resolution",
    "RiskScore", "score_candidate",
    "Store", "Observation", "utcnow", "__version__",
]
