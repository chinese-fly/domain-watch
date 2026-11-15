"""dwatch -- look-alike domain monitoring."""

from .permute import ALL_RULES, Candidate, Permuter, split_hostname
from .resolver import DnsResolver, FakeResolver, Resolution
from .scanner import ScanResult, Scanner
from .score import RiskScore, score_candidate
from .store import Observation, Store, utcnow

__version__ = "1.0.0"

__all__ = [
    "ALL_RULES", "Candidate", "Permuter", "split_hostname",
    "DnsResolver", "FakeResolver", "Resolution",
    "Scanner", "ScanResult", "RiskScore", "score_candidate",
    "Store", "Observation", "utcnow", "__version__",
]
