"""dwatch -- look-alike domain monitoring."""

from .permute import ALL_RULES, Candidate, Permuter, split_hostname

__version__ = "0.3.0"

__all__ = ["ALL_RULES", "Candidate", "Permuter", "split_hostname", "__version__"]
