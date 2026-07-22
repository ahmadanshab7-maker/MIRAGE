"""MIRAGE v0.1 - Passive Linux Environment Profiler

MIRAGE is a measurement instrument for cybersecurity research studying
environmental realism and deception. It collects read-only environmental
measurements and saves them as structured JSON.

IMPORTANT: MIRAGE v0.1 does NOT:
- Detect honeypots or sandboxes
- Calculate authenticity/deception scores
- Classify environments
- Use heuristic thresholds or ML
"""

__version__ = "0.1.0"
__author__ = "MIRAGE Research Project"

from .collectors import (
    system,
    users,
    filesystem,
    software,
    runtime,
    network,
)
from .models.snapshot import Snapshot

__all__ = [
    "__version__",
    "system",
    "users",
    "filesystem",
    "software",
    "runtime",
    "network",
    "Snapshot",
]
