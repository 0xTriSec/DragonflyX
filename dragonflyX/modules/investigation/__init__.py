"""Investigation module — Phase 3B."""

from __future__ import annotations

import re

from dragonflyX.core.exceptions import InvalidInput
from dragonflyX.core.validators import validate_domain, validate_ip

from .schemas import InvestigationTarget, InvestigationResult
from .service import investigate
from .detect import detect_target

__all__ = [
    "investigate",
    "InvestigationResult",
    "InvestigationTarget",
    "detect_target",
]
