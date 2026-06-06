"""IP Intelligence module."""

from dragonflyX.modules.ip_intel.schemas import IPIntelResult
from dragonflyX.modules.ip_intel.service import analyze_ip

__all__ = ["analyze_ip", "IPIntelResult"]
