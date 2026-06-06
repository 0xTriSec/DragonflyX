"""URL Analysis module."""

from dragonflyX.modules.url_analysis.schemas import URLAnalysisResult
from dragonflyX.modules.url_analysis.service import analyze_url

__all__ = ["analyze_url", "URLAnalysisResult"]
