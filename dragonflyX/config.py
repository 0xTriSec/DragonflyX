"""Configuration and API key management."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from dragonflyX.core.exceptions import APIKeyMissing
from dragonflyX.core.logger import logger

KEY_MAP = {
    "virustotal": ("vt_api_key", "VT_API_KEY"),
    "abuseipdb": ("ab_api_key", "AB_API_KEY"),
    "urlscan": ("urlscan_io_key", "URLSCAN_IO_KEY"),
    "shodan": ("shodan_api_key", "SHODAN_API_KEY"),
}


class Settings(BaseSettings):
    """Application settings loaded from .env file."""

    vt_api_key: str = Field(default="", alias="VT_API_KEY")
    ab_api_key: str = Field(default="", alias="AB_API_KEY")
    urlscan_io_key: str = Field(default="", alias="URLSCAN_IO_KEY")
    shodan_api_key: str = Field(default="", alias="SHODAN_API_KEY")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def has_virustotal(self) -> bool:
        return bool(self.vt_api_key)

    @property
    def has_abuseipdb(self) -> bool:
        return bool(self.ab_api_key)

    @property
    def has_urlscan(self) -> bool:
        return bool(self.urlscan_io_key)

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan_api_key)


settings = Settings()


def validate_keys() -> dict[str, bool]:
    """
    Check which API keys are configured.

    Returns:
        Dict mapping API name to whether it's configured
    """
    status = {
        "virustotal": settings.has_virustotal,
        "abuseipdb": settings.has_abuseipdb,
        "urlscan": settings.has_urlscan,
        "shodan": settings.has_shodan,
    }
    for api, configured in status.items():
        if not configured:
            logger.warning(f"API key for {api} not configured — module will be skipped or degraded")
    return status


def require_key(api_name: str) -> str:
    """
    Get an API key or raise if not configured.

    Args:
        api_name: Name of the API (e.g., 'virustotal')

    Returns:
        The API key string

    Raises:
        APIKeyMissing: If the key is not configured
    """
    if api_name not in KEY_MAP:
        raise KeyError(f"Unknown API: {api_name}")
    attr, env_var = KEY_MAP[api_name]
    value = getattr(settings, attr, "")
    if not value:
        raise APIKeyMissing(api_name=api_name, env_var=env_var)
    return value
