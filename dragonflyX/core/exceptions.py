"""DragonflyX exception hierarchy."""

from __future__ import annotations


class DragonflyXError(Exception):
    """Base exception for all DragonflyX errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        """Convert exception to dictionary."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }

    @property
    def user_friendly(self) -> str:
        """Human-readable error message."""
        return self.message


class APIKeyMissing(DragonflyXError):
    """Raised when a required API key is not configured."""

    def __init__(self, api_name: str, env_var: str) -> None:
        self.api_name = api_name
        self.env_var = env_var
        message = f"API key for {api_name} is missing. Set {env_var} in your .env file."
        super().__init__(message=message)

    @property
    def user_friendly(self) -> str:
        return f"API key for {self.api_name} is missing. Set {self.env_var} in your .env file."


class InvalidInput(DragonflyXError):
    """Raised when user input is invalid."""

    def __init__(self, input_type: str, value: str, reason: str) -> None:
        self.input_type = input_type
        self.value = value
        self.reason = reason
        message = f"Invalid {input_type}: '{value}' — {reason}"
        super().__init__(message=message)

    @property
    def user_friendly(self) -> str:
        return f"Invalid {self.input_type}: '{self.value}' — {self.reason}"


class RateLimited(DragonflyXError):
    """Raised when an API rate limit is hit."""

    def __init__(self, api_name: str, retry_after: int | None = None) -> None:
        self.api_name = api_name
        self.retry_after = retry_after
        if retry_after is not None:
            message = f"{api_name} rate limit reached. Retry after {retry_after}s."
        else:
            message = f"{api_name} rate limit reached. Retry soon."
        super().__init__(message=message)

    @property
    def user_friendly(self) -> str:
        if self.retry_after is not None:
            return f"{self.api_name} rate limit reached. Retry after {self.retry_after}s."
        return f"{self.api_name} rate limit reached. Retry soon."


class APIError(DragonflyXError):
    """Raised when an API returns an error response."""

    def __init__(self, api_name: str, status_code: int, message: str) -> None:
        self.api_name = api_name
        self.status_code = status_code
        self.message = message
        full_message = f"{api_name} returned HTTP {status_code}: {message}"
        super().__init__(message=full_message)

    @property
    def is_client_error(self) -> bool:
        """Check if this is a 4xx error."""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """Check if this is a 5xx error."""
        return 500 <= self.status_code < 600

    @property
    def user_friendly(self) -> str:
        return f"{self.api_name} returned HTTP {self.status_code}: {self.message}"


class CacheError(DragonflyXError):
    """Raised when a cache operation fails."""

    def __init__(self, key: str, operation: str, reason: str) -> None:
        self.key = key
        self.operation = operation
        self.reason = reason
        message = f"Cache {operation} failed for key '{key}': {reason}"
        super().__init__(message=message)

    @property
    def user_friendly(self) -> str:
        return f"Cache {self.operation} failed for key '{self.key}': {self.reason}"


class NetworkError(DragonflyXError):
    """Raised when a network request fails."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        self.api_name = "network"  # Required for ExceptionGroup handler
        message = f"Network error reaching {url}: {reason}"
        super().__init__(message=message)

    @property
    def user_friendly(self) -> str:
        return f"Network error reaching {self.url}: {self.reason}"
