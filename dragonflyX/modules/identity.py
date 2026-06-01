"""Username/email OSINT scanner across 20+ platforms."""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, Field

from dragonflyX.core.cache import cache
from dragonflyX.core.validators import validate_username

EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

PLATFORMS: dict[str, dict] = {
    "GitHub": {
        "url": "https://github.com/{username}",
        "not_found_strings": ["Not Found", "404"],
        "method": "status",
    },
    "Twitter/X": {
        "url": "https://twitter.com/{username}",
        "not_found_strings": ["This account doesn", "account doesn", "isn't available"],
        "method": "content",
    },
    "Instagram": {
        "url": "https://www.instagram.com/{username}/",
        "not_found_strings": ["Page Not Found", "Sorry, this page"],
        "method": "content",
    },
    "Facebook": {
        "url": "https://www.facebook.com/{username}",
        "not_found_strings": ["Facebook", "login"],
        "method": "content",
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "not_found_strings": ["Sorry, nobody on Reddit goes by that name"],
        "method": "content",
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{username}",
        "not_found_strings": ["Couldn't find this account"],
        "method": "content",
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{username}",
        "not_found_strings": ["Page not found", "This page doesn't"],
        "method": "content",
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{username}",
        "not_found_strings": ["404", "This page isn't available"],
        "method": "content",
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{username}",
        "not_found_strings": ["Sorry. Unless you've"],
        "method": "content",
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "not_found_strings": ["Hmm", "couldn't find", "Page Not Found"],
        "method": "content",
    },
    "Medium": {
        "url": "https://medium.com/@{username}",
        "not_found_strings": ["Page not found", "404"],
        "method": "content",
    },
    "DevTo": {
        "url": "https://dev.to/{username}",
        "not_found_strings": ["404", "Page not found"],
        "method": "status",
    },
    "GitLab": {
        "url": "https://gitlab.com/{username}",
        "not_found_strings": ["404", "The page you're looking for"],
        "method": "status",
    },
    "Dribbble": {
        "url": "https://dribbble.com/{username}",
        "not_found_strings": ["404", "Page not found", "Ohops!"],
        "method": "content",
    },
    "Behance": {
        "url": "https://www.behance.net/{username}",
        "not_found_strings": ["404", "Page not found"],
        "method": "content",
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={username}",
        "not_found_strings": ["No such user"],
        "method": "content",
    },
    "Keybase": {
        "url": "https://keybase.io/{username}",
        "not_found_strings": ["404", "Not found"],
        "method": "status",
    },
    "Pastebin": {
        "url": "https://pastebin.com/u/{username}",
        "not_found_strings": ["Not Found"],
        "method": "status",
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{username}",
        "not_found_strings": ["The page you were looking for"],
        "method": "content",
    },
    "Snapchat": {
        "url": "https://www.snapchat.com/add/{username}",
        "not_found_strings": ["Sorry!", "Hmm", "couldn't find"],
        "method": "content",
    },
}

# Browser User-Agent de gia lap that
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


class PlatformResult(BaseModel):
    """Represents a found platform result."""

    platform: str
    url: str
    response_time_ms: int | None = None


class IdentityResult(BaseModel):
    """Username/email OSINT scan result."""

    query: str
    query_type: str = "username"
    query_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    found: list[PlatformResult] = Field(default_factory=list)
    not_found: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    error_count: int = 0
    response_times: dict[str, float] = Field(default_factory=dict)
    cached: bool = False

    @property
    def total_checked(self) -> int:
        """Total platforms checked."""
        return len(self.found) + len(self.not_found) + self.error_count


async def check_platform(
    username: str,
    platform_name: str,
    platform_config: dict,
    sem: asyncio.Semaphore,
) -> PlatformResult | None:
    """
    Check if username exists on a platform.

    Returns:
        PlatformResult if found, None if not found or error.
    """
    url = platform_config["url"].format(username=username)
    method = platform_config.get("method", "status")
    not_found_strings = platform_config.get("not_found_strings", [])

    async with sem:
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(8.0, connect=5.0),
                follow_redirects=True,
                headers=BROWSER_HEADERS,
            ) as client:
                response = await client.get(url)
                elapsed_ms = int((time.monotonic() - start) * 1000)

                # Buoc A: 404 luon la not found
                if response.status_code == 404:
                    return None

                # Buoc B: Khong phai 200 thi error
                if response.status_code != 200:
                    return None

                # Buoc C: method == "status" -> chi can 200 la found
                if method == "status":
                    return PlatformResult(
                        platform=platform_name,
                        url=url,
                        response_time_ms=elapsed_ms,
                    )

                # Buoc D: method == "content" -> kiem tra noi dung
                # Doc toi da 4096 bytes de tranh download toan bo page
                try:
                    content = response.text[:4096].lower()
                except Exception:
                    content = ""

                # Neu chua not-found string -> danh dau la not found
                for nf_string in not_found_strings:
                    if nf_string.lower() in content:
                        return None

                # Khong co not-found string -> found
                return PlatformResult(
                    platform=platform_name,
                    url=url,
                    response_time_ms=elapsed_ms,
                )

        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            return None


async def scan_username(
    username: str,
    use_cache: bool = True,
) -> IdentityResult:
    """
    Scan for username across platforms.

    Args:
        username: Username to search for
        use_cache: Whether to use cached results

    Returns:
        IdentityResult with found/not_found/error counts
    """
    validate_username(username)

    if use_cache:
        key = cache.make_key("identity", username)
        cached_data = cache.get(key)
        if cached_data:
            result = IdentityResult.model_validate(cached_data)
            result.cached = True
            return result

    sem = asyncio.Semaphore(10)
    tasks = [
        check_platform(username, name, config, sem)
        for name, config in PLATFORMS.items()
    ]
    results_raw = await asyncio.gather(*tasks, return_exceptions=True)

    found: list[PlatformResult] = []
    not_found: list[str] = []
    error_count = 0
    response_times: dict[str, float] = {}

    for platform_name, raw in zip(PLATFORMS.keys(), results_raw):
        if isinstance(raw, Exception):
            error_count += 1
        elif raw is None:
            not_found.append(platform_name)
        else:
            found.append(raw)
            if raw.response_time_ms is not None:
                response_times[platform_name] = float(raw.response_time_ms)

    result = IdentityResult(
        query=username,
        query_type="username",
        found=found,
        not_found=not_found,
        errors=[],
        error_count=error_count,
        response_times=response_times,
    )

    if use_cache:
        cache.set(
            cache.make_key("identity", username),
            result.model_dump(mode="json"),
            "identity",
        )

    return result


async def scan_email(email: str, use_cache: bool = True) -> IdentityResult:
    """
    Scan for email address (extracts username and searches).

    Args:
        email: Email address to search for
        use_cache: Whether to use cached results

    Returns:
        IdentityResult with found/not_found/error counts
    """
    if not EMAIL_PATTERN.match(email):
        from dragonflyX.core.exceptions import InvalidInput
        raise InvalidInput("email", email, "not a valid email address")

    username = email.split("@")[0]
    result = await scan_username(username, use_cache=use_cache)
    result.query = email
    result.query_type = "email"
    return result
