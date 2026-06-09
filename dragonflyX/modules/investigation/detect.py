"""Input detection for investigation targets."""

from __future__ import annotations

import re

from dragonflyX.core.exceptions import InvalidInput
from dragonflyX.core.validators import validate_domain, validate_ip

from .schemas import InvestigationTarget


def detect_target(raw_input: str) -> InvestigationTarget:
    """
    Detect the type of an investigation target from raw user input.

    Detection priority:
      1. Email: contains @ and has valid domain part
      2. IP: valid IPv4 or IPv6 address
      3. Domain: contains dot, no spaces, valid domain format
      4. Raises InvalidInput if none match

    Args:
        raw_input: Raw string from CLI argument

    Returns:
        InvestigationTarget with detected type and normalized value

    Raises:
        InvalidInput: If input cannot be classified as ip, domain, or email
    """
    normalized = raw_input.strip()

    if not normalized:
        raise InvalidInput(
            input_type="investigation target",
            value=raw_input,
            reason="input cannot be empty",
        )

    # 1. Email check: must contain @ and a valid domain-like part
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", normalized):
        return InvestigationTarget(
            raw_input=raw_input,
            input_type="email",
            normalized=normalized,
        )

    # 2. IP check: valid IPv4 or IPv6 address
    try:
        validate_ip(normalized)
    except InvalidInput:
        pass
    else:
        return InvestigationTarget(
            raw_input=raw_input,
            input_type="ip",
            normalized=normalized,
        )

    # 3. Domain check: valid domain format
    try:
        validate_domain(normalized)
    except InvalidInput:
        pass
    else:
        return InvestigationTarget(
            raw_input=raw_input,
            input_type="domain",
            normalized=normalized.lower(),
        )

    # 4. None matched
    raise InvalidInput(
        input_type="investigation target",
        value=raw_input,
        reason="must be an IP address, domain name, or email address",
    )
