"""Offline phone number intelligence using phonenumbers."""

from __future__ import annotations

from datetime import UTC, datetime

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder
from pydantic import BaseModel, Field

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import InvalidInput


class PhoneIntelResult(BaseModel):
    """Phone number intelligence result."""

    phone_number: str
    formatted_e164: str
    formatted_national: str
    country_code: str
    country_name: str
    carrier: str
    line_type: str
    is_valid: bool
    is_possible: bool
    query_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    cached: bool = False
    errors: list[str] = Field(default_factory=list)


def _map_line_type(number_type: PhoneNumberType) -> str:
    """Map phonenumbers line type to DragonflyX output values."""
    if number_type == PhoneNumberType.MOBILE:
        return "mobile"
    if number_type == PhoneNumberType.FIXED_LINE:
        return "fixed_line"
    if number_type == PhoneNumberType.VOIP:
        return "voip"
    if number_type == PhoneNumberType.FIXED_LINE_OR_MOBILE:
        return "mobile"
    return "unknown"


async def lookup_phone(
    phone: str,
    use_cache: bool = True,
) -> PhoneIntelResult:
    """
    Look up phone number metadata using the phonenumbers library.

    Parses and validates the number, then extracts carrier, region,
    and line type information. Fully offline — no API calls made.

    Args:
        phone: Phone number string, with or without country code
               (e.g. "+84901234567", "0901234567")

    Returns:
        PhoneIntelResult with all available metadata

    Raises:
        InvalidInput: If the phone number cannot be parsed
    """
    if use_cache:
        key = cache.make_key("phone_intel", phone)
        cached = cache.get(key)
        if cached:
            result = PhoneIntelResult.model_validate(cached)
            result.cached = True
            return result

    try:
        parsed = phonenumbers.parse(phone, None)
    except phonenumbers.NumberParseException as exc:
        raise InvalidInput(
            input_type="phone",
            value=phone,
            reason="cannot be parsed",
        ) from exc

    region_code = phonenumbers.region_code_for_number(parsed) or ""
    result = PhoneIntelResult(
        phone_number=phone,
        formatted_e164=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        formatted_national=phonenumbers.format_number(
            parsed,
            phonenumbers.PhoneNumberFormat.NATIONAL,
        ),
        country_code=region_code,
        country_name=geocoder.country_name_for_number(parsed, "en"),
        carrier=carrier.name_for_number(parsed, "en") or "",
        line_type=_map_line_type(phonenumbers.number_type(parsed)),
        is_valid=phonenumbers.is_valid_number(parsed),
        is_possible=phonenumbers.is_possible_number(parsed),
    )

    if use_cache:
        cache.set(
            cache.make_key("phone_intel", phone),
            result.model_dump(mode="json"),
            "phone_intel",
        )

    return result
