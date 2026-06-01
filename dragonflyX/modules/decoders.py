"""URL and string decoders for analyzing encoded/masked URLs."""

from __future__ import annotations

import base64
import codecs
import html as html_lib
import re
import urllib.parse
from urllib.parse import urlparse


type DecodingResult = tuple[str, str | None]

KNOWN_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "short.link", "rebrand.ly", "tiny.cc", "shorturl.at", "cutt.ly", "rb.gy",
    "bl.ink", "snip.ly", "clk.sh", "su.pr", "qr.ae", "po.st", "soo.gd",
    "s.id", "lnkd.in", "fb.me", "g.co", "amzn.to", "youtu.be", "t.ly",
    "url.ie", "adf.ly", "bc.vc", "j.mp", "lc.cx", "mcaf.ee", "ift.tt",
    "dlvr.it", "ff.im", "nico.to", "go2.do", "x.co", "zi.ma", "shrtco.de",
    "zpr.io", "3.ly", "4sq.com", "a.co", "b.link", "c.ly", "d.to",
    "e.gg", "f.gg", "go.ly", "hit.ly", "i.gd", "k.tc",
})


def is_shortener(url: str) -> bool:
    """
    Check if a URL uses a known URL shortening service.

    Args:
        url: URL to check

    Returns:
        True if URL is from a known shortener
    """
    try:
        return urlparse(url).netloc.lower() in KNOWN_SHORTENERS
    except Exception:
        return False


def decode_safelinks(url: str) -> str | None:
    """
    Decode Microsoft Office SafeLinks URLs.

    Args:
        url: SafeLinks URL to decode

    Returns:
        Decoded URL or None if not a SafeLinks URL
    """
    parsed = urlparse(url)
    if "safelinks.protection.outlook.com" not in parsed.netloc:
        return None
    params = parse_qs(parsed.query)
    raw = params.get("url", [None])[0]
    return urllib.parse.unquote(raw) if raw else None


def decode_proofpoint(url: str) -> str | None:
    """
    Decode ProofPoint URLs (v2 and v3 formats).

    Args:
        url: ProofPoint URL to decode

    Returns:
        Decoded URL or None if not a ProofPoint URL
    """
    # v2: nhan ca 2 variant domain cua ProofPoint v2
    is_v2 = (
        "urldefense.proofpoint.com/v2/url" in url
        or "urldefense.com/v2/url" in url
    )
    if is_v2:
        params = parse_qs(urlparse(url).query)
        u = params.get("u", [None])[0]
        if u:
            return urllib.parse.unquote(u.replace("-", "%").replace("_", "/"))

    # v3 detection
    if "urldefense.com/v3/__" in url:
        m = re.search(r"urldefense\.com/v3/__(?P<encoded>[A-Za-z0-9+/=_-]+)__", url)
        if m:
            encoded = m.group("encoded")
            pad = (4 - len(encoded) % 4) % 4
            try:
                decoded = base64.urlsafe_b64decode(encoded + "=" * pad)
                return decoded.decode("utf-8", errors="replace")
            except Exception:
                pass

    return None


def decode_base64_url(text: str) -> str | None:
    """
    Attempt to decode a Base64 string as a URL.

    Args:
        text: Base64 encoded string

    Returns:
        Decoded URL or None if not valid Base64 URL
    """
    if "://" in text:
        return None
    pad = (4 - len(text) % 4) % 4
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * pad)
        if decoded.startswith(b"http"):
            return decoded.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def decode_url(url: str) -> DecodingResult:
    """
    Attempt to decode an encoded URL and identify the encoding type.

    Args:
        url: Potentially encoded URL

    Returns:
        Tuple of (decoded_url, encoding_type)
    """
    result = decode_safelinks(url)
    if result and result != url:
        return (result, "safelinks")

    result = decode_proofpoint(url)
    if result and result != url:
        return (result, "proofpoint")

    result = decode_base64_url(url)
    if result and result != url:
        return (result, "base64")

    if is_shortener(url):
        return (url, "shortener")

    return (url, None)


def decode_string(text: str) -> dict[str, str]:
    """
    Try multiple decoding methods on a string.

    Args:
        text: String to decode

    Returns:
        Dict mapping decoding type to decoded value
    """
    results: dict[str, str] = {}

    # base64
    try:
        pad = (4 - len(text) % 4) % 4
        decoded = base64.b64decode(text + "=" * pad).decode("utf-8")
        if decoded != text:
            results["base64"] = decoded
    except Exception:
        pass

    # hex
    try:
        decoded = bytes.fromhex(text.strip()).decode("utf-8")
        results["hex"] = decoded
    except Exception:
        pass

    # rot13
    try:
        decoded = codecs.decode(text, "rot_13")
        if decoded != text:
            results["rot13"] = decoded
    except Exception:
        pass

    # url-encoded
    if "%" in text:
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            results["url_encoded"] = decoded

    # html entities
    if "&" in text:
        decoded = html_lib.unescape(text)
        if decoded != text:
            results["html_entities"] = decoded

    return results


def parse_qs(query: str) -> dict[str, list[str]]:
    """Simple query string parser."""
    return urllib.parse.parse_qs(query)
