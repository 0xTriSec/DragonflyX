"""Pytest fixtures for DragonflyX tests."""

import pytest


@pytest.fixture
def vt_ip_response() -> dict:
    """VirusTotal IP response with some detections."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 9,
                },
                "reputation": -10,
                "last_analysis_date": 1700000000,
            }
        }
    }


@pytest.fixture
def vt_ip_clean_response() -> dict:
    """VirusTotal IP response with no detections."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 3,
                },
                "reputation": 10,
                "last_analysis_date": 1700000000,
            }
        }
    }


@pytest.fixture
def abuseipdb_response() -> dict:
    """AbuseIPDB response for a clean IP."""
    return {
        "data": {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "isp": "Google LLC",
            "usageType": "Data Center",
            "isTor": False,
            "countryCode": "US",
            "lastReportedAt": None,
        }
    }


@pytest.fixture
def abuseipdb_high_response() -> dict:
    """AbuseIPDB response with high abuse score."""
    return {
        "data": {
            "ipAddress": "1.2.3.4",
            "isPublic": True,
            "abuseConfidenceScore": 92,
            "totalReports": 150,
            "isp": "SomeISP",
            "usageType": "Unknown",
            "isTor": True,
            "countryCode": "XX",
            "lastReportedAt": "2024-01-01T00:00:00+00:00",
        }
    }


@pytest.fixture
def shodan_response() -> dict:
    """Shodan response with open ports."""
    return {
        "ports": [80, 443, 8080],
        "data": [
            {"port": 80, "transport": "tcp", "product": "nginx", "banner": "HTTP/1.1 200 OK"},
            {"port": 443, "transport": "tcp", "product": "nginx", "banner": ""},
        ],
        "vulns": {},
        "hostnames": ["dns.google"],
        "tags": [],
        "os": None,
        "last_update": "2024-01-01T00:00:00",
    }


@pytest.fixture
def ipinfo_response() -> dict:
    """ipinfo.io response for 8.8.8.8."""
    return {
        "ip": "8.8.8.8",
        "hostname": "dns.google",
        "city": "Mountain View",
        "country": "US",
        "org": "AS15169 Google LLC",
        "loc": "37.4056,-122.0775",
    }


@pytest.fixture
def vt_hash_not_found() -> tuple[int, dict]:
    """VirusTotal 404 response for unknown hash."""
    return (404, {"error": {"code": "NotFoundError", "message": "File not found"}})


@pytest.fixture
def vt_hash_malicious() -> dict:
    """VirusTotal response with high detection count."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 2,
                    "harmless": 55,
                    "undetected": 3,
                },
                "type_description": "Win32 EXE",
                "size": 65536,
                "meaningful_name": "malware.exe",
                "first_submission_date": 1600000000,
                "last_analysis_date": 1700000000,
                "last_analysis_results": {
                    "Kaspersky": {"category": "malicious", "result": "Trojan.Win32.Generic"},
                    "BitDefender": {"category": "malicious", "result": "Gen:Variant.Razy"},
                    "Avast": {"category": "malicious", "result": "Win32:Malware"},
                },
                "tags": ["peexe", "64bits"],
            }
        }
    }
