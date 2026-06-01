# DragonflyX

![DragonflyX Banner](assets/images/dragonflyx_project.png)

[![Python 3.13+](https://img.shields.io/badge/Python-3.13+-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-0xTriSec-red?logo=github)](https://github.com/0xTriSec)

DragonflyX enriches indicators of compromise (IP addresses, URLs, file hashes, usernames, domains) by querying multiple intelligence sources in parallel and presenting correlated results with a computed risk score.

## Features

- **IP Intelligence** — Analyze IP addresses using VirusTotal, AbuseIPDB, Shodan, and ipinfo.io
- **URL Analysis** — Scan URLs with URLScan.io and VirusTotal; auto-decodes SafeLinks and ProofPoint
- **Hash Check** — Check file hashes against VirusTotal (MD5, SHA1, SHA256, SHA512)
- **Username OSINT** — Search for usernames across 20+ platforms
- **DNS Tools** — DNS lookup and WHOIS queries
- **Decoders** — Decode Base64, SafeLinks, and ProofPoint encoded URLs
- **Risk Scoring** — Color-coded assessment: `critical` · `high` · `medium` · `low` · `unknown`
- **Report Export** — Save results as JSON, TXT, or HTML

---

## System Requirements

- Python 3.13+
- pip

## Installation

```bash
git clone https://github.com/0xTriSec/DragonflyX.git
cd DragonflyX
pip install -e .
cp .env.example .env
# Edit .env and add your API keys
```

---

## Quick Start

Before running any scan, verify your setup:

```bash
# 1. Check version
dragonflyx version

# 2. Verify API key configuration
dragonflyx config
```

---

## Usage

### IP Intelligence

Analyze an IP address against 4 threat intelligence sources. Returns risk score, geolocation, open ports, and abuse history.

```bash
dragonflyx ip <IP_ADDRESS>
```

### URL Analysis

Scan a URL using URLScan.io and VirusTotal. SafeLinks and ProofPoint-wrapped URLs are decoded automatically before analysis.

```bash
dragonflyx url <URL>
```

### Hash Check

Check a file hash against VirusTotal. Supports MD5, SHA1, SHA256, and SHA512.

```bash
# Check a known hash
dragonflyx hash <HASH>

# Hash a local file and check it
dragonflyx hash --file <PATH_TO_FILE>
```

### Username / OSINT

Search for a username across 20+ platforms. Returns found accounts and response times.

```bash
dragonflyx user <USERNAME>
```

### DNS Lookup

Perform DNS lookup and WHOIS query for a domain. Returns A, AAAA, MX, NS, TXT records and registration info.

```bash
dragonflyx dns <DOMAIN>
```

### Decode Strings

Decode various encoded strings or URLs.

```bash
# Decode Base64
dragonflyx decode --b64 "aHR0cHM6Ly9naXRodWIuY29t"

# Decode Microsoft SafeLinks
dragonflyx decode --safelinks "https://nam01.safelinks.protection.outlook.com/..."

# Decode ProofPoint URL
dragonflyx decode --proofpoint "https://urldefense.proofpoint.com/..."

# Auto-detect encoding type
dragonflyx decode --text "aGVsbG8="

# Auto-detect URL encoding
dragonflyx decode --url "https://encoded-url.com"
```

### Cache Management

```bash
dragonflyx cache stats   # Show cache statistics
dragonflyx cache clear   # Clear all cached results
```

---

## API Keys

DragonflyX requires API keys for most features. All services below offer a free tier:

| Service    | Signup                                   | Free Tier       |
|------------|------------------------------------------|-----------------|
| VirusTotal | https://www.virustotal.com               | 4 req/min       |
| AbuseIPDB  | https://www.abuseipdb.com                | 1,000 req/day   |
| URLScan.io | https://urlscan.io                       | 100 req/day     |
| Shodan     | https://www.shodan.io                    | 100 req/month   |

> **Note:** ipinfo.io works without an API key (50,000 req/month on the free tier).

## Configuration

Copy `.env.example` to `.env` and fill in your keys:

```env
VT_API_KEY=your_virustotal_api_key_here
AB_API_KEY=your_abuseipdb_api_key_here
URLSCAN_IO_KEY=your_urlscan_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
```

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
make test

# Run linting
make lint

# Format code
make format
```

## Project Structure

```
DragonflyX/
├── dragonflyX/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── modules/
│   │   ├── ip_intel/
│   │   ├── url_analysis/
│   │   ├── hash_check/
│   │   ├── identity.py
│   │   ├── dns_tools.py
│   │   └── decoders.py
│   ├── core/
│   │   ├── http_client.py
│   │   ├── rate_limiter.py
│   │   ├── cache.py
│   │   ├── validators.py
│   │   ├── exceptions.py
│   │   └── logger.py
│   └── output/
│       ├── console.py
│       ├── report.py
│       └── html_report.py
└── tests/
```

---

## Documentation

1. [ARCHITECTURE.md](study/ARCHITECTURE.md) — Technical design, data flow, module map, and contributor guide
2. [CHANGELOG.md](study/CHANGELOG.md) — Release history, features added, and known limitations

---

## License

[MIT License](LICENSE) · Built by [@0xTriSec](https://github.com/0xTriSec)