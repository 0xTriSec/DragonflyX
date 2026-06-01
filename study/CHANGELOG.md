# Changelog

All notable changes to DragonflyX are documented in this file.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.0.0] - 2026-6-1

Initial public release.

---

### Added

#### Modules

- **IP Intelligence** (`dragonflyx ip`): Query VirusTotal, AbuseIPDB, Shodan, and ipinfo.io concurrently. Returns a combined risk score, geolocation, ASN info, open ports, CVEs, and abuse history.
- **URL Analysis** (`dragonflyx url`): Submit URLs to URLScan.io and VirusTotal. Automatically decodes Microsoft SafeLinks and ProofPoint-wrapped URLs before analysis.
- **Hash Check** (`dragonflyx hash`): Look up MD5, SHA1, SHA256, and SHA512 hashes against the VirusTotal database. Use `--file` to hash a local file on the fly before querying.
- **Username OSINT** (`dragonflyx user`): Scan a username across 20+ social media and web platforms using concurrent HTTP HEAD requests. Reports found accounts and response times.
- **DNS Tools** (`dragonflyx dns`): Perform DNS lookups for A, AAAA, MX, NS, TXT, CNAME, and SOA records, plus WHOIS registration data.
- **Decoders** (`dragonflyx decode`): Decode Base64, Microsoft SafeLinks, and ProofPoint URL-defense wrappers. Supports `--b64`, `--safelinks`, `--proofpoint`, `--text` (auto-detect), and `--url` (auto-detect URL encoding) flags.

#### CLI Commands

| Command | Description |
|---|---|
| `dragonflyx ip <IP>` | Analyze an IP address against 4 threat intelligence providers |
| `dragonflyx url <URL>` | Scan a URL with URLScan.io and VirusTotal |
| `dragonflyx hash <HASH>` | Check a file hash against VirusTotal |
| `dragonflyx hash --file <PATH>` | Hash a local file and check it against VirusTotal |
| `dragonflyx user <USERNAME>` | OSINT scan across 20+ platforms |
| `dragonflyx dns <DOMAIN>` | DNS lookup and WHOIS query |
| `dragonflyx decode --b64 <STRING>` | Decode a Base64 string |
| `dragonflyx decode --safelinks <URL>` | Decode a Microsoft SafeLinks URL |
| `dragonflyx decode --proofpoint <URL>` | Decode a ProofPoint URL-defense URL |
| `dragonflyx decode --text <STRING>` | Auto-detect and decode an encoded string |
| `dragonflyx decode --url <URL>` | Auto-detect and decode an encoded URL |
| `dragonflyx cache stats` | Show cache statistics |
| `dragonflyx cache clear` | Clear all cached results |
| `dragonflyx config` | Display API key configuration status |
| `dragonflyx version` | Show version |

#### Core Infrastructure

- **Async Parallel Execution**: All provider calls for a given command run concurrently via `asyncio.TaskGroup` (Python 3.11+). A single provider failure does not block results from others.
- **Per-API Rate Limiting**: `asyncio.Semaphore`-based rate limiter in `core/rate_limiter.py` enforces per-source request limits to stay within free-tier quotas.
- **Disk Cache**: TTL-based result caching via `diskcache`. Cache survives process restarts and reduces redundant API calls across CLI sessions.

| Provider   | Cache TTL |
|------------|-----------|
| VirusTotal | 6 hours   |
| AbuseIPDB  | 3 hours   |
| Shodan     | 6 hours   |
| ipinfo.io  | 24 hours  |
| DNS        | 30 minutes|

- **Risk Scoring**: Composite risk score (0–100) computed from aggregated provider findings. Displayed with color-coded severity levels: `critical`, `high`, `medium`, `low`, `unknown`.
- **Report Export**: Save results as JSON, plain TXT, or HTML. HTML reports use a dark-themed layout with risk-colored cards and detection summary bars.
- **Input Validation**: Dedicated `core/validators.py` validates IP addresses, URLs, hashes, and domains before any network call is made.
- **Structured Logging**: `loguru`-based logging configured in `core/logger.py`. Verbose output available via `--debug` flag.

#### API Integrations

| Service | Free Tier | Required |
|---|---|---|
| VirusTotal | 4 req/min | Yes |
| AbuseIPDB | 1,000 req/day | Yes |
| URLScan.io | 100 req/day | Yes |
| Shodan | 100 req/month | Yes |
| ipinfo.io | 50,000 req/month (no key) | No |

---

### Known Limitations

- **Username OSINT**: Platform coverage is limited to services with predictable username-based profile URLs. Platforms requiring authentication or JavaScript rendering are not supported.
- **WHOIS Parsing**: Relies on `python-whois`, which may return incomplete or inconsistent data for certain TLDs.
- **No Startup Key Validation**: API keys are not verified at launch. Invalid keys surface as errors at query time.
- **IPv6 Support**: Full enrichment for IPv6 addresses is limited to ipinfo.io; VirusTotal, AbuseIPDB, and Shodan coverage varies by address type.
- **Rate Limits**: Default semaphore values in `core/rate_limiter.py` are conservative for free-tier accounts. Users with higher-quota plans may adjust these values manually.
- **URL Analysis Wait Time**: URLScan.io scans are asynchronous; DragonflyX polls for results with a short delay, which may time out on slow scans.

---

### Dependencies

- Python 3.13+
- `httpx` — async HTTP client
- `typer` — CLI framework
- `rich` — terminal output formatting
- `pydantic` — data validation and schemas
- `diskcache` — persistent disk-based caching
- `loguru` — structured logging
- `dnspython` — DNS resolution
- `python-whois` — WHOIS queries