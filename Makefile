.PHONY: install dev test lint format clean \
        run-ip run-url run-hash run-dns run-decode run-user \
        version config cache-stats cache-clear help

# ── Setup ──────────────────────────────────────────────────────────────────────

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

# ── Code Quality ───────────────────────────────────────────────────────────────

test:
	pytest tests/ -v --asyncio-mode=auto

test-cov:
	pytest tests/ -v --asyncio-mode=auto --cov=dragonflyX --cov-report=term-missing

lint:
	ruff check dragonflyX/

format:
	ruff format dragonflyX/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	find . -name ".coverage" -delete

# ── Smoke Tests (uses real API calls — requires .env configured) ───────────────

# Google Public DNS — safe, always online, good for IP intel smoke test
run-ip:
	dragonflyx ip 1.1.1.1

# Known-clean domain — safe for URL scan smoke test
run-url:
	dragonflyx url https://example.com

# EICAR test file hash (SHA256) — industry-standard AV test, safe to query
run-hash:
	dragonflyx hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Generic TLD — safe for DNS smoke test
run-dns:
	dragonflyx dns example.com

# Decodes to: https://github.com
run-decode:
	dragonflyx decode --b64 "aHR0cHM6Ly9naXRodWIuY29t"

# Username check — placeholder, replace with a test username
run-user:
	dragonflyx user testuser123

# ── Utility ────────────────────────────────────────────────────────────────────

version:
	dragonflyx version

config:
	dragonflyx config

cache-stats:
	dragonflyx cache stats

cache-clear:
	dragonflyx cache clear

# ── Help ───────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  DragonflyX — Makefile targets"
	@echo ""
	@echo "  Setup"
	@echo "    install       Install package"
	@echo "    dev           Install with dev dependencies"
	@echo ""
	@echo "  Code Quality"
	@echo "    test          Run test suite"
	@echo "    test-cov      Run tests with coverage report"
	@echo "    lint          Run ruff linter"
	@echo "    format        Format code with ruff"
	@echo "    clean         Remove __pycache__ and .pyc files"
	@echo ""
	@echo "  Smoke Tests  (requires .env with API keys)"
	@echo "    run-ip        IP intel smoke test"
	@echo "    run-url       URL scan smoke test"
	@echo "    run-hash      Hash check smoke test (EICAR)"
	@echo "    run-dns       DNS lookup smoke test"
	@echo "    run-decode    Base64 decode smoke test"
	@echo "    run-user      Username OSINT smoke test"
	@echo ""
	@echo "  Utility"
	@echo "    version       Show DragonflyX version"
	@echo "    config        Show API key configuration status"
	@echo "    cache-stats   Show cache statistics"
	@echo "    cache-clear   Clear all cached results"
	@echo ""