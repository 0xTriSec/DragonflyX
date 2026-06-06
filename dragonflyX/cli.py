"""DragonflyX CLI - Main command-line interface."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich import box as rich_box
from rich.table import Table

from dragonflyX import __version__
from dragonflyX.config import KEY_MAP, settings, validate_keys
from dragonflyX.core.cache import cache as cm
from dragonflyX.core.exceptions import DragonflyXError, InvalidInput
from dragonflyX.core.logger import setup_logger
from dragonflyX.modules.decoders import (
    decode_proofpoint,
    decode_safelinks,
    decode_string,
    decode_url,
)
from dragonflyX.modules.dns_tools import lookup_domain
from dragonflyX.modules.dorks_generator import generate_dorks
from dragonflyX.modules.hash_check import check_file, check_hash
from dragonflyX.modules.identity import scan_email, scan_username
from dragonflyX.modules.ip_intel import analyze_ip
from dragonflyX.modules.paste_search import search_paste
from dragonflyX.modules.phone_intel import lookup_phone
from dragonflyX.modules.url_analysis import analyze_url
from dragonflyX.output.console import (
    console,
    display_dns_result,
    display_dorks_result,
    display_error,
    display_hash_result,
    display_identity_result,
    display_ip_result,
    display_paste_result,
    display_phone_result,
    display_url_result,
    show_banner,
    show_spinner,
)
from dragonflyX.output.html_report import save_and_open
from dragonflyX.output.report import save_report

app = typer.Typer(
    name="dragonflyx",
    help="DragonflyX — OSINT + SOC Intelligence Tool",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)


def _run_command(
    coro,
    debug: bool,
    output: Path | None,
    html: bool,
    display_fn,
    use_html: bool = True,
) -> None:
    """Execute a coroutine and display results."""
    setup_logger(debug=debug)
    show_banner()
    validate_keys()

    try:
        with show_spinner("Analyzing..."):
            result = asyncio.run(coro)

        display_fn(result)

        if output is not None:
            fmt = "json" if str(output).endswith(".json") else "txt"
            saved = save_report(result, output, fmt)
            console.print(f"Report saved: {saved}", style="dim green")

        if use_html and html:
            path = save_and_open([result])
            console.print(f"HTML report: {path}", style="dim green")

    except InvalidInput as e:
        display_error(e)
        raise typer.Exit(code=1)
    except DragonflyXError as e:
        display_error(e)
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        console.print("\nCancelled.", style="yellow")
        raise typer.Exit(code=0)


@app.command()
def ip(
    target: str = typer.Argument(..., help="IP address to analyze (IPv4 or IPv6)"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save report (.json or .txt)"),
    html: bool = typer.Option(False, "--html", help="Generate and open HTML report"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache, force fresh queries"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
) -> None:
    """Analyze an IP address using VirusTotal, AbuseIPDB, Shodan, and ipinfo.io."""
    _run_command(
        analyze_ip(target, use_cache=not no_cache),
        debug,
        output,
        html,
        display_ip_result,
    )


@app.command()
def url(
    target: str = typer.Argument(..., help="URL to analyze"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    html: bool = typer.Option(False, "--html"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Analyze a URL using URLScan.io and VirusTotal. Auto-decodes SafeLinks and ProofPoint."""
    _run_command(
        analyze_url(target, use_cache=not no_cache),
        debug,
        output,
        html,
        display_url_result,
    )


@app.command(name="hash")
def hash_cmd(
    target: str | None = typer.Argument(None, help="Hash value (MD5, SHA1, or SHA256)"),
    file: Path | None = typer.Option(None, "--file", "-f", help="Hash a local file"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    html: bool = typer.Option(False, "--html"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Check a file hash or local file against VirusTotal.

    Examples:
      dragonflyx hash d41d8cd98f00b204e9800998ecf8427e
      dragonflyx hash --file ./suspicious.exe
    """
    if target is None and file is None:
        console.print("Provide a hash value or use --file to hash a local file.", style="red")
        raise typer.Exit(code=1)

    if target is not None and file is not None:
        console.print("Provide either a hash value or --file, not both.", style="red")
        raise typer.Exit(code=1)

    if file is not None:
        coro = check_file(str(file), use_cache=not no_cache)
    else:
        coro = check_hash(target, use_cache=not no_cache)

    _run_command(coro, debug, output, html, display_hash_result)


@app.command()
def user(
    target: str = typer.Argument(..., help="Username or email address"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Search a username or email across 20 platforms."""
    if "@" in target:
        coro = scan_email(target, use_cache=not no_cache)
    else:
        coro = scan_username(target, use_cache=not no_cache)

    _run_command(coro, debug, output, False, display_identity_result, use_html=False)


@app.command()
def dns(
    target: str = typer.Argument(..., help="Domain to look up"),
    records: str = typer.Option("A,AAAA,MX,NS,TXT", "--records", "-r", help="Record types, comma-separated"),
    subdomains: bool = typer.Option(
        False,
        "--subdomains",
        "-s",
        help="Enumerate subdomains using a built-in wordlist",
    ),
    output: Path | None = typer.Option(None, "--output", "-o"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """DNS lookup and WhoIs for a domain."""
    _run_command(
        lookup_domain(target, use_cache=not no_cache, enumerate_subs=subdomains),
        debug,
        output,
        False,
        display_dns_result,
        use_html=False,
    )


@app.command(name="phone")
def phone_cmd(
    target: str = typer.Argument(..., help="Phone number to analyze"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Look up carrier, region, and line type for a phone number."""
    _run_command(
        lookup_phone(target, use_cache=not no_cache),
        debug,
        output,
        False,
        display_phone_result,
        use_html=False,
    )


@app.command()
def decode(
    b64: str | None = typer.Option(None, "--b64", help="Decode Base64 string"),
    safelinks: str | None = typer.Option(None, "--safelinks", help="Decode Microsoft SafeLinks URL"),
    proofpoint: str | None = typer.Option(None, "--proofpoint", help="Decode ProofPoint URL"),
    text: str | None = typer.Option(None, "--text", help="Try all decodings on a string"),
    url_input: str | None = typer.Option(None, "--url", help="Auto-detect encoding on a URL"),
) -> None:
    """Decode encoded strings and URLs.

    Examples:
      dragonflyx decode --b64 "aHR0cHM6Ly9naXRodWIuY29t"
      dragonflyx decode --safelinks "https://nam01.safelinks.protection.outlook.com/..."
      dragonflyx decode --text "aGVsbG8gd29ybGQ="
    """
    if b64:
        results = decode_string(b64)
        console.print(f"[cyan]Base64:[/cyan] {results.get('base64', 'Could not decode')}")
    elif safelinks:
        result = decode_safelinks(safelinks)
        console.print(f"[cyan]SafeLinks decoded:[/cyan] {result or 'Not a SafeLinks URL'}")
    elif proofpoint:
        result = decode_proofpoint(proofpoint)
        console.print(f"[cyan]ProofPoint decoded:[/cyan] {result or 'Not a ProofPoint URL'}")
    elif text:
        results = decode_string(text)
        if results:
            for enc, val in results.items():
                console.print(f"[cyan]{enc}:[/cyan] {val}")
        else:
            console.print("No known encodings detected.", style="dim")
    elif url_input:
        decoded, enc = decode_url(url_input)
        if enc:
            console.print(f"[cyan]Encoding:[/cyan] {enc}")
            console.print(f"[cyan]Decoded:[/cyan] {decoded}")
        else:
            console.print("No encoding detected. URL appears clean.", style="dim green")
    else:
        console.print(
            "Provide one of: --b64 --safelinks --proofpoint --text --url",
            style="yellow",
        )
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show DragonflyX version."""
    console.print(f"DragonflyX v{__version__}", style="bold cyan")


@app.command()
def cache(
    action: str = typer.Argument("stats", help="Action: stats or clear"),
) -> None:
    """Manage the local cache.

    Examples:
      dragonflyx cache stats
      dragonflyx cache clear
    """
    if action == "stats":
        stats = cm.stats()
        for key, val in stats.items():
            console.print(f"[cyan]{key}:[/cyan] {val}")
    elif action == "clear":
        cm.clear_all()
        console.print("Cache cleared.", style="bold green")
    else:
        console.print(f"Unknown action '{action}'. Use 'stats' or 'clear'.", style="red")
        raise typer.Exit(code=1)


@app.command(name="config")
def config_show() -> None:
    """Show current configuration and API key status."""
    t = Table("API", "Configured", "Env Variable", box=rich_box.ROUNDED)
    for api, (attr, env_var) in KEY_MAP.items():
        configured = bool(getattr(settings, attr, ""))
        status = "[green]YES[/green]" if configured else "[red]NO[/red]"
        t.add_row(api, status, env_var)
    console.print(t)


@app.command(name="dorks")
def dorks_cmd(
    target: str = typer.Argument(..., help="Domain, email, username, or organization name"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save results to file"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
) -> None:
    """Generate OSINT Google Dorks for a target."""
    _run_command(
        generate_dorks(target),
        debug,
        output,
        False,
        display_dorks_result,
        use_html=False,
    )


@app.command(name="paste")
def paste_cmd(
    target: str = typer.Argument(..., help="Email, username, domain, or IP to search"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save results to file"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
) -> None:
    """Search public paste sites for leaked data related to a target."""
    _run_command(
        search_paste(target, use_cache=not no_cache),
        debug,
        output,
        False,
        display_paste_result,
        use_html=False,
    )


if __name__ == "__main__":
    app()
