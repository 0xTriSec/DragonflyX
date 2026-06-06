"""Console output module using Rich for formatted display."""

from __future__ import annotations

import pyfiglet
from rich import box as rich_box
from rich.console import Console
from rich.panel import Panel
from rich.status import Status
from rich.table import Table

from dragonflyX.core.exceptions import DragonflyXError
from dragonflyX.modules.dns_tools import DNSResult
from dragonflyX.modules.hash_check.schemas import HashCheckResult
from dragonflyX.modules.identity import IdentityResult
from dragonflyX.modules.ip_intel.schemas import IPIntelResult
from dragonflyX.modules.phone_intel import PhoneIntelResult
from dragonflyX.modules.url_analysis.schemas import URLAnalysisResult

console = Console()

RISK_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "bold color(208)",
    "medium": "bold yellow",
    "low": "bold green",
    "unknown": "dim white",
    "malicious": "bold red",
    "suspicious": "bold yellow",
    "clean": "bold green",
}

DEFAULT_NONE = "N/A"


def _none(value, fallback: str = DEFAULT_NONE) -> str:
    """Return value as string or fallback if None."""
    if value is None:
        return fallback
    return str(value)


def _truncate(value: str | None, length: int) -> str:
    """Truncate string to length."""
    if value is None:
        return DEFAULT_NONE
    s = str(value)
    return s[:length] + "..." if len(s) > length else s


def show_banner() -> None:
    """Display the DragonflyX ASCII banner."""
    ascii_art = pyfiglet.figlet_format("DragonflyX", font="slant")
    console.print(ascii_art, style="bold cyan")
    console.print("  OSINT  SOC  Intelligence  |  v2.0.0\n", style="dim cyan")


def show_spinner(message: str) -> Status:
    """Create a spinner status indicator."""
    return Status(message, spinner="dots", console=console)


def display_ip_result(result: IPIntelResult) -> None:
    """Display IP intelligence results."""
    risk_style = RISK_STYLES.get(result.risk_level, "dim white")

    # --- Panel header ---
    header_text = result.ip
    if result.cached:
        header_text += "  [dim](cached)[/dim]"
    console.print(Panel(header_text, title="IP Intelligence", border_style=risk_style))

    # --- Table 1: Summary (3 cot, 4 hang) ---
    t1 = Table(box=rich_box.ROUNDED, show_header=True, padding=(0, 1))
    t1.add_column("Source", style="bold", min_width=12)
    t1.add_column("Status", min_width=18)
    t1.add_column("Key Finding", min_width=40)

    # Hang VirusTotal
    if result.virustotal:
        vt = result.virustotal
        total = vt.total_engines or 1
        status_vt = f"{vt.malicious}/{total} engines"
        finding_vt = f"Malicious: {vt.malicious}, Reputation: {vt.reputation}"
    else:
        status_vt = "N/A"
        finding_vt = "Not available"
    t1.add_row("VirusTotal", status_vt, finding_vt)

    # Hang AbuseIPDB
    if result.abuseipdb:
        ab = result.abuseipdb
        status_ab = f"Score: {ab.abuse_score}/100"
        finding_ab = f"Reports: {ab.total_reports}, ISP: {ab.isp or 'N/A'}"
    else:
        status_ab = "N/A"
        finding_ab = "Not available"
    t1.add_row("AbuseIPDB", status_ab, finding_ab)

    # Hang Shodan
    if result.shodan:
        sh = result.shodan
        port_count = len(sh.open_ports)
        vuln_count = len(sh.vulns)
        status_sh = f"{port_count} open port{'s' if port_count != 1 else ''}"
        finding_sh = f"Vulns: {vuln_count}, OS: {sh.os or 'N/A'}"
    else:
        status_sh = "N/A"
        finding_sh = "Not available"
    t1.add_row("Shodan", status_sh, finding_sh)

    # Hang ipinfo
    if result.ipinfo and not result.ipinfo.is_bogon:
        geo = result.ipinfo.geo
        country = geo.country or "N/A"
        city = geo.city or "N/A"
        asn = geo.asn or "N/A"
        org = geo.org or "N/A"
        status_ip = f"{country} / {city}"
        finding_ip = f"ASN: {asn}, Org: {org}"
    elif result.ipinfo and result.ipinfo.is_bogon:
        status_ip = "Bogon/Private"
        finding_ip = "Private or reserved IP range"
    else:
        status_ip = "N/A"
        finding_ip = "Not available"
    t1.add_row("ipinfo", status_ip, finding_ip)

    console.print(t1)

    # --- Table 2: Open Ports (chi hien thi neu co du lieu, KHONG boc Panel) ---
    if result.shodan and result.shodan.services:
        t2 = Table(title="Open Ports", box=rich_box.ROUNDED, show_header=True, padding=(0, 1))
        t2.add_column("Port", style="cyan", min_width=6)
        t2.add_column("Protocol", min_width=8)
        t2.add_column("Service", min_width=12)
        t2.add_column("Banner", min_width=20)
        for svc in result.shodan.services:
            banner = (svc.banner or "")[:50]
            t2.add_row(
                str(svc.port),
                svc.protocol or "N/A",
                svc.service or "N/A",
                banner or "N/A",
            )
        console.print(t2)

    # --- Table 3: CVEs (chi hien thi neu co du lieu, KHONG boc Panel) ---
    if result.shodan and result.shodan.vulns:
        t3 = Table(title="CVEs", box=rich_box.ROUNDED, show_header=True, padding=(0, 1))
        t3.add_column("CVE ID", style="bold red", min_width=16)
        t3.add_column("CVSS", min_width=6)
        t3.add_column("Summary", min_width=40)
        for vuln in result.shodan.vulns:
            summary = (vuln.summary or "N/A")[:80]
            t3.add_row(
                vuln.cve_id,
                str(vuln.cvss) if vuln.cvss is not None else "N/A",
                summary,
            )
        console.print(t3)

    # --- Errors (chi hien thi neu co) ---
    if result.errors:
        console.print()
        for provider, msg in result.errors.items():
            console.print(f"  [dim red]Error ({provider}): {msg}[/dim red]")

    # --- Risk badge ---
    risk_label = result.risk_level.upper()
    console.print(f"\n  Risk: [{risk_style}]{risk_label}[/{risk_style}] ({result.risk_score}/100)\n")


def display_url_result(result: URLAnalysisResult) -> None:
    """Display URL analysis results."""
    risk_style = RISK_STYLES.get(result.risk_level, "dim white")

    # --- Panel header ---
    console.print(Panel(result.url, title="URL Analysis", border_style=risk_style))

    # --- Decoded URL (chi hien thi neu co) ---
    if result.decoded_url and result.decoded_url != result.url:
        console.print(
            f"  [yellow]Decoded ({result.encoding_type or 'unknown'}): {result.decoded_url}[/yellow]"
        )
        console.print()

    # --- Table: 4 cot (Source, Verdict, Score, Details) ---
    t = Table(box=rich_box.ROUNDED, show_header=True, padding=(0, 1))
    t.add_column("Source", style="bold", min_width=12)
    t.add_column("Verdict", min_width=10)
    t.add_column("Score", min_width=6)
    t.add_column("Details", min_width=30)

    # Hang URLScan
    if result.urlscan:
        us = result.urlscan
        verdict_us = "Malicious" if us.verdict_malicious else "Clean"
        score_us = str(us.verdict_score)
        details_us = f"IPs: {len(us.ips_found)}, Domains: {len(us.domains_found)}"
    else:
        verdict_us = "N/A"
        score_us = "N/A"
        details_us = "Not available"
    t.add_row("URLScan", verdict_us, score_us, details_us)

    # Hang VirusTotal
    if result.virustotal:
        vt = result.virustotal
        total = vt.total_engines or 1
        verdict_vt = f"{vt.malicious}/{total}"
        score_vt = str(total)
        details_vt = f"Malicious: {vt.malicious}, Suspicious: {vt.suspicious}"
    else:
        verdict_vt = "N/A"
        score_vt = "N/A"
        details_vt = "Not available"
    t.add_row("VirusTotal", verdict_vt, score_vt, details_vt)

    console.print(t)

    # --- Errors ---
    if result.errors:
        console.print()
        for provider, msg in result.errors.items():
            console.print(f"  [dim red]Error ({provider}): {msg}[/dim red]")

    # --- Risk badge ---
    risk_label = result.risk_level.upper()
    console.print(f"\n  Risk: [{risk_style}]{risk_label}[/{risk_style}] ({result.risk_score}/100)\n")


def _format_bytes(size: int | None) -> str:
    """Format bytes to human readable."""
    if size is None:
        return DEFAULT_NONE
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _format_date(dt) -> str:
    """Format datetime to string."""
    if dt is None:
        return DEFAULT_NONE
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    return str(dt)


def display_hash_result(result: HashCheckResult) -> None:
    """Display hash check results."""
    risk_style = RISK_STYLES.get(result.risk_level, "dim white")

    # File info panel
    info_lines = [
        f"[cyan]Hash:[/cyan] {result.hash_value}",
        f"[cyan]Type:[/cyan] {result.hash_type.upper()}",
        f"[cyan]Size:[/cyan] {_format_bytes(result.file_size)}",
        f"[cyan]File Type:[/cyan] {_none(result.file_type)}",
    ]
    if result.meaningful_name:
        info_lines.append(f"[cyan]Name:[/cyan] {result.meaningful_name}")
    info_lines.extend([
        f"[cyan]First Seen:[/cyan] {_format_date(result.first_seen)}",
        f"[cyan]Last Seen:[/cyan] {_format_date(result.last_seen)}",
    ])
    console.print(Panel("\n".join(info_lines), title="File Information", border_style="blue"))

    # Detection panel
    total = result.total_engines
    detection_text = f"[bold]{result.malicious_count}/{total}[/bold] engines detected"
    if result.malicious_count > 0:
        detection_text += f" ({result.detection_ratio})"
    console.print(detection_text)

    # Top detections table
    if result.top_detections:
        detections_table = Table(
            title="Top Detections",
            box=rich_box.ROUNDED,
            show_header=True,
            padding=(0, 1),
        )
        detections_table.add_column("Engine", style="bold cyan", min_width=20)
        detections_table.add_column("Category", min_width=12)
        detections_table.add_column("Malware Name", min_width=30)

        for detection in result.top_detections:
            cat_style = "bold red" if detection.category == "malicious" else "bold yellow"
            detections_table.add_row(
                _truncate(detection.engine_name, 40),
                f"[{cat_style}]{detection.category}[/{cat_style}]",
                _truncate(_none(detection.result), 40),
            )

        console.print(detections_table)

    # Risk badge
    risk_label = result.risk_level.upper()
    console.print(f"\n  Risk: [{risk_style}]{risk_label}[/{risk_style}] ({result.risk_score}/100)\n")


def display_identity_result(result: IdentityResult) -> None:
    """Display username/email OSINT results."""
    # Tinh total_checked
    total_count = len(result.found) + len(result.not_found) + result.error_count
    found_count = len(result.found)

    console.print(Panel(
        f"{found_count}/{total_count} platforms found for {result.query}",
        title="Identity OSINT",
        border_style="cyan",
    ))

    # --- Table: 3 cot (chi hien thi neu co ket qua) ---
    if result.found:
        t = Table(box=rich_box.ROUNDED, show_header=True, padding=(0, 1))
        t.add_column("Platform", style="bold", min_width=12)
        t.add_column("URL", style="cyan", min_width=36)
        t.add_column("Response Time", justify="right", min_width=12)

        for p in result.found:
            rt_str = f"{p.response_time_ms}ms" if p.response_time_ms is not None else "N/A"
            t.add_row(p.platform, p.url, rt_str)

        console.print(t)

    # --- Not found (chi hien thi neu co) ---
    if result.not_found:
        not_found_str = ", ".join(result.not_found)
        console.print(f"  [dim]Not found: {not_found_str}[/dim]")

    # --- Errors ---
    if result.error_count > 0:
        console.print(f"  [dim red]Errors: {result.error_count} platforms timed out or failed[/dim red]")

    console.print()


def _format_whois_value(value) -> str | None:
    """Format WHOIS field for display."""
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(v) for v in value[:5])
    if isinstance(value, str) and len(value) > 100:
        return value[:100] + "..."
    return str(value)


def display_dns_result(result: DNSResult) -> None:
    """Display DNS lookup results."""
    console.print(Panel(result.domain, title="DNS Lookup", border_style="blue"))

    # Map cac record type
    record_types = [
        ("A", result.a),
        ("AAAA", result.aaaa),
        ("MX", result.mx),
        ("NS", result.ns),
        ("TXT", result.txt),
        ("CNAME", result.cname),
        ("SOA", result.soa),
    ]

    # --- Mot table cho moi record type (chi hien thi neu co record) ---
    for rtype, records in record_types:
        if not records:
            continue
        t = Table(
            title=f"{rtype} Records",
            box=rich_box.ROUNDED,
            show_header=False,
            padding=(0, 1),
        )
        t.add_column("Value", style="cyan", min_width=20)
        for rec in records:
            t.add_row(rec)
        console.print(t)

    # --- WhoIs panel (chi hien thi neu co du lieu) ---
    if result.whois:
        w = result.whois
        lines = []

        registrar = w.get("registrar") or w.get("Registrar")
        if registrar:
            lines.append(f"Registrar: {_format_whois_value(registrar)}")

        domain_name = w.get("domain_name") or w.get("domain") or w.get("Domain Name")
        if domain_name:
            lines.append(f"Domain Name: {_format_whois_value(domain_name)}")

        # Creation date - co the la list
        created = w.get("creation_date") or w.get("created") or w.get("Created") or w.get("registered_on")
        if created:
            if isinstance(created, list):
                created = str(created[0])
            lines.append(f"Created: {_format_whois_value(created)}")

        # Expiration date
        expires = w.get("expiration_date") or w.get("expires") or w.get("Expires") or w.get("expires_on")
        if expires:
            if isinstance(expires, list):
                expires = str(expires[0])
            lines.append(f"Expires: {_format_whois_value(expires)}")

        # Updated date
        updated = w.get("updated_date") or w.get("updated") or w.get("Updated") or w.get("updated_on")
        if updated:
            if isinstance(updated, list):
                updated = str(updated[0])
            lines.append(f"Updated: {_format_whois_value(updated)}")

        # Name servers
        name_servers = w.get("name_servers") or w.get("nameservers") or w.get("Name Servers")
        if name_servers:
            ns_str = _format_whois_value(name_servers)
            if ns_str:
                lines.append(f"Name Servers: {ns_str}")

        if lines:
            console.print(Panel("\n".join(lines), title="WHOIS", border_style="dim"))

    if result.subdomains:
        if any(item.is_wildcard for item in result.subdomains):
            console.print("  Warning: wildcard DNS detected; some subdomain results may be generic", style="yellow")

        t = Table(
            title="Subdomain Results",
            box=rich_box.ROUNDED,
            show_header=True,
            padding=(0, 1),
        )
        t.add_column("Hostname", style="cyan", min_width=20)
        t.add_column("IP Addresses", min_width=20)
        t.add_column("Wildcard", min_width=10)
        for subdomain in result.subdomains:
            ip_addresses = ", ".join(subdomain.ip_addresses) if subdomain.ip_addresses else "N/A"
            wildcard = "Yes" if subdomain.is_wildcard else "No"
            t.add_row(subdomain.hostname, ip_addresses, wildcard)
        console.print(t)

    # --- Errors (chi hien thi neu co) ---
    if result.errors:
        error_lines = [f"- {err}" for err in result.errors]
        console.print(Panel("\n".join(error_lines), title="Errors", border_style="dim red"))

    console.print()


def display_phone_result(result: PhoneIntelResult) -> None:
    """Display phone number intelligence results."""
    console.print(Panel(result.phone_number, title="Phone Intel", border_style="cyan"))

    t = Table(box=rich_box.ROUNDED, show_header=True, padding=(0, 1))
    t.add_column("Field", style="bold", min_width=16)
    t.add_column("Value", min_width=24)
    t.add_row("E.164 Format", result.formatted_e164)
    t.add_row("National Format", result.formatted_national)
    t.add_row("Country", f"{result.country_name} ({result.country_code})")
    t.add_row("Carrier", result.carrier or "Unknown")
    t.add_row("Line Type", result.line_type)
    t.add_row("Valid", "Yes" if result.is_valid else "No")
    t.add_row("Possible", "Yes" if result.is_possible else "No")
    console.print(t)

    if not result.is_valid:
        console.print("  Number is not valid — metadata may be incomplete", style="yellow")

    if result.errors:
        console.print()
        for error in result.errors:
            console.print(f"  {error}", style="dim red")

    console.print()


def display_dorks_result(results: list) -> None:
    """Display generated dork queries grouped by category."""
    from dragonflyX.modules.dorks_generator import DorkResult

    if not results:
        console.print(Panel(
            "No dorks generated.",
            title="Dorks Generator",
            border_style="cyan",
        ))
        console.print()
        return

    target = results[0].query if results else ""
    console.print(Panel(
        f"{len(results)} dorks — {target}",
        title="Dorks Generator",
        border_style="cyan",
    ))

    grouped: dict[str, list[DorkResult]] = {}
    for dork in results:
        grouped.setdefault(dork.category, []).append(dork)

    for category in ["IDENTITY", "CREDENTIALS & LEAKS", "INFRASTRUCTURE", "TECHNICAL EXPOSURE"]:
        if category not in grouped:
            continue
        t = Table(
            title=f"{category} ({len(grouped[category])})",
            box=rich_box.ROUNDED,
            show_header=True,
            padding=(0, 1),
        )
        t.add_column("Query", style="cyan", min_width=45)
        t.add_column("Description", min_width=35)

        for dork in grouped[category]:
            t.add_row(dork.query, dork.description)
            console.print(f"  {dork.url}", style="dim")

        console.print(t)

    console.print(f"  {len(results)} dorks generated\n")


def _fmt_size(n: int) -> str:
    """Format bytes to human readable string."""
    if n == 0:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def display_paste_result(results: list) -> None:
    """Display paste search results."""

    if not results:
        console.print(Panel(
            "No pastes found.",
            title="Paste Search",
            border_style="yellow",
        ))
        console.print()
        return

    console.print(Panel(
        f"{len(results)} paste(s) found",
        title="Paste Search",
        border_style="yellow",
    ))

    t = Table(
        title="Results",
        box=rich_box.ROUNDED,
        show_header=True,
        padding=(0, 1),
    )
    t.add_column("ID", style="cyan", min_width=14, max_width=14)
    t.add_column("Date", min_width=19)
    t.add_column("Size", min_width=8, justify="right")
    t.add_column("Tags", min_width=20)
    t.add_column("URL", style="dim", min_width=35)

    for paste in results:
        paste_id_str = paste.paste_id[:12]
        date_str = paste.date[:19].replace("T", " ") if paste.date else "N/A"
        size_str = _fmt_size(paste.size)
        tags_str = ", ".join(paste.tags[:3]) if paste.tags else "N/A"
        url_str = paste.url[:50] + ("..." if len(paste.url) > 50 else "")

        t.add_row(paste_id_str, date_str, size_str, tags_str, url_str)

    console.print(t)
    console.print()


def display_error(error: DragonflyXError) -> None:
    """Display an error message."""
    console.print(
        Panel(
            f"[bold]{error.user_friendly}[/bold]",
            title="Error",
            border_style="red",
        )
    )
