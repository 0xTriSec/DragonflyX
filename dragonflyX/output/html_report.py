"""HTML report generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dragonflyX.output.report import _serialize

REPORTS_DIR = Path.home() / ".dragonflyX" / "reports"

RISK_COLORS_HTML: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "unknown": "#6b7280",
    "malicious": "#dc2626",
    "suspicious": "#ea580c",
    "clean": "#16a34a",
}

RISK_BG_HTML: dict[str, str] = {
    "critical": "rgba(220, 38, 38, 0.15)",
    "high": "rgba(234, 88, 12, 0.15)",
    "medium": "rgba(202, 138, 4, 0.15)",
    "low": "rgba(22, 163, 74, 0.15)",
    "unknown": "rgba(107, 114, 128, 0.15)",
    "malicious": "rgba(220, 38, 38, 0.15)",
    "suspicious": "rgba(234, 88, 12, 0.15)",
    "clean": "rgba(22, 163, 74, 0.15)",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DragonflyX Threat Intelligence Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 0;
      background: #f8fafc;
      color: #1e293b;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
    }

    /* === HEADER === */
    .report-header {
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
      color: #f8fafc;
      padding: 2rem 2rem 1.5rem;
      border-bottom: 3px solid #0ea5e9;
    }
    .report-header h1 {
      margin: 0 0 0.25rem;
      font-size: 1.75rem;
      font-weight: 700;
      letter-spacing: -0.025em;
    }
    .report-header .subtitle {
      font-size: 0.875rem;
      opacity: 0.7;
      margin-bottom: 1rem;
    }
    .header-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 1.5rem;
      font-size: 0.8125rem;
    }
    .header-meta-item {
      display: flex;
      align-items: center;
      gap: 0.375rem;
    }
    .header-meta-label {
      opacity: 0.6;
      text-transform: uppercase;
      font-size: 0.6875rem;
      letter-spacing: 0.05em;
    }
    .header-meta-value {
      font-weight: 600;
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    }

    /* === SUMMARY BAR === */
    .summary-bar {
      background: #ffffff;
      border-bottom: 1px solid #e2e8f0;
      padding: 1rem 2rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1.5rem;
      align-items: center;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .summary-label {
      font-size: 0.75rem;
      font-weight: 600;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-right: 0.5rem;
    }
    .risk-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      border: 1px solid currentColor;
    }
    .risk-pill .count {
      font-weight: 700;
    }
    .summary-total {
      margin-left: auto;
      font-size: 0.8125rem;
      color: #64748b;
    }

    /* === MAIN CONTENT === */
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 1.5rem 2rem 3rem;
    }

    /* === RESULT CARDS === */
    .results-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 1.25rem;
    }
    @media (min-width: 768px) {
      .results-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    .result-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      break-inside: avoid;
    }
    .result-card:hover {
      box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }

    /* Card Header */
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.875rem 1.125rem;
      border-bottom: 1px solid #f1f5f9;
      background: #fafbfc;
      gap: 0.75rem;
    }
    .card-header-left {
      display: flex;
      align-items: center;
      gap: 0.625rem;
      min-width: 0;
    }
    .result-type-badge {
      display: inline-block;
      padding: 0.125rem 0.5rem;
      background: #0ea5e9;
      color: white;
      border-radius: 4px;
      font-size: 0.6875rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      flex-shrink: 0;
    }
    .result-type-badge.ip     { background: #7c3aed; }
    .result-type-badge.url    { background: #0ea5e9; }
    .result-type-badge.hash   { background: #ea580c; }
    .result-type-badge.user   { background: #0891b2; }
    .result-type-badge.dns    { background: #16a34a; }
    .result-type-badge.default { background: #64748b; }

    .result-identifier {
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      font-size: 0.875rem;
      font-weight: 600;
      color: #1e293b;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .risk-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
      padding: 0.1875rem 0.625rem;
      border-radius: 9999px;
      font-size: 0.6875rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      flex-shrink: 0;
    }

    /* Card Body */
    .card-body {
      padding: 1rem 1.125rem;
    }

    .card-section {
      margin-bottom: 0.875rem;
    }
    .card-section:last-child {
      margin-bottom: 0;
    }
    .card-section-title {
      font-size: 0.6875rem;
      font-weight: 700;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-bottom: 0.5rem;
    }

    /* Data Grid */
    .data-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
      gap: 0.375rem;
    }
    .data-item {
      background: #f8fafc;
      border: 1px solid #f1f5f9;
      border-radius: 6px;
      padding: 0.375rem 0.625rem;
    }
    .data-item-label {
      font-size: 0.625rem;
      font-weight: 600;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 0.125rem;
    }
    .data-item-value {
      font-size: 0.875rem;
      font-weight: 600;
      color: #1e293b;
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    }
    .data-item-value.highlight-red { color: #dc2626; }
    .data-item-value.highlight-orange { color: #ea580c; }
    .data-item-value.highlight-green { color: #16a34a; }

    /* Detection Bar */
    .detection-bar {
      background: #f1f5f9;
      border-radius: 6px;
      padding: 0.5rem 0.75rem;
      margin-bottom: 0.5rem;
    }
    .detection-bar-header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      margin-bottom: 0.375rem;
    }
    .detection-bar-label {
      font-size: 0.75rem;
      font-weight: 600;
      color: #64748b;
    }
    .detection-bar-ratio {
      font-size: 0.875rem;
      font-weight: 700;
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    }
    .detection-bar-track {
      height: 6px;
      background: #e2e8f0;
      border-radius: 3px;
      overflow: hidden;
      display: flex;
    }
    .detection-bar-fill {
      height: 100%;
      border-radius: 3px;
      transition: width 0.3s ease;
    }

    /* Tags */
    .tags-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.375rem;
    }
    .tag {
      display: inline-block;
      background: #f1f5f9;
      border: 1px solid #e2e8f0;
      border-radius: 4px;
      padding: 0.125rem 0.5rem;
      font-size: 0.6875rem;
      font-weight: 500;
      color: #64748b;
    }

    /* Port List */
    .port-list {
      display: flex;
      flex-wrap: wrap;
      gap: 0.375rem;
    }
    .port-chip {
      background: #0f172a;
      color: #38bdf8;
      border-radius: 4px;
      padding: 0.125rem 0.5rem;
      font-size: 0.75rem;
      font-weight: 600;
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    }

    /* Error Box */
    .error-box {
      background: #fef2f2;
      border: 1px solid #fecaca;
      border-radius: 6px;
      padding: 0.5rem 0.75rem;
      font-size: 0.8125rem;
      color: #dc2626;
    }

    /* JSON Details */
    details {
      margin-top: 0.875rem;
      border-top: 1px solid #f1f5f9;
      padding-top: 0.875rem;
    }
    summary {
      cursor: pointer;
      font-size: 0.75rem;
      font-weight: 600;
      color: #64748b;
      user-select: none;
      list-style: none;
      display: flex;
      align-items: center;
      gap: 0.375rem;
    }
    summary::before {
      content: "▶";
      font-size: 0.625rem;
      transition: transform 0.15s;
    }
    details[open] summary::before {
      transform: rotate(90deg);
    }
    .json-block {
      margin-top: 0.75rem;
      background: #0f172a;
      color: #e2e8f0;
      border-radius: 6px;
      padding: 0.75rem;
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      font-size: 0.75rem;
      line-height: 1.6;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 400px;
      overflow-y: auto;
    }
    .json-key { color: #7dd3fc; }
    .json-string { color: #86efac; }
    .json-number { color: #fcd34d; }
    .json-boolean { color: #f9a8d4; }
    .json-null { color: #94a3b8; }

    /* Footer */
    .report-footer {
      text-align: center;
      padding: 1.5rem 2rem;
      border-top: 1px solid #e2e8f0;
      color: #94a3b8;
      font-size: 0.75rem;
    }
    .report-footer strong {
      color: #64748b;
    }

    /* Print Stylesheet */
    @media print {
      body { background: white; color: black; font-size: 11pt; }
      .report-header {
        background: #1e293b !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
        color: white !important;
      }
      .report-header h1 { color: white !important; }
      .summary-bar {
        background: white !important;
        border-bottom: 2px solid #1e293b;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      .risk-pill {
        border: 1px solid currentColor !important;
        background: transparent !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      .result-card {
        break-inside: avoid;
        box-shadow: none !important;
        border: 1px solid #1e293b;
      }
      .card-header { background: #f8fafc !important; }
      .data-item { background: white !important; border: 1px solid #e2e8f0 !important; }
      .detection-bar { background: #f1f5f9 !important; }
      .port-chip { background: #1e293b !important; color: white !important; }
      .tag { background: white !important; border: 1px solid #1e293b !important; }
      .json-block { background: white !important; color: black !important; border: 1px solid #1e293b; }
      details summary::before { display: none; }
      a { color: black; text-decoration: underline; }
    }
  </style>
</head>
<body>

<!-- HEADER -->
<header class="report-header">
  <h1>DragonflyX Threat Intelligence Report</h1>
  <p class="subtitle">OSINT &amp; SOC Intelligence Analysis</p>
  <div class="header-meta">
    <div class="header-meta-item">
      <span class="header-meta-label">Generated</span>
      <span class="header-meta-value">{{ generated_at }}</span>
    </div>
    <div class="header-meta-item">
      <span class="header-meta-label">Case ID</span>
      <span class="header-meta-value">{{ case_id }}</span>
    </div>
    <div class="header-meta-item">
      <span class="header-meta-label">Tool</span>
      <span class="header-meta-value">DragonflyX v2.0.0</span>
    </div>
  </div>
</header>

<!-- SUMMARY BAR -->
<div class="summary-bar">
  <span class="summary-label">Summary</span>
  {% set counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0, 'malicious': 0, 'suspicious': 0, 'clean': 0} %}
  {% for result in results %}
    {% set rl = get_risk_level(result) %}
    {% if rl in counts %}{% set _ = counts.update({rl: counts[rl] + 1}) %}{% endif %}
  {% endfor %}
  {% for level in ['critical', 'high', 'medium', 'low', 'unknown'] %}
    {% if counts[level] > 0 %}
    <span class="risk-pill" style="color: {{ risk_colors[level] }}; border-color: {{ risk_colors[level] }};">
      <span class="count">{{ counts[level] }}</span> {{ level }}
    </span>
    {% endif %}
  {% endfor %}
  <span class="summary-total">{{ results|length }} result{{ "s" if results|length != 1 else "" }} scanned</span>
</div>

<!-- RESULTS -->
<main class="container">
  <div class="results-grid">
    {% for result in results %}
    {% set rl = get_risk_level(result) %}
    <div class="result-card">
      <div class="card-header">
        <div class="card-header-left">
          {% if result.ip %}<span class="result-type-badge ip">IP</span>
          {% elif result.url %}<span class="result-type-badge url">URL</span>
          {% elif result.hash_value %}<span class="result-type-badge hash">HASH</span>
          {% elif result.query %}<span class="result-type-badge user">USER</span>
          {% elif result.domain %}<span class="result-type-badge dns">DNS</span>
          {% else %}<span class="result-type-badge default">RESULT</span>{% endif %}
          <span class="result-identifier">{{ get_title(result) }}</span>
        </div>
        <span class="risk-badge" style="background-color: {{ risk_colors[rl] }}; color: white;">
          {{ rl }}
        </span>
      </div>

      <div class="card-body">

        {# === IP INTEL === #}
        {% if result.ip %}
          <div class="card-section">
            <div class="card-section-title">Risk Assessment</div>
            <div class="data-grid">
              <div class="data-item">
                <div class="data-item-label">Score</div>
                <div class="data-item-value">{{ result.risk_score|default(0) }}/100</div>
              </div>
              {% if result.virustotal %}
              <div class="data-item">
                <div class="data-item-label">VT Malicious</div>
                <div class="data-item-value {% if result.virustotal.malicious > 5 %}highlight-red{% elif result.virustotal.malicious > 0 %}highlight-orange{% else %}highlight-green{% endif %}">{{ result.virustotal.malicious|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">VT Suspicious</div>
                <div class="data-item-value {% if result.virustotal.suspicious > 0 %}highlight-orange{% endif %}">{{ result.virustotal.suspicious|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">VT Reputation</div>
                <div class="data-item-value {% if result.virustotal.reputation < 0 %}highlight-red{% endif %}">{{ result.virustotal.reputation|default(0) }}</div>
              </div>
              {% endif %}
              {% if result.abuseipdb %}
              <div class="data-item">
                <div class="data-item-label">Abuse Score</div>
                <div class="data-item-value {% if result.abuseipdb.abuse_score > 80 %}highlight-red{% elif result.abuseipdb.abuse_score > 50 %}highlight-orange{% endif %}">{{ result.abuseipdb.abuse_score|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Reports</div>
                <div class="data-item-value">{{ result.abuseipdb.total_reports|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">TOR</div>
                <div class="data-item-value">{{ 'Yes' if result.abuseipdb.is_tor else 'No' }}</div>
              </div>
              {% endif %}
            </div>
          </div>

          {% if result.ipinfo and result.ipinfo.geo %}
          <div class="card-section">
            <div class="card-section-title">Geolocation</div>
            <div class="data-grid">
              <div class="data-item">
                <div class="data-item-label">Country</div>
                <div class="data-item-value">{{ result.ipinfo.geo.country|default('N/A') }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">City</div>
                <div class="data-item-value">{{ result.ipinfo.geo.city|default('N/A') }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">ASN</div>
                <div class="data-item-value">{{ result.ipinfo.geo.asn|default('N/A') }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Org</div>
                <div class="data-item-value">{{ (result.ipinfo.geo.org|default('N/A'))[:30] }}</div>
              </div>
            </div>
          </div>
          {% endif %}

          {% if result.shodan and result.shodan.open_ports %}
          <div class="card-section">
            <div class="card-section-title">Open Ports ({{ result.shodan.open_ports|length }})</div>
            <div class="port-list">
              {% for port in result.shodan.open_ports[:15] %}
              <span class="port-chip">{{ port }}</span>
              {% endfor %}
              {% if result.shodan.open_ports|length > 15 %}
              <span class="tag">+{{ result.shodan.open_ports|length - 15 }} more</span>
              {% endif %}
            </div>
          </div>
          {% endif %}

          {% if result.shodan and result.shodan.vulns %}
          <div class="card-section">
            <div class="card-section-title">Vulnerabilities ({{ result.shodan.vulns|length }})</div>
            <div class="tags-row">
              {% for vuln in result.shodan.vulns[:8] %}
              <span class="tag" title="{{ vuln.summary|default('') }}">{{ vuln.cve_id }}{% if vuln.cvss %} ({{ "%.1f"|format(vuln.cvss) }}){% endif %}</span>
              {% endfor %}
            </div>
          </div>
          {% endif %}

        {# === URL ANALYSIS === #}
        {% elif result.url %}
          {% if result.decoded_url and result.decoded_url != result.url %}
          <div class="card-section">
            <div class="card-section-title">Decoded URL ({{ result.encoding_type|default('encoded') }})</div>
            <div class="data-item" style="background:#fffbeb; border-color:#fde68a;">
              <div class="data-item-value" style="font-size:0.75rem; word-break:break-all;">{{ result.decoded_url }}</div>
            </div>
          </div>
          {% endif %}

          {% if result.urlscan %}
          <div class="card-section">
            <div class="card-section-title">URLScan.io Verdict</div>
            <div class="data-grid">
              <div class="data-item">
                <div class="data-item-label">Malicious</div>
                <div class="data-item-value {% if result.urlscan.verdict_malicious %}highlight-red{% endif %}">{{ 'Yes' if result.urlscan.verdict_malicious else 'No' }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Score</div>
                <div class="data-item-value {% if result.urlscan.verdict_score > 50 %}highlight-red{% elif result.urlscan.verdict_score > 0 %}highlight-orange{% endif %}">{{ result.urlscan.verdict_score|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">IPs Found</div>
                <div class="data-item-value">{{ result.urlscan.ips_found|length|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Domains</div>
                <div class="data-item-value">{{ result.urlscan.domains_found|length|default(0) }}</div>
              </div>
            </div>
          </div>
          {% endif %}

          {% if result.virustotal %}
          <div class="card-section">
            <div class="card-section-title">VirusTotal</div>
            <div class="detection-bar">
              <div class="detection-bar-header">
                <span class="detection-bar-label">Detection Ratio</span>
                <span class="detection-bar-ratio" style="color: {% if result.virustotal.malicious > 5 %}#dc2626{% elif result.virustotal.malicious > 0 %}#ea580c{% else %}#16a34a{% endif %};">
                  {{ result.virustotal.malicious|default(0) }}/{{ result.virustotal.total_engines|default(0) }}
                </span>
              </div>
              <div class="detection-bar-track">
                {% set pct = ((result.virustotal.malicious|default(0) / max(result.virustotal.total_engines|default(1), 1)) * 100)|round|int if result.virustotal.total_engines else 0 %}
                <div class="detection-bar-fill" style="width: {{ pct }}%; background: {% if pct > 50 %}#dc2626{% elif pct > 0 %}#ea580c{% else %}#16a34a{% endif %};"></div>
              </div>
            </div>
          </div>
          {% endif %}

        {# === HASH CHECK === #}
        {% elif result.hash_value %}
          <div class="card-section">
            <div class="card-section-title">File Information</div>
            <div class="data-grid">
              <div class="data-item">
                <div class="data-item-label">Hash Type</div>
                <div class="data-item-value">{{ (result.hash_type|upper|default('HASH')) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">File Type</div>
                <div class="data-item-value">{{ result.file_type|default('Unknown') }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Size</div>
                <div class="data-item-value">{% if result.file_size %}{{ (result.file_size / 1024)|round(1) }} KB{% else %}N/A{% endif %}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Name</div>
                <div class="data-item-value">{{ (result.meaningful_name|default('Unknown'))[:30] }}</div>
              </div>
            </div>
          </div>

          <div class="card-section">
            <div class="card-section-title">Detection Ratio</div>
            <div class="detection-bar">
              <div class="detection-bar-header">
                <span class="detection-bar-label">Engines</span>
                <span class="detection-bar-ratio" style="color: {% if result.malicious_count > 10 %}#dc2626{% elif result.malicious_count >= 5 %}#ea580c{% elif result.malicious_count > 0 %}#ca8a04{% else %}#16a34a{% endif %};">
                  {{ result.malicious_count|default(0) }}/{{ result.total_engines|default(0) }}
                </span>
              </div>
              <div class="detection-bar-track">
                {% set pct = ((result.malicious_count|default(0) / max(result.total_engines|default(1), 1)) * 100)|round|int if result.total_engines else 0 %}
                <div class="detection-bar-fill" style="width: {{ pct }}%; background: {% if pct > 50 %}#dc2626{% elif pct > 10 %}#ea580c{% elif pct > 0 %}#ca8a04{% else %}#16a34a{% endif %};"></div>
              </div>
            </div>
          </div>

          {% if result.top_detections %}
          <div class="card-section">
            <div class="card-section-title">Top Detections</div>
            {% for det in result.top_detections[:5] %}
            <div style="display:flex; justify-content:space-between; padding:0.25rem 0; border-bottom:1px solid #f1f5f9; font-size:0.8125rem;">
              <span style="font-weight:600;">{{ det.engine_name }}</span>
              <span style="color:{% if det.category == 'malicious' %}#dc2626{% else %}#ea580c{% endif %};">{{ det.result|default(det.category) }}</span>
            </div>
            {% endfor %}
          </div>
          {% endif %}

          {% if result.tags %}
          <div class="card-section">
            <div class="tags-row">
              {% for tag in result.tags[:8] %}
              <span class="tag">{{ tag }}</span>
              {% endfor %}
            </div>
          </div>
          {% endif %}

        {# === IDENTITY OSINT === #}
        {% elif result.query %}
          <div class="card-section">
            <div class="card-section-title">Platform Summary</div>
            <div class="data-grid">
              <div class="data-item">
                <div class="data-item-label">Found</div>
                <div class="data-item-value highlight-green">{{ result.found|length|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Not Found</div>
                <div class="data-item-value">{{ result.not_found|length|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Errors</div>
                <div class="data-item-value {% if result.error_count|default(0) > 0 %}highlight-orange{% endif %}">{{ result.error_count|default(0) }}</div>
              </div>
              <div class="data-item">
                <div class="data-item-label">Type</div>
                <div class="data-item-value">{{ result.query_type|default('username')|upper }}</div>
              </div>
            </div>
          </div>
          {% if result.found %}
          <div class="card-section">
            <div class="card-section-title">Found On</div>
            <div class="tags-row">
              {% for platform in result.found %}
              <span class="tag" style="background:#ecfdf5; border-color:#6ee7b7; color:#15803d;">{{ platform }}</span>
              {% endfor %}
            </div>
          </div>
          {% endif %}

        {# === DNS LOOKUP === #}
        {% elif result.domain %}
          <div class="card-section">
            <div class="card-section-title">DNS Records</div>
            <div class="data-grid">
              {% if result.a %}<div class="data-item"><div class="data-item-label">A</div><div class="data-item-value">{{ result.a[0] }}</div></div>{% endif %}
              {% if result.aaaa %}<div class="data-item"><div class="data-item-label">AAAA</div><div class="data-item-value">{{ result.aaaa[0] }}</div></div>{% endif %}
              {% if result.mx %}<div class="data-item"><div class="data-item-label">MX</div><div class="data-item-value">{{ (result.mx[0]|default('N/A'))[:30] }}</div></div>{% endif %}
              {% if result.ns %}<div class="data-item"><div class="data-item-label">NS</div><div class="data-item-value">{{ (result.ns[0]|default('N/A'))[:30] }}</div></div>{% endif %}
            </div>
          </div>
        {% endif %}

        {# Errors #}
        {% if result.errors %}
        <div class="card-section">
          {% for src, err in result.errors.items() %}
          <div class="error-box">Source "{{ src }}": {{ err }}</div>
          {% endfor %}
        </div>
        {% endif %}

        {# Raw JSON #}
        <details>
          <summary>Raw JSON Data</summary>
          <div class="json-block">{{ result | tojson }}</div>
        </details>
      </div>
    </div>
    {% endfor %}
  </div>
</main>

<!-- FOOTER -->
<footer class="report-footer">
  <strong>DragonflyX v2.0.0</strong> &mdash; OSINT &amp; SOC Intelligence Tool &mdash; Generated {{ generated_at }}
</footer>

</body>
</html>"""


def _get_risk_level(result: dict) -> str:
    """Get risk level from result."""
    return result.get("risk_level") or result.get("risk") or "unknown"


def _get_result_title(result: dict) -> str:
    """Get title for a result."""
    if "ip" in result:
        return result["ip"]
    if "url" in result:
        return result["url"][:80]
    if "hash_value" in result:
        return f"{result['hash_value'][:16]}..."
    if "query" in result:
        return result["query"]
    if "domain" in result:
        return result["domain"]
    return "Result"


def generate_html(results: list[Any], case_id: str | None = None) -> str:
    """
    Generate HTML report from results.

    Args:
        results: List of result objects
        case_id: Optional case identifier

    Returns:
        HTML string
    """
    serialized = [_serialize(r) for r in results]

    from jinja2 import Environment
    env = Environment()
    env.globals["max"]   = max
    env.globals["min"]   = min
    env.globals["len"]   = len
    env.globals["str"]   = str
    env.globals["int"]   = int
    env.globals["list"]  = list
    env.globals["range"] = range
    env.filters["tojson"] = lambda v: json.dumps(v, indent=2, default=str)
    env.filters["default"] = lambda v, d=None: v if v is not None else d

    template = env.from_string(HTML_TEMPLATE)
    return template.render(
        results=serialized,
        case_id=case_id or "unnamed",
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        risk_colors=RISK_COLORS_HTML,
        get_risk_level=_get_risk_level,
        get_title=_get_result_title,
    )


def save_and_open(results: list[Any], output_path: Path | None = None) -> Path:
    """
    Generate and save HTML report, then open in browser.

    Args:
        results: List of result objects
        output_path: Optional output path

    Returns:
        Path to saved HTML file
    """
    import webbrowser

    if output_path is None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"report_{ts}.html"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(generate_html(results), encoding="utf-8")
    webbrowser.open(output_path.as_uri())

    return output_path
