"""Indicator extraction and analysis tool.

Extracts and classifies IOCs (IPs, hashes, CVEs, URLs, emails) from unstructured text,
with bogon / private IP filtering and report generation.
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import sys
from typing import Any, Optional

try:
    from cti_toolbox.utils import formatting
except ImportError:
    import mybasics as formatting  # type: ignore

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
]

BOGUS_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_MD5_RE = re.compile(r"\b([a-fA-F0-9]{32})\b")
_SHA1_RE = re.compile(r"\b([a-fA-F0-9]{40})\b")
_SHA256_RE = re.compile(r"\b([a-fA-F0-9]{64})\b")
_CVE_RE = re.compile(r"\bCVE[-_ ]?\d{4}[-_ ]?\d{4,}\b", re.IGNORECASE)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s/$.?#].[^\s]*", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def is_bogon(ip_str: str) -> bool:
    """Check if an IPv4 address belongs to bogon / reserved space."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in BOGUS_NETWORKS)
    except ValueError:
        return False


def is_private(ip_str: str) -> bool:
    """Check if an IPv4 address is in private RFC1918 space."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def getIP(text: str, filter_bogons: bool = False) -> set[str]:
    """Extract IPv4 addresses from text."""
    ips = set(_IPV4_RE.findall(text))
    if filter_bogons:
        ips = {ip for ip in ips if not is_bogon(ip)}
    return ips


def getMD5(text: str) -> set[str]:
    """Extract MD5 hashes from text."""
    return set(_MD5_RE.findall(text))


def getSHA1(text: str) -> set[str]:
    """Extract SHA1 hashes from text."""
    return set(_SHA1_RE.findall(text))


def getSHA256(text: str) -> set[str]:
    """Extract SHA256 hashes from text."""
    return set(_SHA256_RE.findall(text))


def getCVE(text: str) -> set[str]:
    """Extract CVE identifiers from text and normalize to CVE-YYYY-NNNN format."""
    raw_cves = _CVE_RE.findall(text)
    normalized: set[str] = set()
    for cve in raw_cves:
        clean = re.sub(r"[\s_]+", "-", cve).upper()
        if not clean.startswith("CVE-"):
            clean = "CVE-" + clean.lstrip("CVE").lstrip("-")
        normalized.add(clean)
    return normalized


def getURL(text: str) -> set[str]:
    """Extract URLs from text."""
    return set(_URL_RE.findall(text))


def getEmail(text: str) -> set[str]:
    """Extract email addresses from text."""
    return set(_EMAIL_RE.findall(text))


def get_all_indicators(text: str) -> dict[str, list[str]]:
    """Extract all supported IOCs into a categorized dictionary."""
    return {
        "ipv4": sorted(getIP(text)),
        "md5": sorted(getMD5(text)),
        "sha1": sorted(getSHA1(text)),
        "sha256": sorted(getSHA256(text)),
        "cve": sorted(getCVE(text)),
        "url": sorted(getURL(text)),
        "email": sorted(getEmail(text)),
    }


def getXML(text: str, ox: Optional[str] = None) -> str:
    """Extract IOCs and format as XML."""
    backset: list[str] = []
    for item in sorted(getIP(text)):
        backset.append(formatting.StoXML("ip", item))
    for item in sorted(getCVE(text)):
        backset.append(formatting.StoXML("cve", item))
    for item in sorted(getMD5(text)):
        backset.append(formatting.StoXML("MD5", item))
    for item in sorted(getSHA1(text)):
        backset.append(formatting.StoXML("SHA1", item))
    for item in sorted(getSHA256(text)):
        backset.append(formatting.StoXML("SHA256", item))

    if ox:
        return " ".join(backset)
    return "".join(backset)


def getJSON(text: str) -> str:
    """Extract IOCs and format as JSON."""
    return json.dumps(get_all_indicators(text), indent=2)


def va(text: str, method: Optional[str] = None) -> str:
    """Generate an HTML Security / Threat Intelligence report."""
    threat_intel = ", ".join(sorted(getCVE(text))) or "None detected"
    ip_intel = ", ".join(sorted(getIP(text))) or "None detected"
    hash_intel = ", ".join(sorted(getMD5(text) | getSHA256(text))) or "None detected"
    safe_text = html.escape(text)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Threat Intelligence Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; color: #24292e; }}
        h1 {{ color: #0366d6; border-bottom: 1px solid #eaecef; padding-bottom: 8px; }}
        h2 {{ color: #24292e; margin-top: 20px; }}
        .card {{ background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 6px; padding: 16px; margin-bottom: 16px; }}
        pre {{ background: #24292e; color: #f6f8fa; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
        .badge {{ background: #0366d6; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>Security / Threat Intelligence Report</h1>
    <div class="card">
        <h2>Threat / CVE Intelligence</h2>
        <p>{threat_intel}</p>
    </div>
    <div class="card">
        <h2>IP Intelligence</h2>
        <p>{ip_intel}</p>
    </div>
    <div class="card">
        <h2>Hashes (MD5 / SHA256)</h2>
        <p>{hash_intel}</p>
    </div>
    <div class="card">
        <h2>Raw Event Data</h2>
        <pre>{safe_text}</pre>
    </div>
</body>
</html>"""


def main() -> None:
    """CLI entry point for indicators."""
    parser = argparse.ArgumentParser(description="Extract threat indicators (IP, Hashes, CVEs, URLs) from text.")
    parser.add_argument("input", nargs="?", default=None, help="Input text or file path (reads stdin if omitted)")
    parser.add_argument("-f", "--format", choices=["json", "xml", "text", "html"], default="text", help="Output format (default: text)")
    parser.add_argument("--filter-bogons", action="store_true", help="Exclude private and bogon IP addresses")

    args = parser.parse_args()

    content = ""
    if args.input:
        import os
        if os.path.isfile(args.input):
            with open(args.input, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        else:
            content = args.input
    else:
        if not sys.stdin.isatty():
            content = sys.stdin.read()
        else:
            parser.print_help()
            sys.exit(0)

    if args.format == "json":
        print(getJSON(content))
    elif args.format == "xml":
        print(getXML(content))
    elif args.format == "html":
        print(va(content))
    else:
        indicators = get_all_indicators(content)
        for category, items in indicators.items():
            if items:
                print(f"[{category.upper()}] ({len(items)}):")
                for item in items:
                    print(f"  - {item}")


if __name__ == "__main__":
    main()
