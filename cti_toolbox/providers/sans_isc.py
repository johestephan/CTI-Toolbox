"""SANS ISC Patch Tuesday Intelligence Client."""

from __future__ import annotations

import argparse
import html
import json
import sys
from typing import Any, Optional

import requests

try:
    from cti_toolbox.providers import xforce
except ImportError:
    import xfexchange as xforce  # type: ignore

BASE_URL = "https://isc.sans.edu/api/getmspatchday"
TIMEOUT = 10


def getbyDate(date_str: str) -> dict[str, Any]:
    """Retrieve Patch Tuesday bulletin from SANS ISC for a date (YYYY-MM-DD or YYYYMM)."""
    clean_date = date_str.strip()
    url = f"{BASE_URL}/{clean_date}?json"
    headers = {
        "Accept": "application/json",
        "User-Agent": "CTI-Toolbox/1.1.0 (SANS-ISC-Client)",
    }
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
        return {"error": f"HTTP {response.status_code}", "detail": response.text[:200]}
    except requests.RequestException as e:
        return {"error": "Connection failed", "detail": str(e)}


def pt_toWeb(date_str: str) -> str:
    """Generate HTML bullet list of Patch Tuesday vulnerabilities."""
    data = getbyDate(date_str)
    entries = data.get("getmspatchday", [])
    if isinstance(entries, dict):
        entries = [entries]

    if not entries:
        return "<p>No Patch Tuesday entries found for this date.</p>"

    html_parts: list[str] = []
    for item in entries:
        bulletin_id = html.escape(str(item.get("id", "N/A")))
        exploits = html.escape(str(item.get("exploits", "N/A")))
        affected = html.escape(str(item.get("affected", "N/A")))
        severity = html.escape(str(item.get("severity", "N/A")))
        clients = html.escape(str(item.get("clients", "")))
        servers = html.escape(str(item.get("servers", "")))
        title = html.escape(str(item.get("title", "No title")))

        html_parts.append(f"""<ul> <b>{bulletin_id}</b>
        <li>Title: {title}</li>
        <li>Known Exploits: <b>{exploits}</b></li>
        <li>Affects: {affected}</li>
        <li>Severity: {severity}</li>
        <li>Client / Server: {clients} / {servers}</li></ul>""")

    return "\n".join(html_parts)


def pt_toWebv2(date_str: str) -> str:
    """Generate HTML summary enriched with IBM X-Force data if available."""
    data = getbyDate(date_str)
    entries = data.get("getmspatchday", [])
    if isinstance(entries, dict):
        entries = [entries]

    output_parts: list[str] = []
    for item in entries:
        bulletin_id = str(item.get("id", ""))
        if xforce and bulletin_id:
            xfe_data = xforce.getxfid_fromMS(bulletin_id)
            output_parts.append(json.dumps(xfe_data, indent=2))
        else:
            output_parts.append(json.dumps(item, indent=2))

    return "\n".join(output_parts)


def main() -> None:
    """CLI entry point for ptuesday."""
    parser = argparse.ArgumentParser(description="Fetch SANS ISC Patch Tuesday intelligence by date.")
    parser.add_argument("date", nargs="?", help="Date in YYYY-MM-DD format (e.g. 2024-01-09)")
    parser.add_argument("-d", "--date", dest="date_opt", help="Date in YYYY-MM-DD format")
    parser.add_argument("-f", "--format", choices=["json", "html", "text"], default="text", help="Output format (default: text)")

    args = parser.parse_args()
    date_val = args.date or args.date_opt

    if not date_val:
        parser.print_help()
        sys.exit(0)

    data = getbyDate(date_val)

    if args.format == "json":
        print(json.dumps(data, indent=2))
    elif args.format == "html":
        print(pt_toWeb(date_val))
    else:
        entries = data.get("getmspatchday", [])
        if isinstance(entries, dict):
            entries = [entries]
        if not entries:
            print(f"No records found for date {date_val}")
        for item in entries:
            print(f"[{item.get('id', 'N/A')}] {item.get('title', 'N/A')}")
            print(f"  Severity: {item.get('severity', 'N/A')} | Exploits: {item.get('exploits', 'N/A')} | Affects: {item.get('affected', 'N/A')}")
            print()


if __name__ == "__main__":
    main()
