"""PacketMail IP Reputation Client."""

from __future__ import annotations

import argparse
import re
import sys
from typing import Optional

import requests

try:
    from cti_toolbox import config as IC
except ImportError:
    import config as IC  # type: ignore

try:
    from cti_toolbox.defang import redact
except ImportError:
    import redactit as redact  # type: ignore

TIMEOUT = 10
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")


def _get_api_key(api_key: Optional[str] = None) -> str:
    key = api_key or (getattr(IC, "pama_key", "") if IC else getattr(IC, "sc_apikey", ""))
    return str(key).strip()


def query_ip(ip: str, api_key: Optional[str] = None) -> str:
    """Query PacketMail for a single IP address."""
    key = _get_api_key(api_key)
    url = f"https://www.packetmail.net/iprep.php/{ip.strip()}"
    params = {"apikey": key} if key else {}
    headers = {"User-Agent": "CTI-Toolbox/1.1.0 (PacketMail-Client)"}

    try:
        response = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.text
        return f"[HTTP {response.status_code}] Error querying {ip}"
    except requests.RequestException as e:
        return f"[Connection Error] {ip}: {e}"


def doAnalyse(text: str, key: Optional[str] = None) -> str:
    """Extract IPs from text, query PacketMail, and defang the combined response."""
    found_ips = set(_IPV4_RE.findall(text))
    if not found_ips:
        return "No IPv4 addresses detected in input."

    combined_response = []
    for ip in sorted(found_ips):
        result = query_ip(ip, api_key=key)
        combined_response.append(f"=== Results for {ip} ===\n{result}\n")

    raw_text = "\n".join(combined_response)
    return redact.redactit(raw_text)


def main() -> None:
    """CLI entry point for packetmail."""
    parser = argparse.ArgumentParser(description="Query PacketMail IP reputation for IPs found in text or files.")
    parser.add_argument("input", nargs="?", help="IP address, text containing IPs, or file path")
    parser.add_argument("-k", "--key", dest="key", help="PacketMail API key override")

    args = parser.parse_args()

    if not args.input:
        if not sys.stdin.isatty():
            content = sys.stdin.read()
        else:
            parser.print_help()
            sys.exit(0)
    else:
        import os
        if os.path.isfile(args.input):
            with open(args.input, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        else:
            content = args.input

    output = doAnalyse(content, key=args.key)
    print(output)


if __name__ == "__main__":
    main()
