"""VirusTotal API Client for CTI-Toolbox."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

import requests

try:
    from cti_toolbox import config as IC
except ImportError:
    import config as IC  # type: ignore

VT_BASE_V2 = "https://www.virustotal.com/vtapi/v2"
TIMEOUT = 10


def _get_api_key(api_key: Optional[str] = None) -> str:
    key = api_key or (getattr(IC, "vt_key", "") if IC else "")
    return str(key).strip()


def getresult(ip: str, api_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve IP address report from VirusTotal."""
    key = _get_api_key(api_key)
    if not key:
        return {"error": "VirusTotal API key is missing. Set VT_KEY in .env or config."}

    params = {"ip": ip.strip(), "apikey": key}
    url = f"{VT_BASE_V2}/ip-address/report"
    try:
        response = requests.get(url, params=params, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:
            return {"error": "VirusTotal rate limit exceeded (HTTP 204)"}
        elif response.status_code == 403:
            return {"error": "Invalid VirusTotal API key (HTTP 403)"}
        else:
            return {"error": f"HTTP {response.status_code}", "detail": response.text[:200]}
    except requests.RequestException as e:
        return {"error": "Connection error", "detail": str(e)}


def urlresult(resource: str, api_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve URL scan report from VirusTotal."""
    key = _get_api_key(api_key)
    if not key:
        return {"error": "VirusTotal API key is missing. Set VT_KEY in .env or config."}

    params = {"resource": resource.strip(), "apikey": key}
    url = f"{VT_BASE_V2}/url/report"
    try:
        response = requests.get(url, params=params, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:
            return {"error": "VirusTotal rate limit exceeded (HTTP 204)"}
        elif response.status_code == 403:
            return {"error": "Invalid VirusTotal API key (HTTP 403)"}
        else:
            return {"error": f"HTTP {response.status_code}", "detail": response.text[:200]}
    except requests.RequestException as e:
        return {"error": "Connection error", "detail": str(e)}


def fileresult(file_hash: str, api_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve file hash report (MD5, SHA1, SHA256) from VirusTotal."""
    key = _get_api_key(api_key)
    if not key:
        return {"error": "VirusTotal API key is missing. Set VT_KEY in .env or config."}

    params = {"resource": file_hash.strip(), "apikey": key}
    url = f"{VT_BASE_V2}/file/report"
    try:
        response = requests.get(url, params=params, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:
            return {"error": "VirusTotal rate limit exceeded (HTTP 204)"}
        elif response.status_code == 403:
            return {"error": "Invalid VirusTotal API key (HTTP 403)"}
        else:
            return {"error": f"HTTP {response.status_code}", "detail": response.text[:200]}
    except requests.RequestException as e:
        return {"error": "Connection error", "detail": str(e)}


def search(text: str, api_key: Optional[str] = None) -> dict[str, Any]:
    """Search for an IP, URL, or hash on VirusTotal."""
    cleaned = text.strip()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        return urlresult(cleaned, api_key)
    elif len(cleaned) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return fileresult(cleaned, api_key)
    else:
        return getresult(cleaned, api_key)


def main() -> None:
    """CLI entry point for VirusTotal."""
    parser = argparse.ArgumentParser(description="Query VirusTotal API for IP, URL, or hash intelligence.")
    parser.add_argument("indicator", nargs="?", help="Target IP, URL, or file hash")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-s", "--hash", help="Target file hash (MD5, SHA1, SHA256)")
    parser.add_argument("-k", "--key", help="VirusTotal API key override")

    args = parser.parse_args()

    target = args.indicator or args.ip or args.url or args.hash
    if not target:
        parser.print_help()
        sys.exit(0)

    if args.ip:
        res = getresult(args.ip, api_key=args.key)
    elif args.url:
        res = urlresult(args.url, api_key=args.key)
    elif args.hash:
        res = fileresult(args.hash, api_key=args.key)
    else:
        res = search(args.indicator, api_key=args.key)

    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
