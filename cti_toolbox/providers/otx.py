"""AlienVault Open Threat Exchange (OTX) API Client."""

from __future__ import annotations

import argparse
import json
from typing import Any, Optional

import requests

try:
    from cti_toolbox import config as IC
except ImportError:
    import config as IC  # type: ignore

BASE_URL = "https://otx.alienvault.com/api/v1"
TIMEOUT = 10


def _get_headers(auth_key: Optional[str] = None) -> dict[str, str]:
    key = auth_key or (getattr(IC, "otx_authkey", "") if IC else "")
    return {
        "X-OTX-API-KEY": str(key).strip(),
        "Accept": "application/json",
        "User-Agent": "CTI-Toolbox/1.1.0 (Security-Intelligence)",
    }


def _request_json(endpoint: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    url = f"{BASE_URL}{endpoint}" if not endpoint.startswith("http") else endpoint
    headers = _get_headers(auth_key)
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            return {"error": "Invalid or missing AlienVault OTX API key", "status_code": 403}
        elif response.status_code == 404:
            return {"error": "Indicator not found in OTX", "status_code": 404}
        else:
            return {"error": f"HTTP {response.status_code}", "detail": response.text[:200]}
    except requests.RequestException as e:
        return {"error": "Request failed", "detail": str(e)}


def PADip(ip: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve passive DNS information for an IPv4 address."""
    return _request_json(f"/indicators/IPv4/{ip.strip()}/passive_dns", auth_key)


def GEip(ip: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve general information for an IPv4 address."""
    return _request_json(f"/indicators/IPv4/{ip.strip()}/general", auth_key)


def URLip(ip: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve URL list associated with an IPv4 address."""
    return _request_json(f"/indicators/IPv4/{ip.strip()}/url_list", auth_key)


def REip(ip: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve reputation data for an IPv4 address."""
    return _request_json(f"/indicators/IPv4/{ip.strip()}/reputation", auth_key)


def MALip(ip: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve malware samples associated with an IPv4 address."""
    return _request_json(f"/indicators/IPv4/{ip.strip()}/malware", auth_key)


def IPmax(ip: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve all available OTX data for an IPv4 address."""
    ip_clean = ip.strip()
    return {
        "ip": ip_clean,
        "general": GEip(ip_clean, auth_key),
        "reputation": REip(ip_clean, auth_key),
        "malware": MALip(ip_clean, auth_key),
        "url_list": URLip(ip_clean, auth_key),
        "passive_dns": PADip(ip_clean, auth_key),
    }


def URL(url_str: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve general details for a URL."""
    return _request_json(f"/indicators/url/{url_str.strip()}/general", auth_key)


def CVE(cve_id: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve general information for a CVE identifier."""
    return _request_json(f"/indicators/cve/{cve_id.strip()}/general", auth_key)


def Pulseday(auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve daily pulse activity."""
    return _request_json("/pulses/activity", auth_key)


def PulseSub(limit: int = 30, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve pulses from subscribed feeds."""
    return _request_json(f"/pulses/subscribed?limit={limit}", auth_key)


def getIndicators(pulse_id: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve indicators inside a specific pulse ID."""
    return _request_json(f"/pulses/{pulse_id.strip()}/indicators", auth_key)


def getMalhash(file_hash: str, auth_key: Optional[str] = None) -> dict[str, Any]:
    """Retrieve analysis for a file hash (MD5, SHA1, SHA256)."""
    return _request_json(f"/indicators/file/{file_hash.strip()}/analysis", auth_key)


def parsePulse(data: dict[str, Any], auth_key: Optional[str] = None) -> dict[str, Any]:
    """Parse pulse data and fetch indicators for all included pulse IDs."""
    combined: dict[str, Any] = {}
    results = data.get("results", [])
    for item in results:
        pulse_id = item.get("id")
        if pulse_id:
            combined[pulse_id] = getIndicators(pulse_id, auth_key)
    return combined


def main() -> None:
    """CLI entry point for OTX."""
    parser = argparse.ArgumentParser(description="Query AlienVault Open Threat Exchange (OTX) API.")
    parser.add_argument("-i", "--ip", dest="ip", help="Query IPv4 intelligence")
    parser.add_argument("-u", "--url", dest="url", help="Query URL intelligence")
    parser.add_argument("-c", "--cve", dest="cve", help="Query CVE intelligence")
    parser.add_argument("-s", "--hash", dest="hash", help="Query file hash (MD5/SHA1/SHA256)")
    parser.add_argument("-p", "--pulses", action="store_true", help="Fetch recent subscribed pulses")
    parser.add_argument("-k", "--key", dest="key", help="OTX API key override")

    args = parser.parse_args()

    if args.ip:
        print(json.dumps(IPmax(args.ip, auth_key=args.key), indent=2))
    elif args.url:
        print(json.dumps(URL(args.url, auth_key=args.key), indent=2))
    elif args.cve:
        print(json.dumps(CVE(args.cve, auth_key=args.key), indent=2))
    elif args.hash:
        print(json.dumps(getMalhash(args.hash, auth_key=args.key), indent=2))
    elif args.pulses:
        print(json.dumps(PulseSub(auth_key=args.key), indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
