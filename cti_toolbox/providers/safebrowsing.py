"""Google Safe Browsing API Client."""

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

SAFEBROWSING_V4_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT = 10


def _get_api_key(api_key: Optional[str] = None) -> str:
    key = api_key or (getattr(IC, "go_key", "") if IC else "")
    return str(key).strip()


def lookup(url: str, api_key: Optional[str] = None) -> dict[str, Any]:
    """Check a URL against Google Safe Browsing API v4."""
    key = _get_api_key(api_key)
    if not key:
        return {"error": "Google API key is not configured. Set GO_KEY in .env or config."}

    payload = {
        "client": {
            "clientId": "cti-toolbox",
            "clientVersion": "1.1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "THREAT_TYPE_UNSPECIFIED",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url.strip()}],
        },
    }

    try:
        response = requests.post(
            f"{SAFEBROWSING_V4_URL}?key={key}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=TIMEOUT,
        )
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            is_malicious = len(matches) > 0
            return {
                "url": url.strip(),
                "is_malicious": is_malicious,
                "matches": matches,
                "Google_Safebrowsing": "MALICIOUS" if is_malicious else "CLEAN",
            }
        else:
            return {"error": f"HTTP {response.status_code}", "detail": response.text[:200]}
    except requests.RequestException as e:
        return {"error": "Request failed", "detail": str(e)}


def main() -> None:
    """CLI entry point for safebrowsing."""
    parser = argparse.ArgumentParser(description="Check URL safety using Google Safe Browsing API.")
    parser.add_argument("url", nargs="?", help="URL to check")
    parser.add_argument("-k", "--key", dest="key", help="Google Safe Browsing API key override")

    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        sys.exit(0)

    result = lookup(args.url, api_key=args.key)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
