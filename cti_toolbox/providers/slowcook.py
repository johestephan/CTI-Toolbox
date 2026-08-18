"""IBM X-Force threat category harvester and high-roller IP detector."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests

try:
    from cti_toolbox import config as IC
except ImportError:
    import config as IC  # type: ignore

BASE_URL = "https://api.xforce.ibmcloud.com"
TIMEOUT = 12

INTRcat = {
    "1": "Spam",
    "2": "Anonymisation Services",
    "3": "Scanning IPs",
    "4": "Dynamic IPs",
    "5": "Malware",
    "6": "Bots",
    "7": "Botnet Command and Control Server",
}


def _get_headers(credentials: Optional[str] = None) -> dict[str, str]:
    cred = credentials or (getattr(IC, "xfex_cred", "") if IC else "")
    headers = {
        "Accept": "application/json",
        "User-Agent": "CTI-Toolbox/1.1.0 (Slowcook)",
    }
    if cred:
        if not str(cred).startswith("Basic "):
            encoded = base64.b64encode(str(cred).encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {encoded}"
        else:
            headers["Authorization"] = str(cred)
    return headers


def ask(url: str, credentials: Optional[str] = None) -> dict[str, Any]:
    """Perform authenticated GET request to X-Force."""
    try:
        response = requests.get(url, headers=_get_headers(credentials), timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
        return {"error": f"HTTP {response.status_code}", "url": url}
    except requests.RequestException as e:
        return {"error": "Connection error", "detail": str(e), "url": url}


def slowcookINTRIP(cat: str = "1", days_back: int = 5, limit: int = 2000, credentials: Optional[str] = None) -> dict[str, Any]:
    """Fetch recent IPs reported for a specific threat category."""
    cat_name = INTRcat.get(str(cat), "Malware")
    start_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00Z")
    url = f"{BASE_URL}/ipr?category={requests.utils.quote(cat_name)}&startDate={start_date}&limit={limit}"
    return ask(url, credentials)


def getIP(ip: str, credentials: Optional[str] = None) -> dict[str, Any]:
    """Retrieve detailed intelligence for a specific IP."""
    url = f"{BASE_URL}/ipr/{ip.strip()}"
    return ask(url, credentials)


def searchHIGHroller(iplist: list[str] | set[str], credentials: Optional[str] = None) -> str:
    """Check a list of target IPs against all active threat categories."""
    target_set = {ip.strip() for ip in iplist}
    retdata: list[str] = []

    for cat_id, cat_name in INTRcat.items():
        data = slowcookINTRIP(cat_id, credentials=credentials)
        rows = data.get("rows", []) if isinstance(data, dict) else []
        for item in rows:
            ip = item.get("ip")
            if ip and ip in target_set:
                score = item.get("score", "N/A")
                created = item.get("created", "N/A")
                retdata.append(f"{cat_name}; {ip}; {score}; {created}")

    return "\n".join(retdata)


def getHIGHroller(limit: float = 8.0, credentials: Optional[str] = None) -> dict[str, Any]:
    """Harvest all IPs across categories exceeding the given threat score threshold."""
    now_iso = datetime.now(timezone.utc).isoformat()
    results: dict[str, Any] = {"timestamp": now_iso, "threshold": limit, "categories": {}}

    for cat_id, cat_name in INTRcat.items():
        data = slowcookINTRIP(cat_id, credentials=credentials)
        high_score_items: list[dict[str, Any]] = []
        rows = data.get("rows", []) if isinstance(data, dict) else []

        for item in rows:
            score = item.get("score")
            if isinstance(score, (int, float)) and score >= limit:
                high_score_items.append({
                    "ip": item.get("ip"),
                    "score": score,
                    "created": item.get("created"),
                    "geo": item.get("geo", {}).get("country", "Unknown") if isinstance(item.get("geo"), dict) else "Unknown",
                })

        results["categories"][cat_name] = high_score_items

    return results


def main() -> None:
    """CLI entry point for slowcook."""
    parser = argparse.ArgumentParser(description="Harvest high-scoring malicious IPs across X-Force categories.")
    parser.add_argument("-t", "--threshold", type=float, default=8.0, help="Threat score threshold (0.0 to 10.0, default: 8.0)")
    parser.add_argument("-c", "--category", choices=list(INTRcat.keys()), help="Query specific category (1-7)")
    parser.add_argument("-i", "--ip", help="Check if specific IP is a high roller")
    parser.add_argument("-k", "--key", help="X-Force auth credentials override")

    args = parser.parse_args()

    if args.ip:
        res = searchHIGHroller([args.ip], credentials=args.key)
        print(res if res else f"IP {args.ip} not found in recent high threat categories.")
    elif args.category:
        data = slowcookINTRIP(args.category, credentials=args.key)
        print(json.dumps(data, indent=2))
    else:
        data = getHIGHroller(limit=args.threshold, credentials=args.key)
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
