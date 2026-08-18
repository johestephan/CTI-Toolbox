"""IBM X-Force Exchange Threat Intelligence API Client."""

from __future__ import annotations

import argparse
import base64
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests

try:
    from cti_toolbox import config as IC
except ImportError:
    import config as IC  # type: ignore

BASE_URL = "https://api.xforce.ibmcloud.com"
TIMEOUT = 10

CATEGORY_MAP = {
    "1": "Spam",
    "2": "Anonymisation Services",
    "3": "Scanning IPs",
    "4": "Dynamic IPs",
    "5": "Malware",
    "6": "Bots",
    "7": "Botnet Command and Control Server",
}


def _get_auth_header(credentials: Optional[str] = None) -> dict[str, str]:
    cred = credentials or (getattr(IC, "xfex_cred", "") if IC else "")
    cred_str = str(cred).strip()
    headers = {
        "Accept": "application/json",
        "User-Agent": "CTI-Toolbox/1.1.0 (IBM-XFE)",
    }
    if cred_str:
        if ":" in cred_str and not cred_str.startswith("Basic "):
            encoded = base64.b64encode(cred_str.encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {encoded}"
        elif cred_str.startswith("Basic "):
            headers["Authorization"] = cred_str
        else:
            headers["Authorization"] = f"Basic {cred_str}"
    return headers


def _request_xfe(endpoint: str, credentials: Optional[str] = None) -> Any:
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    headers = _get_auth_header(credentials)
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401 or response.status_code == 403:
            return {"error": "Authentication failed - check X-Force credentials", "status_code": response.status_code}
        elif response.status_code == 404:
            return {"error": "Resource not found in X-Force", "status_code": 404}
        else:
            return {"error": f"HTTP {response.status_code}", "detail": response.text[:200]}
    except requests.RequestException as e:
        return {"error": "Connection error", "detail": str(e)}


def getPAM(text: str, credentials: Optional[str] = None) -> str:
    """Search signatures by fulltext query and return the first PAM ID."""
    data = _request_xfe(f"signatures/fulltext?q={requests.utils.quote(text.strip())}", credentials)
    if isinstance(data, dict) and "rows" in data and data["rows"]:
        return str(data["rows"][0].get("pamid", "")).strip()
    return "Not found"


def getXFD_fromCVE(cve: str, credentials: Optional[str] = None) -> str:
    """Retrieve X-Force DB ID (xfdbid) from a CVE identifier."""
    data = _request_xfe(f"vulnerabilities/search/{requests.utils.quote(cve.strip())}", credentials)
    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        return str(data[0].get("xfdbid", "Not found"))
    return "Not found"


def getXFD(pamid: str, credentials: Optional[str] = None) -> str:
    """Retrieve X-Force DB ID protected against by a PAM signature ID."""
    data = _request_xfe(f"signatures/{requests.utils.quote(pamid.strip())}", credentials)
    if isinstance(data, dict) and "protects_against" in data:
        return str(data["protects_against"].get("xfdbid", "Not found"))
    return "Not found"


def getFull(xfid: str, credentials: Optional[str] = None) -> list[Any]:
    """Retrieve full vulnerability details."""
    if str(xfid).strip() in ("Not found", ""):
        return ["Not found", "N/A", [], []]
    data = _request_xfe(f"vulnerabilities/{requests.utils.quote(str(xfid).strip())}", credentials)
    if isinstance(data, dict) and "error" not in data:
        return [
            data.get("description", "No description"),
            data.get("risk_level", "Unknown"),
            data.get("platforms_affected", []),
            data.get("stdcode", []),
        ]
    return [str(data.get("error", "Error")), "N/A", [], []]


def getCase_attachments(case_id: str, credentials: Optional[str] = None) -> Any:
    """Retrieve attachments for an X-Force Casefile ID."""
    return _request_xfe(f"casefiles/{requests.utils.quote(case_id.strip())}/attachments", credentials)


def getTrend(ip: str, credentials: Optional[str] = None) -> tuple[list[str], list[Any]]:
    """Retrieve historical threat score trend for an IP address."""
    data = _request_xfe(f"ipr/{requests.utils.quote(ip.strip())}", credentials)
    dates: list[str] = []
    scores: list[Any] = []
    if isinstance(data, dict) and "history" in data:
        for item in data["history"]:
            dates.append(item.get("created", ""))
            scores.append(item.get("score", 0))
    return (dates, scores)


def getip(ip: str, credentials: Optional[str] = None) -> dict[str, Any]:
    """Retrieve comprehensive IP reputation and malware association."""
    ip_clean = ip.strip()
    data_rep = _request_xfe(f"ipr/{ip_clean}", credentials)
    data_mal = _request_xfe(f"ipr/malware/{ip_clean}", credentials)

    merged: dict[str, Any] = {}
    if isinstance(data_rep, dict):
        merged.update(data_rep)
    if isinstance(data_mal, dict):
        merged.update(data_mal)
    return merged if merged else {"error": "No data returned"}


def ixf_IPtoWeb(ip: str, credentials: Optional[str] = None) -> str:
    """Generate HTML snippet for IP report."""
    dataset = getip(ip, credentials)
    geo = dataset.get("geo", {}).get("country", "Unknown") if isinstance(dataset.get("geo"), dict) else "Unknown"
    score = dataset.get("score", "N/A")
    cats = dataset.get("categoryDescriptions", {})
    desc = ", ".join(cats.values()) if isinstance(cats, dict) else "N/A"
    return f"""<ul><b> {ip} </b>
    <li>Description: {desc}</li>
    <li>Score: {score}</li>
    <li>Geo Location: {geo}</li></ul>"""


def ixf_m(text: str) -> int:
    """Placeholder helper for XFE malware search."""
    return 0


def ixf_cve_forWeb(cve: str, credentials: Optional[str] = None) -> str:
    """Generate HTML summary for a CVE."""
    xfid = getXFD_fromCVE(cve, credentials)
    result = getFull(xfid, credentials)
    desc, risk, platforms, stdcodes = result[0], result[1], ", ".join(result[2]), ", ".join(result[3])
    return f"""<ul><b> {cve} </b>
    <li>Description: {desc}</li>
    <li>Risk Level: {risk}</li>
    <li>Affected Platforms: {platforms}</li>
    <li>Standard Codes: {stdcodes}</li></ul>"""


def ixf_s(text: str, credentials: Optional[str] = None) -> list[Any]:
    """Look up PAM signature and return vulnerability details."""
    pam_id = getPAM(text.strip(","), credentials)
    xf_id = getXFD(pam_id, credentials)
    return getFull(xf_id, credentials)


def ixf_forWeb(text: str, credentials: Optional[str] = None) -> str:
    """Generate HTML summary for a PAM signature."""
    result = ixf_s(text.strip(","), credentials)
    desc, risk, platforms, stdcodes = result[0], result[1], ", ".join(result[2]), ", ".join(result[3])
    return f"""<ul><b> {text} </b>
    <li>Description: {desc}</li>
    <li>Risk Level: {risk}</li>
    <li>Affected Platforms: {platforms}</li>
    <li>Standard Codes: {stdcodes}</li></ul>"""


def getVulnr(credentials: Optional[str] = None) -> Any:
    """Fetch latest vulnerabilities list from X-Force."""
    return _request_xfe("vulnerabilities", credentials)


def getURL(url_str: str, credentials: Optional[str] = None) -> Any:
    """Fetch categorization and risk score for a URL."""
    return _request_xfe(f"url/{requests.utils.quote(url_str.strip())}", credentials)


def getURLm(url_str: str, credentials: Optional[str] = None) -> Any:
    """Fetch malware association for a URL."""
    return _request_xfe(f"url/malware/{requests.utils.quote(url_str.strip())}", credentials)


def getCase_Shared(credentials: Optional[str] = None) -> Any:
    """Fetch shared casefiles from X-Force."""
    return _request_xfe("casefiles/shared", credentials)


def getCase_Public(credentials: Optional[str] = None) -> Any:
    """Fetch public casefiles from X-Force."""
    return _request_xfe("casefiles/public", credentials)


def getXPUdir(credentials: Optional[str] = None) -> Any:
    """Fetch XPU signature directory."""
    return _request_xfe("signatures/xpu/directory", credentials)


def getCase_by_Group(group_id: str, credentials: Optional[str] = None) -> Any:
    """Fetch casefiles by group ID."""
    return _request_xfe(f"user/groups/{requests.utils.quote(group_id.strip())}/casefiles", credentials)


def getxfid_fromMS(msid: str, credentials: Optional[str] = None) -> Any:
    """Fetch vulnerability data by Microsoft security bulletin ID."""
    return _request_xfe(f"vulnerabilities/msid/{requests.utils.quote(msid.strip())}", credentials)


def getmsid(msid: str, credentials: Optional[str] = None) -> Any:
    """Alias for getxfid_fromMS."""
    return getxfid_fromMS(msid, credentials)


def getMalw(file_hash: str, credentials: Optional[str] = None) -> Any:
    """Fetch malware report for a file hash."""
    return _request_xfe(f"malware/{requests.utils.quote(file_hash.strip())}", credentials)


def getDAMN(case_id: str, credentials: Optional[str] = None) -> set[str]:
    """Extract IP indicators from case attachments."""
    data = getCase_attachments(case_id, credentials)
    iplist: set[str] = set()
    if isinstance(data, dict) and "attachments" in data:
        for item in data["attachments"]:
            report = item.get("report", {})
            if "IP" in report.get("type", ""):
                iplist.add(report.get("title", ""))
    return iplist


def intrIPs(cat: Optional[str] = None, credentials: Optional[str] = None) -> dict[str, Any]:
    """Retrieve interesting threat IPs by category."""
    category_name = CATEGORY_MAP.get(str(cat), "Botnet Command and Control Server")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
    endpoint = f"ipr?category={requests.utils.quote(category_name)}&startDate={yesterday}&limit=45"
    data = _request_xfe(endpoint, credentials)
    return data if isinstance(data, dict) else {"IBM XForce Exchange": "No Data"}


def extractIP(text: str) -> Optional[str]:
    """Extract the first IPv4 address from text."""
    ip_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    matches = ip_re.findall(text)
    return matches[0] if matches else None


def main() -> None:
    """CLI entry point for X-Force."""
    parser = argparse.ArgumentParser(description="Query IBM X-Force Exchange Threat Intelligence API.")
    parser.add_argument("-i", "--ip", dest="ip", help="Query IPv4 intelligence")
    parser.add_argument("-u", "--url", dest="url", help="Query URL intelligence")
    parser.add_argument("-s", "--sig", dest="s_string", help="Search PAM signature name")
    parser.add_argument("-p", "--pam", dest="pam_name", help="Query PAM signature details")
    parser.add_argument("-m", "--multiple", dest="pam_file", help="File of PAM names to query (one per line)")
    parser.add_argument("-c", "--coll", dest="coll_file", help="Export public casefiles to file")
    parser.add_argument("--cve", dest="cve", help="Query CVE details via X-Force")
    parser.add_argument("--hash", dest="hash", help="Query malware hash")
    parser.add_argument("-k", "--key", dest="key", help="X-Force auth credentials override")

    args = parser.parse_args()

    if args.s_string:
        res = ixf_s(args.s_string, credentials=args.key)
        print(f"PAM: {args.s_string}\nDescription: {res[0]}\nRisk Level: {res[1]}\nAffected: {', '.join(res[2])}\nSTD Code: {', '.join(res[3])}")
    elif args.pam_name:
        res = ixf_s(args.pam_name, credentials=args.key)
        print(f"PAM: {args.pam_name}\nDescription: {res[0]}\nRisk Level: {res[1]}\nAffected: {', '.join(res[2])}\nSTD Code: {', '.join(res[3])}")
    elif args.ip:
        print(json.dumps(getip(args.ip, credentials=args.key), indent=2))
    elif args.url:
        print(json.dumps(getURL(args.url, credentials=args.key), indent=2))
    elif args.cve:
        print(json.dumps(getFull(getXFD_fromCVE(args.cve, credentials=args.key), credentials=args.key), indent=2))
    elif args.hash:
        print(json.dumps(getMalw(args.hash, credentials=args.key), indent=2))
    elif args.coll_file:
        public_cases = getCase_Public(credentials=args.key)
        with open(args.coll_file, "w", encoding="utf-8") as f:
            f.write(f"## Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(json.dumps(public_cases, indent=2))
        print(f"Public collections saved to {args.coll_file}")
    elif args.pam_file:
        output_file = f"{args.pam_file}_OUT"
        with open(args.pam_file, "r", encoding="utf-8") as infile, open(output_file, "w", encoding="utf-8") as outfile:
            outfile.write("PAM_Name, Description, Risk_Score, Affected_Systems, STDcode\n")
            for line in infile:
                sig_name = line.strip().strip(",")
                if not sig_name:
                    continue
                print(f"Processing: {sig_name}")
                res = ixf_s(sig_name, credentials=args.key)
                desc = str(res[0]).replace(",", ";")
                outfile.write(f"{sig_name}, {desc}, {res[1]}, {';'.join(res[2])}, {';'.join(res[3])}\n")
                time.sleep(1)
        print(f"Batch PAM results saved to {output_file}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
