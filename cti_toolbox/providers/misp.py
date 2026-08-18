"""MISP & STIX 2.1 Threat Intelligence Client."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import requests

try:
    from cti_toolbox import config as IC
except ImportError:
    import config as IC  # type: ignore

DEFAULT_INDICATOR_TYPES = ["md5", "sha256", "ip-src", "ip-dst", "domain", "url", "filename"]
TIMEOUT = 15


def _get_misp_headers(auth_key: Optional[str] = None) -> dict[str, str]:
    key = auth_key or (getattr(IC, "misp_authkey", "") if IC else "")
    return {
        "Authorization": str(key).strip(),
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "CTI-Toolbox/1.1.0 (MISP-Wrapper)",
    }


def fetch_misp_attributes(
    misp_url: str,
    indicator_type: str,
    auth_key: Optional[str] = None,
) -> list[str]:
    """Download plain-text indicator values of a specific type from MISP."""
    base = misp_url.rstrip("/")
    endpoint = f"{base}/attributes/text/download/{indicator_type}"
    headers = _get_misp_headers(auth_key)

    try:
        response = requests.get(endpoint, headers=headers, timeout=TIMEOUT, verify=False)  # noqa: S501
        if response.status_code == 200:
            return [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
        else:
            sys.stderr.write(f"[MISP Error] HTTP {response.status_code} fetching {indicator_type}\n")
            return []
    except requests.RequestException as e:
        sys.stderr.write(f"[MISP Connection Error] {e}\n")
        return []


def create_stix_bundle(indicators_by_type: dict[str, list[str]], title: str = "MISP Export") -> dict[str, Any]:
    """Package indicators into a STIX 2.1 JSON bundle."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stix_objects: list[dict[str, Any]] = []

    type_to_pattern = {
        "md5": lambda v: f"[file:hashes.md5 = '{v}']",
        "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        "ip-src": lambda v: f"[ipv4-addr:value = '{v}']",
        "ip-dst": lambda v: f"[ipv4-addr:value = '{v}']",
        "domain": lambda v: f"[domain-name:value = '{v}']",
        "url": lambda v: f"[url:value = '{v}']",
    }

    for ind_type, values in indicators_by_type.items():
        pattern_fn = type_to_pattern.get(ind_type)
        if not pattern_fn:
            continue
        for val in values:
            obj_id = f"indicator--{uuid.uuid4()}"
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": obj_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"{ind_type.upper()}: {val}",
                "pattern": pattern_fn(val),
                "pattern_type": "stix",
                "valid_from": now_iso,
            })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects,
    }


def export_all_indicators(
    misp_url: Optional[str] = None,
    auth_key: Optional[str] = None,
    types: Optional[list[str]] = None,
) -> dict[str, list[str]]:
    """Download indicators for all configured types from MISP."""
    url = misp_url or (getattr(IC, "misp_url", "http://127.0.0.1:8080") if IC else "http://127.0.0.1:8080")
    indicator_types = types or DEFAULT_INDICATOR_TYPES
    results: dict[str, list[str]] = {}

    for ind_type in indicator_types:
        values = fetch_misp_attributes(url, ind_type, auth_key)
        results[ind_type] = values

    return results


def main() -> None:
    """CLI entry point for MISP wrapper."""
    parser = argparse.ArgumentParser(description="Fetch indicators from MISP and export to STIX 2.1 or JSON.")
    parser.add_argument("-m", "--misp", dest="misp_url", default=None, help="URL of MISP instance (e.g. https://misp.local)")
    parser.add_argument("-k", "--key", dest="auth_key", default=None, help="MISP API Auth Key")
    parser.add_argument("-t", "--types", nargs="+", default=DEFAULT_INDICATOR_TYPES, help="Indicator types to download")
    parser.add_argument("-f", "--format", choices=["json", "stix", "text"], default="stix", help="Output format (default: stix)")
    parser.add_argument("-o", "--output", dest="output_file", help="Path to save output file")

    args = parser.parse_args()

    misp_url = args.misp_url or (getattr(IC, "misp_url", "http://127.0.0.1:8080") if IC else "http://127.0.0.1:8080")
    indicators = export_all_indicators(misp_url, args.auth_key, args.types)

    if args.format == "stix":
        bundle = create_stix_bundle(indicators)
        output_content = json.dumps(bundle, indent=2)
    elif args.format == "json":
        output_content = json.dumps(indicators, indent=2)
    else:
        lines: list[str] = []
        for itype, vals in indicators.items():
            lines.append(f"=== {itype.upper()} ({len(vals)}) ===")
            lines.extend(vals)
            lines.append("")
        output_content = "\n".join(lines)

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(output_content)
        print(f"Exported {args.format.upper()} data to {args.output_file}")
    else:
        print(output_content)


if __name__ == "__main__":
    main()
