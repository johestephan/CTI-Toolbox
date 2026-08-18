"""Unified Command Line Interface for CTI-Toolbox."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from cti_toolbox import config
from cti_toolbox.extract import indicators, rss
from cti_toolbox.defang import redact
from cti_toolbox.providers import (
    otx,
    xforce,
    virustotal,
    safebrowsing,
    sans_isc,
    packetmail,
)
from cti_toolbox.utils import compare


def cmd_extract(args: argparse.Namespace) -> None:
    content = _get_input(args.input, args.file)
    if args.format == "json":
        print(indicators.getJSON(content))
    elif args.format == "xml":
        print(indicators.getXML(content))
    elif args.format == "html":
        print(indicators.va(content))
    else:
        found = indicators.get_all_indicators(content)
        for cat, items in found.items():
            if items:
                print(f"[{cat.upper()}] ({len(items)}):")
                for it in items:
                    print(f"  - {it}")


def cmd_defang(args: argparse.Namespace) -> None:
    content = _get_input(args.input, args.file)
    print(redact.redactit(content, searchkey=args.key))


def cmd_otx(args: argparse.Namespace) -> None:
    if args.ip:
        print(json.dumps(otx.IPmax(args.ip, auth_key=args.key), indent=2))
    elif args.url:
        print(json.dumps(otx.URL(args.url, auth_key=args.key), indent=2))
    elif args.cve:
        print(json.dumps(otx.CVE(args.cve, auth_key=args.key), indent=2))
    elif args.hash:
        print(json.dumps(otx.getMalhash(args.hash, auth_key=args.key), indent=2))
    elif args.pulses:
        print(json.dumps(otx.PulseSub(auth_key=args.key), indent=2))
    else:
        print("Specify an indicator to query with --ip, --url, --cve, --hash, or --pulses", file=sys.stderr)


def cmd_xfe(args: argparse.Namespace) -> None:
    if args.ip:
        print(json.dumps(xforce.getip(args.ip, credentials=args.key), indent=2))
    elif args.url:
        print(json.dumps(xforce.getURL(args.url, credentials=args.key), indent=2))
    elif args.cve:
        xfid = xforce.getXFD_fromCVE(args.cve, credentials=args.key)
        print(json.dumps(xforce.getFull(xfid, credentials=args.key), indent=2))
    elif args.hash:
        print(json.dumps(xforce.getMalw(args.hash, credentials=args.key), indent=2))
    elif args.sig:
        res = xforce.ixf_s(args.sig, credentials=args.key)
        print(f"PAM: {args.sig}\nDescription: {res[0]}\nRisk: {res[1]}\nAffected: {', '.join(res[2])}\nSTD: {', '.join(res[3])}")
    else:
        print("Specify an indicator to query with --ip, --url, --cve, --hash, or --sig", file=sys.stderr)


def cmd_vt(args: argparse.Namespace) -> None:
    target = args.indicator or args.ip or args.url or args.hash
    if not target:
        print("Specify an indicator to query (IP, URL, or hash)", file=sys.stderr)
        return
    res = virustotal.search(target, api_key=args.key)
    print(json.dumps(res, indent=2))


def cmd_google(args: argparse.Namespace) -> None:
    res = safebrowsing.lookup(args.url, api_key=args.key)
    print(json.dumps(res, indent=2))


def cmd_ptuesday(args: argparse.Namespace) -> None:
    data = sans_isc.getbyDate(args.date)
    if args.format == "json":
        print(json.dumps(data, indent=2))
    elif args.format == "html":
        print(sans_isc.pt_toWeb(args.date))
    else:
        entries = data.get("getmspatchday", [])
        if isinstance(entries, dict):
            entries = [entries]
        for item in entries:
            print(f"[{item.get('id', 'N/A')}] {item.get('title', 'N/A')}")
            print(f"  Severity: {item.get('severity', 'N/A')} | Exploits: {item.get('exploits', 'N/A')}")


def cmd_rss(args: argparse.Namespace) -> None:
    feeds = [args.url] if args.url else None
    print(rss.get(feeds=feeds, output_format=args.format))


def cmd_compare(args: argparse.Namespace) -> None:
    stats = compare.compare_files(args.file1, args.file2, min_word_matches=args.min_matches, verbose=not args.quiet)
    print(f"\nSummary: {stats['matches']} matches between {args.file1} and {args.file2}")


def cmd_pama(args: argparse.Namespace) -> None:
    content = _get_input(args.input, args.file)
    print(packetmail.doAnalyse(content, key=args.key))


def _get_input(text_arg: Optional[str], file_arg: Optional[str]) -> str:
    if file_arg:
        with open(file_arg, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    if text_arg:
        if os.path.isfile(text_arg):
            with open(text_arg, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        return text_arg
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cti",
        description="CTI-Toolbox: Cyber Threat Intelligence swiss army knife.",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {config.VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Extract command
    p_extract = subparsers.add_parser("extract", help="Extract IOCs from text or files")
    p_extract.add_argument("input", nargs="?", help="Input text or file")
    p_extract.add_argument("-f", "--file", help="Input file path")
    p_extract.add_argument("--format", choices=["text", "json", "xml", "html"], default="text")
    p_extract.set_defaults(func=cmd_extract)

    # Defang command
    p_defang = subparsers.add_parser("defang", help="Defang and sanitize IOCs")
    p_defang.add_argument("input", nargs="?", help="Input text or file")
    p_defang.add_argument("-f", "--file", help="Input file path")
    p_defang.add_argument("-k", "--key", help="Custom keywords to redact")
    p_defang.set_defaults(func=cmd_defang)

    # OTX command
    p_otx = subparsers.add_parser("otx", help="Query AlienVault OTX")
    p_otx.add_argument("-i", "--ip", help="Query IP")
    p_otx.add_argument("-u", "--url", help="Query URL")
    p_otx.add_argument("-c", "--cve", help="Query CVE")
    p_otx.add_argument("-s", "--hash", help="Query Hash")
    p_otx.add_argument("-p", "--pulses", action="store_true", help="Get subscribed pulses")
    p_otx.add_argument("-k", "--key", help="API Key override")
    p_otx.set_defaults(func=cmd_otx)

    # XFE command
    p_xfe = subparsers.add_parser("xfe", help="Query IBM X-Force Exchange")
    p_xfe.add_argument("-i", "--ip", help="Query IP")
    p_xfe.add_argument("-u", "--url", help="Query URL")
    p_xfe.add_argument("-c", "--cve", help="Query CVE")
    p_xfe.add_argument("-s", "--hash", help="Query Hash")
    p_xfe.add_argument("-p", "--sig", help="Query PAM signature")
    p_xfe.add_argument("-k", "--key", help="Auth credentials override")
    p_xfe.set_defaults(func=cmd_xfe)

    # VT command
    p_vt = subparsers.add_parser("vt", help="Query VirusTotal")
    p_vt.add_argument("indicator", nargs="?", help="Target IP, URL, or hash")
    p_vt.add_argument("-i", "--ip", help="Target IP")
    p_vt.add_argument("-u", "--url", help="Target URL")
    p_vt.add_argument("-s", "--hash", help="Target hash")
    p_vt.add_argument("-k", "--key", help="API Key override")
    p_vt.set_defaults(func=cmd_vt)

    # Google SafeBrowsing command
    p_go = subparsers.add_parser("google", help="Query Google Safe Browsing")
    p_go.add_argument("url", help="URL to inspect")
    p_go.add_argument("-k", "--key", help="Google API key override")
    p_go.set_defaults(func=cmd_google)

    # Patch Tuesday command
    p_pt = subparsers.add_parser("ptuesday", help="Query SANS ISC Patch Tuesday")
    p_pt.add_argument("date", help="Date (YYYY-MM-DD or YYYYMM)")
    p_pt.add_argument("--format", choices=["text", "json", "html"], default="text")
    p_pt.set_defaults(func=cmd_ptuesday)

    # RSS command
    p_rss = subparsers.add_parser("rss", help="Harvest threat feeds")
    p_rss.add_argument("-u", "--url", help="Feed URL")
    p_rss.add_argument("--format", choices=["text", "json", "xml"], default="text")
    p_rss.set_defaults(func=cmd_rss)

    # Compare command
    p_cmp = subparsers.add_parser("compare", help="Compare two indicator lists")
    p_cmp.add_argument("file1", help="First file")
    p_cmp.add_argument("file2", help="Second file")
    p_cmp.add_argument("-m", "--min-matches", type=int, default=1)
    p_cmp.add_argument("-q", "--quiet", action="store_true")
    p_cmp.set_defaults(func=cmd_compare)

    # PacketMail command
    p_pama = subparsers.add_parser("pama", help="Query PacketMail IP reputation")
    p_pama.add_argument("input", nargs="?", help="Input text or file")
    p_pama.add_argument("-f", "--file", help="Input file path")
    p_pama.add_argument("-k", "--key", help="API Key override")
    p_pama.set_defaults(func=cmd_pama)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
