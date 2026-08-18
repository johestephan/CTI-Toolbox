"""Threat intelligence defanging and redaction utility.

Defangs indicators of compromise (IPs, URLs, domains, email addresses)
to prevent accidental clicks and malicious activation.
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Optional

try:
    from cti_toolbox.defang import zones
except ImportError:
    import redactit_zone as zones  # type: ignore

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_SCHEME_RE = re.compile(r"\b(https?|ftp|file)://", re.IGNORECASE)


def redact_ip(ip: str) -> str:
    """Defang an IPv4 address (e.g. 192.168.1.1 -> 192.168.1[.]1)."""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + "[.]" + parts[3]
    return ip


def redactIP(ip: str) -> str:
    """Backward-compatible alias for redact_ip."""
    return redact_ip(ip)


def redact_email(email: str) -> str:
    """Defang an email address (e.g. user@domain.com -> user[@]domain[.]com)."""
    if "@" not in email:
        return email
    user, domain = email.split("@", 1)
    if "." in domain:
        domain_parts = domain.rsplit(".", 1)
        new_domain = domain_parts[0] + "[.]" + domain_parts[1]
    else:
        new_domain = domain
    return f"{user}[@]{new_domain}"


def redactemail(email: str) -> str:
    """Backward-compatible alias for redact_email."""
    return redact_email(email)


def redact_schemes(text: str) -> str:
    """Defang URI schemes (http:// -> hxxp://, https:// -> hxxps://, ftp:// -> fxp://)."""
    def _replace_scheme(match: re.Match[str]) -> str:
        scheme = match.group(1).lower()
        if scheme == "http":
            return "hxxp://"
        elif scheme == "https":
            return "hxxps://"
        elif scheme == "ftp":
            return "fxp://"
        return f"{scheme}://"

    return _SCHEME_RE.sub(_replace_scheme, text)


def redact_domains(text: str) -> str:
    """Defang domain TLDs using the zone database."""
    tld_dict = getattr(zones, "ROOT_DOMAIN_LIST", getattr(zones, "ROOOT_Domain_List", {}))
    for tld, defanged_tld in tld_dict.items():
        pattern = re.escape(tld) + r"(?=[\s/:?#\"'<>,\)\]]|$)"
        text = re.sub(pattern, defanged_tld, text)
    return text


def redactit(text: str, searchkey: Optional[str] = None) -> str:
    """Defang and sanitize text containing IOCs, with optional keyword redaction."""
    if not text:
        return ""

    if searchkey and len(searchkey) > 1:
        custom_replacement = "<REDACTED>"
        keys_to_replace: list[str] = []
        for item in searchkey.split(","):
            item = item.strip()
            if item.startswith("$#="):
                custom_replacement = item.split("=", 1)[1]
            elif item:
                keys_to_replace.append(item)

        for key in keys_to_replace:
            text = text.replace(key, custom_replacement)

    # 1. Defang protocols / schemes
    text = redact_schemes(text)

    # 2. Defang IP addresses
    found_ips = set(_IPV4_RE.findall(text))
    for ip in found_ips:
        text = text.replace(ip, redact_ip(ip))

    # 3. Defang email addresses
    found_emails = set(_EMAIL_RE.findall(text))
    for email in found_emails:
        text = text.replace(email, redact_email(email))

    # 4. Defang root domains
    text = redact_domains(text)

    return text


def main() -> None:
    """Command-line interface for redactit."""
    parser = argparse.ArgumentParser(
        description="Defang and sanitize IOCs (IPs, URLs, Domains, Emails) in text.",
    )
    parser.add_argument("input", nargs="?", default=None, help="Input text or file path (reads stdin if omitted)")
    parser.add_argument("-k", "--key", dest="searchkey", default=None, help="Custom keywords to redact (e.g. 'org_name,secret,$#=[MASK]')")
    parser.add_argument("-f", "--file", dest="filepath", default=None, help="Path to file to redact")

    args = parser.parse_args()

    content = ""
    if args.filepath:
        with open(args.filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    elif args.input:
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

    result = redactit(content, searchkey=args.searchkey)
    print(result)


if __name__ == "__main__":
    main()
