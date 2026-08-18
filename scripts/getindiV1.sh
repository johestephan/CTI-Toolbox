#!/usr/bin/env bash
#
# Fast shell-based IOC extractor for server access logs and incident artifacts.
#

set -euo pipefail

usage() {
    local exit_code="${1:-0}"
    echo "Usage: $0 <log_file>"
    echo "Extracts scanner IPs, HTTP URLs, WGET/FTP payloads, and cmd= injection strings."
    exit "$exit_code"
}

if [[ $# -lt 1 ]]; then
    usage 1
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage 0
fi

if [[ ! -f "$1" ]]; then
    echo "Error: File not found: $1" >&2
    exit 1
fi

FILE="$1"

echo ""
echo "Scanning IPs: (known scanner user-agents / signatures)"
echo "======================================================"
grep -a -i -E "zmeu|masscan|python|perl|curl|black|mui|jorgee|nmap|nikto|sqlmap|gobuster|dirbuster" "$FILE" \
    | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u || true

echo ""
echo "HTTP/HTTPS URLs (objects):"
echo "======================================================"
grep -oE "https?://[a-zA-Z0-9./:_~%?&=#+-]+" "$FILE" | sort -u || true

echo ""
echo "WGET/CURL/FTP Commands (objects):"
echo "======================================================"
grep -oE "(wget|curl|ftp)\s+[a-zA-Z0-9./:_~-]+" "$FILE" | sort -u || true

echo ""
echo "Command Injection (cmd= / eval=):"
echo "======================================================"
grep -oE "(cmd|eval|exec|system)=[a-zA-Z0-9./:%_~+&?=-]+" "$FILE" | sort -u || true
