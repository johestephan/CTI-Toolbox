#!/usr/bin/env bash
#
# Extract HTTP/HTTPS URIs from logs or files, with optional download support.
#

set -euo pipefail

usage() {
    local exit_code="${1:-0}"
    echo "Usage: $0 [-d|--download] <file>"
    echo "  -d, --download    Actually download the extracted URIs (timeout 3s, max 1 retry)"
    echo "  -h, --help        Show this help message"
    exit "$exit_code"
}

DOWNLOAD=0
FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--download)
            DOWNLOAD=1
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            FILE="$1"
            shift
            ;;
    esac
done

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
    echo "Error: Please specify a valid file." >&2
    usage 1
fi

echo ""
echo "HTTP/HTTPS (objects):"
echo "====================================="

URLS=$(grep -oE "https?://[a-zA-Z0-9./:_~%?&=#+-]+" "$FILE" | sort -u || true)

if [[ -z "$URLS" ]]; then
    echo "No HTTP/HTTPS URIs found."
    exit 0
fi

echo "$URLS"

if [[ "$DOWNLOAD" -eq 1 ]]; then
    echo ""
    echo "Downloading objects to ./downloads/..."
    mkdir -p downloads
    while IFS= read -r ITEM; do
        if [[ -n "$ITEM" ]]; then
            echo "Fetching: $ITEM"
            wget --timeout=3 -t 1 -P downloads/ "$ITEM" || echo "Failed to download $ITEM"
        fi
    done <<< "$URLS"
fi
