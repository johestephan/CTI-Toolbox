"""Formatting and serialization helpers for indicators."""

from __future__ import annotations

import html
import json
from typing import Any


def StoXML(selftype: str, value: Any) -> str:
    """Format an indicator into an XML string."""
    safe_type = html.escape(str(selftype).strip())
    safe_val = html.escape(str(value).strip())
    return f"<indicator>\n  <type>{safe_type}</type>\n  <value>{safe_val}</value>\n</indicator>\n"


def StoJSON(selftype: str, value: Any) -> str:
    """Format an indicator into a JSON string."""
    return json.dumps({str(selftype).strip(): str(value).strip()}, indent=2)


def sanitize_input(text: str) -> str:
    """Strip dangerous characters and whitespace from raw input strings."""
    if not isinstance(text, str):
        return str(text)
    return text.strip()
