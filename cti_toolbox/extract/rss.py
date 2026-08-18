"""Threat Intelligence RSS Feed Harvester.

Parses security RSS / Atom feeds, extracts threat indicators, and exports XML / JSON summaries.
"""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from typing import Any, Optional

import requests

try:
    from cti_toolbox.extract import indicators
except ImportError:
    import indifetch as indicators  # type: ignore

DEFAULT_RSS_FEEDS = [
    "https://www.malware-traffic-analysis.net/blog-entries.rss",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
]

TIMEOUT = 10


def _parse_xml_feed(content: bytes) -> list[dict[str, str]]:
    """Parse RSS/Atom feeds using standard library ElementTree."""
    entries: list[dict[str, str]] = []
    try:
        root = ET.fromstring(content)
        channel = root.find("channel")
        if channel is not None:
            for item in channel.findall("item"):
                title = item.findtext("title", "")
                description = item.findtext("description", "")
                link = item.findtext("link", "")
                entries.append({"title": title, "summary": description, "link": link})
            return entries

        for entry in root.findall("{http://www.w3.org/2005/Atom}entry"):
            title = entry.findtext("{http://www.w3.org/2005/Atom}title", "")
            summary = entry.findtext("{http://www.w3.org/2005/Atom}summary", "") or entry.findtext("{http://www.w3.org/2005/Atom}content", "")
            link_elem = entry.find("{http://www.w3.org/2005/Atom}link")
            link = link_elem.get("href", "") if link_elem is not None else ""
            entries.append({"title": title, "summary": summary, "link": link})
    except ET.ParseError:
        pass
    return entries


def fetch_feed(url: str) -> list[dict[str, str]]:
    """Fetch and parse feed items using feedparser or ElementTree."""
    try:
        import feedparser  # type: ignore
        feed = feedparser.parse(url)
        items: list[dict[str, str]] = []
        for item in feed.get("items", []):
            items.append({
                "title": item.get("title", ""),
                "summary": item.get("summary", "") or item.get("description", ""),
                "link": item.get("link", ""),
            })
        return items
    except ImportError:
        pass

    try:
        response = requests.get(url, headers={"User-Agent": "CTI-Toolbox/1.1.0"}, timeout=TIMEOUT)
        if response.status_code == 200:
            return _parse_xml_feed(response.content)
    except requests.RequestException:
        pass

    return []


def get(feeds: Optional[list[str]] = None, output_format: str = "xml") -> str:
    """Fetch all configured feeds and extract indicators."""
    feed_list = feeds or DEFAULT_RSS_FEEDS
    results: list[dict[str, Any]] = []
    xml_chunks: list[str] = []

    for url in feed_list:
        feed_items = fetch_feed(url)
        combined_text = " ".join([f"{item['title']} {item['summary']}" for item in feed_items])
        found = indicators.get_all_indicators(combined_text)

        results.append({
            "feed_url": url,
            "item_count": len(feed_items),
            "indicators": found,
        })

        xml_data = indicators.getXML(combined_text, ox="yes")
        xml_chunks.append(f"##\n# {url}\n##\n{xml_data}")

    if output_format == "json":
        return json.dumps(results, indent=2)
    return "\n\n".join(xml_chunks)


def main() -> None:
    """CLI entry point for rss feed extractor."""
    parser = argparse.ArgumentParser(description="Harvest threat indicators from security RSS feeds.")
    parser.add_argument("-u", "--url", help="Custom RSS feed URL to parse")
    parser.add_argument("-f", "--format", choices=["xml", "json", "text"], default="text", help="Output format")

    args = parser.parse_args()

    feeds = [args.url] if args.url else DEFAULT_RSS_FEEDS

    if args.format == "json":
        print(get(feeds, output_format="json"))
    elif args.format == "xml":
        print(get(feeds, output_format="xml"))
    else:
        for url in feeds:
            items = fetch_feed(url)
            print(f"=== Feed: {url} ({len(items)} items) ===")
            text = " ".join([f"{i['title']} {i['summary']}" for i in items])
            found = indicators.get_all_indicators(text)
            for k, v in found.items():
                if v:
                    print(f"  {k.upper()}: {', '.join(v)}")
            print()


if __name__ == "__main__":
    main()
