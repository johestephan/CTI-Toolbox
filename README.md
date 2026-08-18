# Cyber Threat Intelligence Toolbox (CTI-Toolbox)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A modular Python toolkit for Cyber Threat Intelligence (CTI) analysts, SOC teams, and incident responders. Extract, sanitize, defang, correlate, and enrich Indicators of Compromise (IOCs) across leading threat intelligence APIs and open feeds.

---

## Table of Contents

- [Directory Structure](#directory-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Usage (`cti.py`)](#cli-usage-ctipy)
- [Python Library Usage](#python-library-usage)
- [Modules & Capabilities](#modules--capabilities)
  - [1. IOC Extraction (`extract/`)](#1-ioc-extraction-extract)
  - [2. Defanging & Redaction (`defang/`)](#2-defanging--redaction-defang)
  - [3. Threat Intelligence Providers (`providers/`)](#3-threat-intelligence-providers-providers)
  - [4. Comparison & Utilities (`utils/`)](#4-comparison--utilities-utils)
  - [5. Shell Analysis Scripts (`scripts/`)](#5-shell-analysis-scripts-scripts)
- [Running Tests](#running-tests)
- [License](#license)

---

## Directory Structure

The repository is structured into modular subfolders for easy navigation:

```text
CTI-Toolbox/
├── cti_toolbox/                  # Core Python package
│   ├── config.py                 # Central configuration and API key manager
│   ├── cli.py                    # Unified command-line interface implementation
│   ├── extract/                  # Indicator extraction and feed harvesting
│   │   ├── indicators.py         # IOC extraction (IPs, hashes, CVEs, URLs, emails) & bogon filter
│   │   ├── rss.py                # Security RSS / Atom feed harvester
│   │   └── search.py             # Blocklist & feed directory search (blip)
│   ├── defang/                   # Sanitization and defanging utilities
│   │   ├── redact.py             # Defangs IPs, URLs, domains, emails, & keyword masking
│   │   └── zones.py              # IANA Root TLD zone database (1,300+ TLDs)
│   ├── providers/                # Threat intelligence API integrations
│   │   ├── otx.py                # AlienVault OTX API client
│   │   ├── xforce.py             # IBM X-Force Exchange API client
│   │   ├── slowcook.py           # IBM X-Force threat category scraper & high-roller detector
│   │   ├── virustotal.py         # VirusTotal API client (IP, URL, file hash)
│   │   ├── safebrowsing.py       # Google Safe Browsing v4 threatMatches client
│   │   ├── sans_isc.py           # SANS ISC Microsoft Patch Tuesday client
│   │   ├── packetmail.py         # PacketMail IP reputation client
│   │   └── misp.py               # MISP client & STIX 2.1 JSON bundle exporter
│   └── utils/                    # Common utilities and data formatting
│       ├── compare.py            # Cross-file indicator token overlap & scoring
│       └── formatting.py         # Structured XML/JSON serialization helpers
├── scripts/                      # Shell scripts for incident log parsing & artifact analysis
│   ├── getindiV1.sh              # Web access log scanner & attack extractor
│   ├── getCodeV1.sh              # WGET command and payload URI extractor
│   └── getUriCode.sh             # HTTP/HTTPS URI extractor and downloader
├── data/                         # Sample datasets and references
│   ├── samples/text.xml          # Sample XML indicator export
│   └── zonefile                  # Raw IANA TLD source list
├── tests/                        # Automated unit test suite (16 tests)
│   ├── test_config.py
│   ├── test_indicators.py
│   ├── test_redact.py
│   ├── test_compare.py
│   └── test_providers.py
├── cti.py                        # Top-level CLI executable entry point
├── .env.example                  # Environment configuration template
├── iprep_conf.py.CHANGEME        # Legacy configuration template
├── pyproject.toml                # Modern PEP 517/621 packaging metadata
└── requirements.txt              # Production dependencies
```

---

## Quick Start

### 1. Installation

```bash
git clone https://github.com/johestephan/CTI-Toolbox.git
cd CTI-Toolbox

# Install dependencies
pip install -r requirements.txt

# (Optional) Install in editable/development mode
pip install -e .
```

### 2. Configuration

API keys can be supplied via **Environment Variables**, a **`.env`** file, or a legacy **`iprep_conf.py`** file.

Create your local `.env`:
```bash
cp .env.example .env
```

Edit `.env` with your API keys:
```ini
# AlienVault OTX: https://otx.alienvault.com/api/
OTX_AUTHKEY=your_otx_api_key

# IBM X-Force Exchange (API Key or Basic credentials): https://exchange.xforce.ibmcloud.com/
XFEX_CRED=your_xforce_credentials

# VirusTotal: https://www.virustotal.com/
VT_KEY=your_virustotal_api_key

# Google Safe Browsing: https://console.developers.google.com/
GO_KEY=your_google_api_key

# PacketMail: https://www.packetmail.net/
PACKETMAIL_KEY=your_packetmail_key

# MISP Instance (optional)
MISP_URL=https://misp.your-org.local
MISP_AUTHKEY=your_misp_key
```

---

## CLI Usage (`cti.py`)

The unified CLI `cti.py` provides access to all toolbox capabilities:

```bash
# View available commands
python3 cti.py --help
```

### Common Commands

| Task | Command Example |
| :--- | :--- |
| **Extract IOCs** | `python3 cti.py extract "Attacker at 185.117.73.160 exploited CVE-2021-44228" --format json` |
| **Extract from File** | `python3 cti.py extract -f /var/log/nginx/access.log --format xml` |
| **Defang Indicators** | `python3 cti.py defang "Phishing URL http://malicious.com sent from attacker@bad.com"` |
| **Custom Redaction** | `python3 cti.py defang "SecretProject server 10.0.0.1" -k "SecretProject,$#=[REDACTED]"` |
| **AlienVault OTX IP** | `python3 cti.py otx -i 8.8.8.8` |
| **AlienVault OTX CVE** | `python3 cti.py otx -c CVE-2021-44228` |
| **IBM X-Force IP** | `python3 cti.py xfe -i 185.117.73.160` |
| **VirusTotal Hash/IP** | `python3 cti.py vt 5d41402abc4b2a76b9719d911017c592` |
| **Google Safe Browsing**| `python3 cti.py google "http://testsafebrowsing.appspot.com/s/malware.html"` |
| **Patch Tuesday** | `python3 cti.py ptuesday 2024-01-09` |
| **Threat RSS Feeds** | `python3 cti.py rss --format text` |
| **Compare Lists** | `python3 cti.py compare feed1.txt feed2.txt` |
| **PacketMail IP Rep** | `python3 cti.py pama "Suspicious IP 198.51.100.22 observed"` |

---

## Python Library Usage

You can import and use `cti_toolbox` directly in your Python applications:

```python
from cti_toolbox.extract import indicators
from cti_toolbox.defang import redact
from cti_toolbox.providers import otx, virustotal

# 1. Extract IOCs from raw unstructured text
raw_text = "Found attack from 185.117.73.160 downloading http://evil.com/payload.exe (MD5: 5d41402abc4b2a76b9719d911017c592)"
iocs = indicators.get_all_indicators(raw_text)
print(iocs)
# Output: {'ipv4': ['185.117.73.160'], 'md5': ['5d41402abc4b2a76b9719d911017c592'], 'url': ['http://evil.com/payload.exe'], ...}

# 2. Defang indicators for safe reporting
safe_text = redact.redactit(raw_text)
print(safe_text)
# Output: Found attack from 185.117.73[.]160 downloading hxxp://evil[.]com/payload.exe ...

# 3. Query Threat Intel APIs
otx_info = otx.IPmax("8.8.8.8")
vt_report = virustotal.search("5d41402abc4b2a76b9719d911017c592")
```

---

## Modules & Capabilities

### 1. IOC Extraction (`extract/`)
- **[cti_toolbox/extract/indicators.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/extract/indicators.py)**: Extracts IPv4, IPv6, MD5, SHA-1, SHA-256, CVEs (normalized to `CVE-YYYY-NNNN`), URLs, and emails. Features bogon / RFC1918 private network filtering.
- **[cti_toolbox/extract/rss.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/extract/rss.py)**: Harvester for security advisories (CISA, Malware Traffic Analysis, Hacker News).
- **[cti_toolbox/extract/search.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/extract/search.py)**: Searches local blocklists or feed directories for target indicators.

### 2. Defanging & Redaction (`defang/`)
- **[cti_toolbox/defang/redact.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/defang/redact.py)**: Safe defanging of URIs (`http://` -> `hxxp://`), IPs (`1.1.1.1` -> `1.1.1[.]1`), emails (`user@evil.com` -> `user[@]evil[.]com`), and domain TLDs (`evil.com` -> `evil[.]com`).
- **[cti_toolbox/defang/zones.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/defang/zones.py)**: Comprehensive dictionary of 1,300+ IANA root zone TLDs.

### 3. Threat Intelligence Providers (`providers/`)
- **[cti_toolbox/providers/otx.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/providers/otx.py)**: AlienVault OTX API integration (reputation, malware samples, passive DNS, pulses).
- **[cti_toolbox/providers/xforce.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/providers/xforce.py)**: IBM X-Force Exchange (IP reputation, vulnerability database, PAM signatures, shared casefiles).
- **[cti_toolbox/providers/slowcook.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/providers/slowcook.py)**: Scrapes X-Force threat categories (C2, Bots, Malware, Spam) for high-roller IPs exceeding score thresholds.
- **[cti_toolbox/providers/virustotal.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/providers/virustotal.py)**: VirusTotal lookup for IPs, URLs, domains, and hashes.
- **[cti_toolbox/providers/safebrowsing.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/providers/safebrowsing.py)**: Google Safe Browsing API v4 real-time verification.
- **[cti_toolbox/providers/sans_isc.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/providers/sans_isc.py)**: SANS ISC Patch Tuesday vulnerability database.
- **[cti_toolbox/providers/packetmail.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/providers/packetmail.py)**: PacketMail IP reputation service.
- **[cti_toolbox/providers/misp.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/providers/misp.py)**: MISP indicator extraction and STIX 2.1 JSON bundle export.

### 4. Comparison & Utilities (`utils/`)
- **[cti_toolbox/utils/compare.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/utils/compare.py)**: Correlates indicator lists and calculates token overlap scores.
- **[cti_toolbox/utils/formatting.py](file:///MyProjects/CTI-Toolbox/cti_toolbox/utils/formatting.py)**: XML/JSON/HTML serialization helpers.

### 5. Shell Analysis Scripts (`scripts/`)
- **[scripts/getindiV1.sh](file:///MyProjects/CTI-Toolbox/scripts/getindiV1.sh)**: High-speed log scanner for attack signatures (Masscan, Zmeu, Nikto, SQLmap, command injections).
- **[scripts/getCodeV1.sh](file:///MyProjects/CTI-Toolbox/scripts/getCodeV1.sh)**: Extract wget commands and dropped binaries.
- **[scripts/getUriCode.sh](file:///MyProjects/CTI-Toolbox/scripts/getUriCode.sh)**: Extract HTTP/HTTPS URIs from incident notes with optional `--download`.

---

## Running Tests

The test suite uses Python's built-in `unittest` runner and requires no external testing dependencies:

```bash
# Run all unit tests
python3 -m unittest discover -v tests
```

---

## License

```text
Copyright 2016-2026 Joerg Stephan & Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```