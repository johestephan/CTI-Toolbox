"""Configuration manager for CTI-Toolbox.

Loads settings from environment variables, .env file, or legacy iprep_conf.py.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Optional

VERSION = "1.1.0"

# Default configuration values
DEFAULT_CONFIG = {
    "otx_authkey": "",
    "xfex_cred": "",
    "vt_key": "",
    "go_key": "",
    "sc_apikey": "",
    "pama_key": "",
    "misp_url": "http://127.0.0.1:8080",
    "misp_authkey": "",
    "LOCAL_LINK": "http://127.0.0.1:5010",
    "LOCAL_PORT": "5010",
    "VERSION": VERSION,
}


def _load_env_file(env_path: Path) -> dict[str, str]:
    """Parse a simple .env file without external dependencies."""
    env_vars: dict[str, str] = {}
    if not env_path.is_file():
        return env_vars
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    env_vars[key] = val
    except Exception:
        pass
    return env_vars


def _load_legacy_conf(conf_path: Path) -> dict[str, Any]:
    """Load settings from legacy iprep_conf.py if present."""
    legacy_vars: dict[str, Any] = {}
    if not conf_path.is_file():
        return legacy_vars
    try:
        scope: dict[str, Any] = {}
        with open(conf_path, "r", encoding="utf-8") as f:
            code = f.read()
            exec(code, scope)  # noqa: S102
        for k, v in scope.items():
            if not k.startswith("__"):
                legacy_vars[k] = v
    except Exception:
        pass
    return legacy_vars


# Root directory of the repository (parent of cti_toolbox or current working directory)
BASE_DIR = Path(__file__).resolve().parent.parent

# Load configs in priority order: default < legacy file < .env < environment variables
_legacy_conf = _load_legacy_conf(BASE_DIR / "iprep_conf.py")
_env_conf = _load_env_file(BASE_DIR / ".env")

# Map environment variable names to config keys
_ENV_MAPPINGS = {
    "OTX_AUTHKEY": "otx_authkey",
    "OTX_API_KEY": "otx_authkey",
    "XFEX_CRED": "xfex_cred",
    "XFORCE_CRED": "xfex_cred",
    "XFORCE_API_KEY": "xfex_cred",
    "VT_KEY": "vt_key",
    "VIRUSTOTAL_API_KEY": "vt_key",
    "GO_KEY": "go_key",
    "GOOGLE_API_KEY": "go_key",
    "GOOGLE_SAFEBROWSING_KEY": "go_key",
    "SC_APIKEY": "sc_apikey",
    "SLOWCOOK_APIKEY": "sc_apikey",
    "PAMA_KEY": "pama_key",
    "PACKETMAIL_KEY": "pama_key",
    "MISP_URL": "misp_url",
    "MISP_AUTHKEY": "misp_authkey",
    "LOCAL_LINK": "LOCAL_LINK",
    "LOCAL_PORT": "LOCAL_PORT",
}


def get_config(key: str, default: Any = "") -> Any:
    """Retrieve a config value from env, .env, legacy conf, or defaults."""
    # Check OS environment
    for env_key, mapped_key in _ENV_MAPPINGS.items():
        if mapped_key == key and env_key in os.environ:
            return os.environ[env_key]
    if key.upper() in os.environ:
        return os.environ[key.upper()]
    if key in os.environ:
        return os.environ[key]

    # Check .env
    for env_key, mapped_key in _ENV_MAPPINGS.items():
        if mapped_key == key and env_key in _env_conf:
            return _env_conf[env_key]
    if key in _env_conf:
        return _env_conf[key]

    # Check legacy iprep_conf.py
    if key in _legacy_conf:
        return _legacy_conf[key]

    # Return default
    return DEFAULT_CONFIG.get(key, default)


# Module-level variable exports
otx_authkey: str = str(get_config("otx_authkey"))
xfex_cred: str = str(get_config("xfex_cred"))
vt_key: str = str(get_config("vt_key"))
go_key: str = str(get_config("go_key"))
sc_apikey: str = str(get_config("sc_apikey"))
pama_key: str = str(get_config("pama_key", sc_apikey))
misp_url: str = str(get_config("misp_url"))
misp_authkey: str = str(get_config("misp_authkey"))
LOCAL_LINK: str = str(get_config("LOCAL_LINK"))
LOCAL_PORT: str = str(get_config("LOCAL_PORT"))


def validate_key(key_name: str, key_val: Optional[str]) -> bool:
    """Check if a required API key is configured."""
    if not key_val or key_val.strip() in ("", "CHANGEME", "YOUR_API_KEY_HERE"):
        sys.stderr.write(f"[WARNING] '{key_name}' is not configured. Some API requests may fail.\n")
        return False
    return True
