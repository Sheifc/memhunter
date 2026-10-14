"""
memhunter/config.py
Environment configuration and strict false-positive blocklists eliminating legacy
service_memdump noise (X.509 OIDs, version numbers, sandbox hooks, and FTP runtime strings).
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent

for env_path in (REPO_ROOT / ".env", Path.cwd() / ".env", Path.home() / ".env"):
    if env_path.is_file():
        load_dotenv(env_path)
        break

GTI_KEY = os.getenv("GTI_KEY", "").strip() or os.getenv("VT_API_KEY", "").strip()
DEFAULT_BASE_URL = os.getenv("GTI_BASE_URL", "https://www.virustotal.com/api/v3").rstrip("/")
DEFAULT_OUTPUT_DIR = Path(os.getenv("MEMHUNTER_OUTPUT_DIR", str(REPO_ROOT / "output")))
DEFAULT_TMP_DIR = Path(os.getenv("MEMHUNTER_TMP_DIR", "/tmp"))
MAX_DUMP_MB = int(os.getenv("MEMHUNTER_MAX_DUMP_MB", "1500"))
DOWNLOAD_TIMEOUT = int(os.getenv("MEMHUNTER_DOWNLOAD_TIMEOUT", "180"))

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# 1. X.509 OID prefixes and binary/assembly version numbers misclassified as IPv4 by legacy scanners
FALSE_POSITIVE_IP_PREFIXES = (
    "1.3.6.1",
    "1.3.14.",
    "1.3.36.",
    "1.3.132.",
    "1.3.185.",
    "1.9.16.",
    "2.5.4.",
    "2.5.5.",
    "2.5.29.",
    "2.16.840.",
    "2.23.43.",
    "2.23.140.",
    "1.2.840.",
    "0.",
    "127.",
    "169.254.",
    "224.",
    "239.",
    "240.",
    "255.",
)

FALSE_POSITIVE_EXACT_IPS = {
    "1.3.6.1",
    "1.0.0.0",
    "1.0.0.1",
    "1.0.0.10",
    "1.0.1.1",
    "2.0.0.0",
    "4.0.0.0",
    "4.0.0.1",
    "4.0.30319",
    "5.0.0.0",
    "5.1.0.0",
    "5.5.7.1",
    "5.15.2.0",
    "6.0.0.0",
    "8.8.8.8",
    "8.8.4.4",
    "49.1.1.1",
}

# 2. Sandbox hooks, Python runtime docstrings, and benign CA/schema URLs polluting URL/DDR lists
FALSE_POSITIVE_URL_SUBSTRINGS = (
    "github.com/therealdreg/anticuckoo",
    "github.com/python/cpython",
    "github.com/urllib3/urllib3",
    "github.com/psf/requests",
    "github.com/tensorflow/",
    "github.com/aliftype/",
    "github.com/google/fonts",
    "notofonts.github.io",
    "schemas.microsoft.com",
    "schemas.xmlsoap.org",
    "www.w3.org",
    "purl.org",
    "ocsp.digicert.com",
    "crl.comodoca.com",
    "crt.sectigo.com",
    "crl.sectigo.com",
    "ocsp.sectigo.com",
    "crl.microsoft.com",
    "www.microsoft.com/pki",
    "www.microsoft.com0",
    "wdcp.microsoft.com",
    "letsencrypt.org",
    "pki.goog",
    "aka.ms/",
    "go.microsoft.com",
    "www.jiyu-kobo.co.jp",
    "ftp.unicode.org",
)

# 3. Runtime strings misclassified as FTP credentials/activity
FALSE_POSITIVE_FTP_STRINGS = {
    "USER API",
    "USER INTERACTION:",
    "USER INTERACTION",
    "USER NAME",
    "USER PROFILE",
    "USER ENV",
    "ftp://ftp.unicode.org/",
    "ftp://ftp.unicode.org",
}


def is_valid_public_c2_ip(candidate: str) -> bool:
    """Validate that a candidate IPv4 string is a real routable IP and not an X.509 OID or version."""
    val = candidate.strip()
    if val in FALSE_POSITIVE_EXACT_IPS:
        return False
    if any(val.startswith(prefix) for prefix in FALSE_POSITIVE_IP_PREFIXES):
        return False
    try:
        ip = ipaddress.IPv4Address(val)
    except ipaddress.AddressValueError:
        return False

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    octets = [int(x) for x in val.split(".")]
    # Reject typical 4-part version numbers like 5.15.2.0 or 4.1.2.0 ending in .0
    if octets[3] == 0 or (octets[0] <= 6 and octets[2] <= 10 and octets[3] <= 10):
        return False
    return True


def is_benign_or_sandbox_url(url: str) -> bool:
    """Return True if a URL belongs to sandbox instrumentation, runtime docstrings, or benign schemas."""
    low = url.strip().lower()
    if len(low) < 10:
        return True
    return any(sub in low for sub in FALSE_POSITIVE_URL_SUBSTRINGS)


def is_valid_ftp_indicator(entry: str) -> bool:
    """Return True only if an FTP indicator is genuine and not a runtime/Unicode table false positive."""
    clean = entry.strip()
    if not clean or clean.upper() in FALSE_POSITIVE_FTP_STRINGS:
        return False
    if "ftp.unicode.org" in clean.lower():
        return False
    if clean.upper().startswith(("USER API", "USER INTERACTION", "USER DOMAIN", "USER TOKEN")):
        return False
    return True
