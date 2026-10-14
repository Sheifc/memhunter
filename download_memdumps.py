#!/usr/bin/env python3
"""
download_memdumps.py
Standalone, portable CLI utility to enumerate and download VirusTotal / GTI v3
sandbox memory dumps (`memdump` ZIPs).

Why this script is self-contained:
Can be copied to any external machine with Python 3 + `requests` (and optional
`python-dotenv`) to download memory dump ZIPs for a single hash or a file of hashes
without requiring the rest of the `memhunter` package.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

try:
    from dotenv import load_dotenv

    for _p in (Path(__file__).resolve().parent / ".env", Path.cwd() / ".env", Path.home() / ".env"):
        if _p.is_file():
            load_dotenv(_p)
            break
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("download_memdumps")

DEFAULT_BASE_URL = os.getenv("GTI_BASE_URL", "https://www.virustotal.com/api/v3").rstrip("/")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def get_headers(api_key: str) -> Dict[str, str]:
    if not api_key:
        raise ValueError("GTI_KEY or VT_API_KEY is required.")
    if api_key.startswith("ya29."):
        return {"Authorization": f"Bearer {api_key}", "User-Agent": "MemHunter-Downloader/1.0"}
    return {"x-apikey": api_key, "User-Agent": "MemHunter-Downloader/1.0"}


def find_memdump_sandboxes(sha256: str, api_key: str, base_url: str = DEFAULT_BASE_URL) -> List[Dict[str, Any]]:
    url = f"{base_url}/files/{sha256.lower()}/behaviours"
    resp = requests.get(url, headers=get_headers(api_key), timeout=30)
    if resp.status_code != 200:
        return []
    out: List[Dict[str, Any]] = []
    for item in resp.json().get("data", []):
        attrs = item.get("attributes") or {}
        if attrs.get("has_memdump") is True:
            out.append(
                {
                    "sandbox_id": str(item.get("id") or ""),
                    "sandbox_name": str(attrs.get("sandbox_name") or "unknown"),
                }
            )
    return out


def download_memdump(
    sandbox_id: str,
    output_dir: Path,
    api_key: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: int = 180,
) -> Optional[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = sandbox_id.replace("/", "_").replace(" ", "_")
    target_zip = output_dir / f"{safe_name}.zip"
    encoded_id = quote(sandbox_id, safe="")
    url = f"{base_url}/file_behaviours/{encoded_id}/memdump"

    with requests.get(url, headers=get_headers(api_key), stream=True, timeout=timeout, allow_redirects=True) as resp:
        if resp.status_code != 200:
            logger.warning("HTTP %d downloading memdump for %s", resp.status_code, sandbox_id)
            return None
        with open(target_zip, "wb") as f:
            for chunk in resp.iter_content(chunk_size=262144):
                if chunk:
                    f.write(chunk)

    size_mb = target_zip.stat().st_size / (1024 * 1024)
    logger.info("[✔] Downloaded %s (%.2f MB)", target_zip.name, size_mb)
    return target_zip


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone VirusTotal v3 Memdump Downloader.")
    parser.add_argument(
        "--hash",
        "--sha256",
        dest="hashes",
        action="append",
        default=[],
        help="SHA-256 hash to download memdump for (can be specified multiple times)",
    )
    parser.add_argument("--file", "--hashes-file", dest="file", type=Path, default=None, help="File with SHA-256 hashes (one per line)")
    parser.add_argument("--output-dir", type=Path, default=Path("data/memdumps"), help="Destination directory")
    parser.add_argument("--all-sandboxes", action="store_true", help="Download from all sandboxes (default: first)")
    parser.add_argument("--dry-run", action="store_true", help="Only list available memdumps without downloading")
    args = parser.parse_args(argv)

    api_key = os.getenv("GTI_KEY", "").strip() or os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        logger.error("Missing GTI_KEY or VT_API_KEY environment variable.")
        return 1

    hashes: List[str] = []
    for raw_h in args.hashes or []:
        h = raw_h.strip().lower()
        if SHA256_RE.match(h) and h not in hashes:
            hashes.append(h)
    if args.file and args.file.is_file():
        for line in args.file.read_text(encoding="utf-8").splitlines():
            h = line.strip().lower()
            if SHA256_RE.match(h) and h not in hashes:
                hashes.append(h)

    if not hashes:
        logger.error("Specify --hash <sha256> or --file <path>.")
        return 1

    for sha in hashes:
        sandboxes = find_memdump_sandboxes(sha, api_key=api_key)
        if not sandboxes:
            logger.info("[-] %s: No sandbox with has_memdump=True", sha)
            continue
        for sb in sandboxes if args.all_sandboxes else sandboxes[:1]:
            logger.info("[+] %s: Found memdump in %s (%s)", sha[:12], sb["sandbox_name"], sb["sandbox_id"])
            if not args.dry_run:
                download_memdump(sb["sandbox_id"], args.output_dir, api_key=api_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
