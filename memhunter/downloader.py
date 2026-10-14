"""
memhunter/downloader.py
VirusTotal / GTI v3 behaviour memory dump enumerator and streaming downloader.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from memhunter.config import DEFAULT_BASE_URL, DOWNLOAD_TIMEOUT, SHA256_RE

logger = logging.getLogger("memhunter.downloader")


def get_auth_headers(api_key: str) -> Dict[str, str]:
    """Build VT / GTI request headers supporting x-apikey or Bearer token."""
    if not api_key:
        raise ValueError("GTI_KEY cannot be empty.")
    if api_key.startswith("ya29."):
        return {"Authorization": f"Bearer {api_key}", "User-Agent": "MemHunter/1.0"}
    return {"x-apikey": api_key, "User-Agent": "MemHunter/1.0"}


def list_memdump_behaviours(
    sha256: str,
    api_key: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: int = 30,
) -> List[Dict[str, Any]]:
    """
    Query GET /files/{sha256}/behaviours and return all sandbox reports where
    attributes.has_memdump is True.
    """
    clean_sha = sha256.lower().strip()
    if not SHA256_RE.match(clean_sha):
        raise ValueError(f"Invalid SHA-256 digest: {sha256}")

    url = f"{base_url.rstrip('/')}/files/{clean_sha}/behaviours"
    headers = get_auth_headers(api_key)
    resp = requests.get(url, headers=headers, timeout=timeout)

    if resp.status_code == 404:
        return []
    if resp.status_code != 200:
        raise RuntimeError(f"VT /files/{clean_sha}/behaviours returned HTTP {resp.status_code}: {resp.text[:200]}")

    behaviours = resp.json().get("data", [])
    available: List[Dict[str, Any]] = []
    for item in behaviours:
        attrs = item.get("attributes") or {}
        if attrs.get("has_memdump") is True:
            sandbox_id = str(item.get("id") or "")
            sandbox_name = str(attrs.get("sandbox_name") or sandbox_id.split("_", 1)[-1])
            available.append(
                {
                    "sandbox_id": sandbox_id,
                    "sandbox_name": sandbox_name,
                    "has_pcap": bool(attrs.get("has_pcap")),
                    "analysis_date": attrs.get("analysis_date"),
                    "processes_tree": attrs.get("processes_tree") or [],
                    "mutexes_created": attrs.get("mutexes_created") or [],
                    "command_executions": attrs.get("command_executions") or [],
                }
            )
    return available


def download_behaviour_memdump_zip(
    sandbox_id: str,
    dest_dir: Path,
    api_key: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: int = DOWNLOAD_TIMEOUT,
) -> Optional[Path]:
    """
    Stream GET /file_behaviours/{sandbox_id}/memdump to a temporary .zip file inside dest_dir.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_name = sandbox_id.replace("/", "_").replace(" ", "_")
    zip_path = dest_dir / f"{safe_name}.zip"

    encoded_id = quote(sandbox_id, safe="")
    url = f"{base_url.rstrip('/')}/file_behaviours/{encoded_id}/memdump"
    headers = get_auth_headers(api_key)

    with requests.get(url, headers=headers, stream=True, timeout=timeout, allow_redirects=True) as resp:
        if resp.status_code == 404:
            logger.warning("Memdump not found (404) for sandbox_id=%s", sandbox_id)
            return None
        if resp.status_code != 200:
            raise RuntimeError(f"Failed downloading memdump {sandbox_id} (HTTP {resp.status_code})")

        with open(zip_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=262144):
                if chunk:
                    f.write(chunk)

    if not zip_path.is_file() or zip_path.stat().st_size < 4:
        zip_path.unlink(missing_ok=True)
        return None
    return zip_path
