"""Stealer In-Memory Deobfuscation and Targeted Payload Extraction."""

from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Any
from ..models import CredentialCategory, StealerCredentialFinding

B64_PATTERN = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
URL_PATTERN = re.compile(rb"https?://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[^\s\"'<>]*)?")
ONION_PATTERN = re.compile(rb"[a-z2-7]{16,56}\.onion")
TELEGRAM_BOT_PATTERN = re.compile(rb"[0-9]{8,10}:[a-zA-Z0-9_-]{35}")
DISCORD_WEBHOOK_PATTERN = re.compile(rb"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+")

BROWSER_DATA_PATTERNS = [
    (b"AppData\\Local\\Google\\Chrome\\User Data", "Google Chrome Profile"),
    (b"AppData\\Roaming\\Mozilla\\Firefox\\Profiles", "Mozilla Firefox Profile"),
    (b"AppData\\Local\\Microsoft\\Edge\\User Data", "Microsoft Edge Profile"),
    (b"AppData\\Local\\BraveSoftware\\Brave-Browser", "Brave Browser Profile"),
    (b"AppData\\Local\\Yandex\\YandexBrowser", "Yandex Browser Profile"),
    (b"CREATE TABLE moz_cookies", "Firefox Cookie Database"),
    (b"CREATE TABLE logins", "Chromium Login Data Database"),
    (b"CREATE TABLE autofill", "Chromium Autofill Database"),
    (b"os_crypt\":{\"encrypted_key\":", "Chrome Local State DPAPI Key Blob"),
]


class StealerDeobfuscator:
    """Deobfuscates memory strings, decodes base64 blobs, and hunts stealer targets."""

    def __init__(self, context_keys: list[str] | None = None):
        self.context_keys = [k.encode("utf-8") for k in (context_keys or []) if k]

    def deobfuscate(self, buffer: bytes) -> dict[str, Any]:
        """Runs multi-pass deobfuscation and extraction over raw memory buffer."""
        buf_len = len(buffer)
        findings: dict[str, Any] = {
            "decoded_base64_payloads": [],
            "c2_urls": [],
            "telegram_bots": [],
            "discord_webhooks": [],
            "browser_profiles_targeted": [],
            "xor_decrypted_strings": [],
            "extracted_credentials": [],
        }

        # 1. Hunt Base64 Encoded In-Memory Blobs
        seen_b64: set[str] = set()
        for m in B64_PATTERN.finditer(buffer):
            raw_b64 = m.group(0)
            if len(raw_b64) < 24:
                continue
            rem = len(raw_b64) % 4
            if rem and not raw_b64.endswith(b"="):
                raw_b64 = raw_b64[:-rem]
            if len(raw_b64) < 24:
                continue
            try:
                decoded = base64.b64decode(raw_b64)
                # Check if decoded payload contains meaningful indicators
                if (
                    b"http" in decoded
                    or b"{" in decoded
                    or b"MZ" in decoded[:4]
                    or b"PK" in decoded[:4]
                    or b"SELECT" in decoded.upper()
                ):
                    b64_str = raw_b64.decode("latin1")
                    if b64_str not in seen_b64:
                        seen_b64.add(b64_str)
                        findings["decoded_base64_payloads"].append({
                            "offset": m.start(),
                            "encoded_sample": b64_str[:40] + ("..." if len(b64_str) > 40 else ""),
                            "decoded_preview": decoded[:120].decode("latin1", errors="replace"),
                            "size_bytes": len(decoded),
                        })
            except Exception:
                pass

        # 2. Hunt Network C2 Endpoints in Plain / Deobfuscated Memory
        seen_urls: set[str] = set()
        for m in URL_PATTERN.finditer(buffer):
            raw_url = m.group(0).decode("latin1", errors="ignore")
            # Strip nulls, non-printable chars, and trailing punctuation
            clean_url = re.split(r"[\x00-\x1f\x7f-\xff\s\"'<>{}\\]", raw_url)[0].rstrip(".,;:")
            if len(clean_url) < 11:
                continue
            # Ensure host contains a dot or valid IP/domain
            try:
                parsed = urllib.parse.urlparse(clean_url)
                netloc = parsed.netloc.split(":")[0]
                if not ("." in netloc or netloc == "localhost"):
                    continue
            except Exception:
                continue

            # Filter out generic Microsoft / W3 / schema URLs
            if not any(
                ign in clean_url.lower()
                for ign in ("w3.org", "microsoft.com", "schema.org", "xmlsoap.org", "schemas.microsoft", "go.microsoft")
            ):
                if clean_url not in seen_urls:
                    seen_urls.add(clean_url)
                    findings["c2_urls"].append(clean_url)

        for m in ONION_PATTERN.finditer(buffer):
            raw_onion = m.group(0).decode("latin1", errors="ignore")
            clean_onion = re.split(r"[\x00-\x1f\x7f-\xff\s\"'<>]", raw_onion)[0]
            onion_url = f"http://{clean_onion}"
            if onion_url not in seen_urls:
                seen_urls.add(onion_url)
                findings["c2_urls"].append(onion_url)

        # 3. Hunt Exfiltration Exits (Telegram Bots & Discord Webhooks)
        for m in TELEGRAM_BOT_PATTERN.finditer(buffer):
            bot_token = m.group(0).decode("latin1", errors="ignore")
            findings["telegram_bots"].append(bot_token[:12] + "..." + bot_token[-6:])
            findings["extracted_credentials"].append(
                StealerCredentialFinding(
                    category=CredentialCategory.TELEGRAM_SESSION,
                    platform="Telegram Exfiltration Bot Token",
                    match_value=bot_token[:12] + "..." + bot_token[-6:],
                    offset=m.start(),
                    context_snippet=f"Telegram bot token found at offset 0x{m.start():X}",
                )
            )

        for m in DISCORD_WEBHOOK_PATTERN.finditer(buffer):
            hook = m.group(0).decode("latin1", errors="ignore")
            findings["discord_webhooks"].append(hook)
            findings["extracted_credentials"].append(
                StealerCredentialFinding(
                    category=CredentialCategory.CLOUD_CREDENTIAL,
                    platform="Discord Exfiltration Webhook",
                    match_value=hook[:45] + "...",
                    offset=m.start(),
                    context_snippet=f"Discord webhook found at offset 0x{m.start():X}",
                )
            )

        # 4. Browser Profiles & Credential Target Reconnaissance
        seen_targets: set[str] = set()
        for marker, desc in BROWSER_DATA_PATTERNS:
            idx = buffer.find(marker)
            if idx != -1:
                target_str = f"{desc} (offset: 0x{idx:X})"
                if target_str not in seen_targets:
                    seen_targets.add(target_str)
                    findings["browser_profiles_targeted"].append(target_str)

        # 5. Targeted Multi-byte XOR Decryption using Sample Context Keys
        if self.context_keys:
            for key in self.context_keys:
                if len(key) < 3 or len(key) > 64:
                    continue
                # Search high-entropy regions for candidate XOR ciphertext
                # If key is known, search for XORed string of common stealer keywords
                test_probes = [b"http://", b"https://", b"passwords.txt", b"wallet.dat"]
                for probe in test_probes:
                    xored_probe = bytes(b ^ key[i % len(key)] for i, b in enumerate(probe))
                    found_idx = buffer.find(xored_probe)
                    if found_idx != -1:
                        # Decrypt surrounding 512 bytes
                        dec_slice = buffer[found_idx : min(buf_len, found_idx + 512)]
                        dec_plain = bytes(b ^ key[(found_idx + i) % len(key)] for i, b in enumerate(dec_slice))
                        findings["xor_decrypted_strings"].append({
                            "key": key.decode("latin1", errors="replace"),
                            "offset": found_idx,
                            "decrypted_preview": dec_plain[:100].decode("latin1", errors="replace"),
                        })

        return findings
