"""Kinetic Network, C2, and Exfiltration Endpoint Carver."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from ..models import NetworkC2Finding

DDR_DOMAINS = {
    "github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "steamcommunity.com",
    "t.me",
    "telegram.me",
    "discord.com",
    "pastebin.com",
    "rentry.co",
    "telegra.ph",
    "mastodon.social",
}

BENIGN_DOMAINS = {
    "schemas.microsoft.com",
    "www.w3.org",
    "schemas.xmlsoap.org",
    "crl.microsoft.com",
    "ocsp.digicert.com",
    "cacerts.digicert.com",
    "www.digicert.com",
    "crl.verisign.com",
    "go.microsoft.com",
    "windowsupdate.microsoft.com",
    "ctldl.windowsupdate.com",
    "msdn.microsoft.com",
    "support.microsoft.com",
}


class NetworkC2Carver:
    """Carves IPv4 endpoints, C2 URLs, Dead Drop Resolvers, and FTP channels from memory."""

    def __init__(self):
        # IPv4 pattern with optional port: 199.231.188.109 or 199.231.188.109:21
        self._ip_pattern = re.compile(
            rb"\b[1-9]\d{0,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b"
        )

        # Standard URL pattern
        self._url_pattern = re.compile(
            rb"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{4,300}",
            re.IGNORECASE,
        )

        # FTP URL pattern
        self._ftp_pattern = re.compile(
            rb"ftp://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{4,200}",
            re.IGNORECASE,
        )

        # FTP command sequence in memory (strict boundaries)
        self._ftp_command_pattern = re.compile(
            rb"(?:^|[\r\n\x00])(USER\s+[a-zA-Z0-9_\-\.]{1,32}|PASS\s+[^\r\n\x00]{1,32}|STOR\s+[^\r\n\x00]{1,64}|RETR\s+[^\r\n\x00]{1,64}|227 Entering Passive Mode)",
        )

    def scan(self, buffer: bytes) -> list[NetworkC2Finding]:
        """Carves all network intelligence from process memory."""
        findings: list[NetworkC2Finding] = []
        seen: set[str] = set()

        # 1. FTP URL Scanning
        for match in self._ftp_pattern.finditer(buffer):
            raw = match.group(0).decode("latin1", errors="ignore").strip()
            if raw in seen:
                continue
            seen.add(raw)
            findings.append(
                NetworkC2Finding(
                    endpoint_type="FTP",
                    value=raw,
                    port=21,
                    context="FTP Exfiltration Endpoint",
                )
            )

        # 2. HTTP/HTTPS URLs & Dead Drop Resolvers
        for match in self._url_pattern.finditer(buffer):
            raw = match.group(0).decode("latin1", errors="ignore").rstrip("/.;,)'\"")
            if raw in seen or len(raw) < 10:
                continue

            # Filter benign Microsoft/W3 schema URLs
            is_benign = False
            for bd in BENIGN_DOMAINS:
                if bd in raw.lower():
                    is_benign = True
                    break
            if is_benign:
                continue

            seen.add(raw)

            # Check if Dead Drop Resolver
            is_ddr = any(ddr in raw.lower() for ddr in DDR_DOMAINS)
            endpoint_type = "DDR" if is_ddr else "URL"
            context = "Dead Drop Resolver (DDR)" if is_ddr else "HTTP/HTTPS C2 Endpoint"

            # Check Telegram / Discord specific
            if "api.telegram.org/bot" in raw:
                endpoint_type = "Telegram_Bot"
                context = "Telegram Exfiltration Bot"
            elif "discord.com/api/webhooks" in raw:
                endpoint_type = "Discord_Webhook"
                context = "Discord Exfiltration Webhook"

            findings.append(
                NetworkC2Finding(
                    endpoint_type=endpoint_type,
                    value=raw,
                    context=context,
                )
            )

        # 3. Public IPv4 Scanning
        for match in self._ip_pattern.finditer(buffer):
            raw_match = match.group(0).decode("latin1")
            port = None
            if ":" in raw_match:
                ip_str, port_str = raw_match.split(":")
                try:
                    port = int(port_str)
                except ValueError:
                    port = None
            else:
                ip_str = raw_match

            # Validate IP format and public status
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not ip_obj.is_global or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_loopback:
                    continue
                # Eliminate version-like strings such as 10.0.19041.1
                parts = [int(p) for p in ip_str.split(".")]
                if parts[0] <= 0 or parts[0] >= 224:
                    continue
                # Reject typical fake version numbers
                if parts[2] > 1000 or parts[3] > 1000:
                    continue
            except Exception:
                continue

            if ip_str in seen:
                continue
            seen.add(ip_str)

            context = "Public C2 / Relay IP"
            if port == 21:
                context = "FTP Exfiltration Server"

            findings.append(
                NetworkC2Finding(
                    endpoint_type="IPv4",
                    value=ip_str,
                    port=port,
                    context=context,
                )
            )

        # 4. In-Memory FTP Commands Check
        ftp_cmds = self._ftp_command_pattern.findall(buffer)
        if ftp_cmds and not any(f.endpoint_type == "FTP" for f in findings):
            cmd_samples = [c.decode("latin1", errors="ignore") for c in ftp_cmds[:3]]
            findings.append(
                NetworkC2Finding(
                    endpoint_type="FTP",
                    value=f"FTP Activity Detected: {', '.join(cmd_samples)}",
                    port=21,
                    context="In-Memory FTP Command Stream",
                )
            )

        return findings
