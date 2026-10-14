"""Kinetic In-Memory Mutex Carver for Windows Process Memory Dumps."""

from __future__ import annotations

import re
from typing import Iterator
from ..models import MutexFinding

# Standard system mutexes to filter or classify
KNOWN_BENIGN_MUTEX_PATTERNS = {
    "Local\\SM0",
    "Local\\MSCTF",
    "Local\\ZonesCacheCounterMutex",
    "Local\\ZoneAttributeCacheCounterMutex",
    "Local\\c:!programdata!microsoft!windows defender",
}

MALWARE_FAMILY_MUTEX_SIGNATURES: dict[str, str] = {
    "FzYmEt": "QueenBee / BotGenStudio",
    "yLtBNw": "Lumma Stealer",
    "pptplsa": "QueenBee / BotGenStudio Loader",
    "RedLine": "RedLine Stealer",
    "Vidar": "Vidar Stealer",
    "Stealc": "Stealc",
    "Raccoon": "Raccoon Stealer",
    "AgentTesla": "AgentTesla",
}


class MutexCarver:
    """Scans and carves named Win32 Mutex and Event objects from process memory."""

    def __init__(self, min_name_len: int = 3, max_name_len: int = 80):
        self.min_name_len = min_name_len
        self.max_name_len = max_name_len

        # Regex for ASCII mutexes
        self._ascii_pattern = re.compile(
            rb"(?:Global|Local|BaseNamedObjects|Sessions\\\d+)\\[a-zA-Z0-9_\-\.\$\{\}]{3,80}"
        )

        # Regex for UTF-16LE mutexes
        self._utf16_prefix = re.compile(
            rb"(?:G\x00l\x00o\x00b\x00a\x00l\x00|L\x00o\x00c\x00a\x00l\x00|B\x00a\x00s\x00e\x00N\x00a\x00m\x00e\x00d\x00O\x00b\x00j\x00e\x00c\x00t\x00s\x00)\\\x00"
            rb"(?:[a-zA-Z0-9_\-\.\$\{\}]\x00){3,80}"
        )

    def scan(self, buffer: bytes) -> list[MutexFinding]:
        """Extracts unique mutexes from the memory buffer."""
        findings: list[MutexFinding] = []
        seen: set[str] = set()

        # 1. ASCII Mutex Scan
        for match in self._ascii_pattern.finditer(buffer):
            raw = match.group(0)
            try:
                name = raw.decode("latin1").strip("\x00").strip()
            except Exception:
                continue

            # Strip trailing non-printable or noisy punctuation
            name = re.sub(r"[\r\n\t]+.*$", "", name)
            if len(name) < 5 or name in seen:
                continue

            seen.add(name)
            findings.append(self._create_finding(name, match.start()))

        # 2. UTF-16LE Mutex Scan
        for match in self._utf16_prefix.finditer(buffer):
            raw = match.group(0)
            try:
                name = raw.decode("utf-16le").strip("\x00").strip()
            except Exception:
                continue

            name = re.sub(r"[\r\n\t]+.*$", "", name)
            if len(name) < 5 or name in seen:
                continue

            seen.add(name)
            findings.append(self._create_finding(name, match.start()))

        return findings

    def _create_finding(self, name: str, offset: int) -> MutexFinding:
        scope = "Local"
        if name.startswith("Global\\"):
            scope = "Global"
        elif name.startswith("BaseNamedObjects\\"):
            scope = "BaseNamedObjects"
        elif name.startswith("Sessions\\"):
            scope = "Session"

        associated_family = None
        for pattern, family in MALWARE_FAMILY_MUTEX_SIGNATURES.items():
            if pattern.lower() in name.lower():
                associated_family = family
                break

        is_suspicious = True
        name_lower = name.lower()
        for benign in KNOWN_BENIGN_MUTEX_PATTERNS:
            if benign.lower() in name_lower:
                is_suspicious = False
                break

        return MutexFinding(
            name=name,
            scope=scope,
            offset=offset,
            is_suspicious=is_suspicious,
            associated_family=associated_family,
        )
