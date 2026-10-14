"""Kinetic DGA and Custom Encoding Alphabet Detector."""

from __future__ import annotations

import re
from ..models import DGAAlphabetFinding

KNOWN_ALPHABETS = [
    (
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "Base62 / DGA Numeric-First Character Set",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "Standard Base64 Alphabet",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        "URL-Safe Base64 Alphabet",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "Base62 Standard Alphabet",
    ),
    (
        b"abcdefghijklmnopqrstuvwxyz012345",
        "RFC 4648 Base32 Lowercase Alphabet",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        "RFC 4648 Base32 Standard Alphabet",
    ),
    (
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        "Bitcoin Base58 Alphabet",
    ),
    (
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "52-Character Alpha Key Alphabet",
    ),
]


class DGADetector:
    """Scans and extracts custom Base64/DGA alphabets and obfuscated character sets."""

    def __init__(self):
        # Scan for contiguous sequences of 32-64 unique ASCII characters
        self._generic_charset_pattern = re.compile(
            rb"[a-zA-Z0-9_\-\.\$\+\/\@]{32,64}"
        )

    def scan(self, buffer: bytes) -> list[DGAAlphabetFinding]:
        """Detects known and custom DGA/encoding alphabets."""
        findings: list[DGAAlphabetFinding] = []
        seen: set[str] = set()

        # 1. Known Standard & Custom Alphabets
        for alphabet_bytes, desc in KNOWN_ALPHABETS:
            idx = buffer.find(alphabet_bytes)
            if idx != -1:
                alpha_str = alphabet_bytes.decode("latin1")
                if alpha_str not in seen:
                    seen.add(alpha_str)
                    findings.append(
                        DGAAlphabetFinding(
                            alphabet=alpha_str,
                            alphabet_type=desc,
                            offset=idx,
                        )
                    )

        # 2. Heuristic Detection of Permuted 64-char Alphabets
        for match in self._generic_charset_pattern.finditer(buffer):
            raw = match.group(0)
            if len(raw) in (32, 62, 64):
                if len(set(raw)) >= len(raw) - 2:  # High character uniqueness
                    try:
                        alpha_str = raw.decode("latin1")
                    except Exception:
                        continue
                    if alpha_str not in seen:
                        seen.add(alpha_str)
                        findings.append(
                            DGAAlphabetFinding(
                                alphabet=alpha_str,
                                alphabet_type="Custom Permuted Alphabet",
                                offset=match.start(),
                            )
                        )

        return findings
