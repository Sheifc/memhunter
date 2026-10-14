"""Kinetic Crypto Solver: reconstructs keys and decrypts in-flight memory payloads."""

from __future__ import annotations

import re
from typing import Any
from ..models import CryptoPrimitiveFinding, DecryptedRegionFinding, PrimitiveType
from .sbox_detector import calculate_entropy

KNOWN_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "Executable PE Binary"),
    (b"PK\x03\x04", "ZIP Archive"),
    (b"\x1f\x8b\x08", "GZIP Stream"),
    (b"SQLite format 3\x00", "SQLite Database"),
    (b"{\"settings\":", "JSON Configuration"),
    (b"{\"bot_id\":", "Botnet JSON Configuration"),
    (b"POST /", "HTTP POST Exfiltration Request"),
    (b"HTTP/1.1", "HTTP C2 Response"),
]


def rc4_crypt_prefix(key: bytes, data: bytes, max_bytes: int = 32) -> bytes:
    """Fast RC4 decrypts only the first max_bytes for signature checking."""
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) % 256
        s[i], s[j] = s[j], s[i]

    i = j = 0
    limit = min(len(data), max_bytes)
    out = bytearray(limit)
    for idx in range(limit):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[idx] = data[idx] ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Pure Python RC4 stream cipher execution."""
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) % 256
        s[i], s[j] = s[j], s[i]

    i = j = 0
    out = bytearray(len(data))
    for idx, b in enumerate(data):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[idx] = b ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


class CryptoSolver:
    """Discovers keys adjacent to cryptographic primitives and solves encrypted memory chunks."""

    def __init__(self, key_search_radius: int = 4096, max_decrypt_size: int = 65536):
        self.key_search_radius = key_search_radius
        self.max_decrypt_size = max_decrypt_size

    def solve(self, buffer: bytes, primitives: list[CryptoPrimitiveFinding]) -> list[DecryptedRegionFinding]:
        findings: list[DecryptedRegionFinding] = []
        buf_len = len(buffer)
        if buf_len < 64:
            return findings

        # Target RC4 S-Boxes
        rc4_primitives = [p for p in primitives if p.primitive == PrimitiveType.RC4_KSA_SBOX]
        if not rc4_primitives:
            return findings

        for prim in rc4_primitives[:4]:
            sbox_offset = prim.offset
            # Look for candidate keys in heap window around S-Box
            win_start = max(0, sbox_offset - self.key_search_radius)
            win_end = min(buf_len, sbox_offset + prim.size + self.key_search_radius)
            search_window = buffer[win_start:win_end]

            # Extract printable ASCII candidate keys (length 8 to 32)
            key_candidates: list[bytes] = []
            for m in re.finditer(rb"[A-Za-z0-9_\-\.!@#\$%^&\*]{8,32}", search_window):
                cand = m.group(0)
                if cand not in key_candidates:
                    key_candidates.append(cand)
                if len(key_candidates) >= 15:
                    break

            if not key_candidates:
                continue

            # Look for high entropy blocks nearby that could be ciphertexts
            for chunk_offset in range(win_start, win_end - 512, 512):
                chunk = buffer[chunk_offset : min(buf_len, chunk_offset + 4096)]
                chunk_entropy = calculate_entropy(chunk[:256])

                if chunk_entropy < 7.0:
                    continue

                for cand_key in key_candidates:
                    # Test decrypt only first 32 bytes for magic match
                    prefix = rc4_crypt_prefix(cand_key, chunk, max_bytes=32)
                    matched_desc = None
                    for magic, desc in KNOWN_MAGIC_SIGNATURES:
                        if prefix.startswith(magic):
                            matched_desc = desc
                            break

                    if matched_desc:
                        decrypted = rc4_crypt(cand_key, chunk[: min(len(chunk), self.max_decrypt_size)])
                        entropy_after = calculate_entropy(decrypted[:256])
                        preview = decrypted[:128].decode("latin1", errors="replace").replace("\n", " ")
                        findings.append(
                            DecryptedRegionFinding(
                                cipher="RC4",
                                key_hex=cand_key.hex(),
                                offset=chunk_offset,
                                size=len(decrypted),
                                entropy_before=chunk_entropy,
                                entropy_after=entropy_after,
                                plaintext_preview=f"[{matched_desc}] {preview}",
                            )
                        )
                        break

                if findings:
                    break

        return findings
