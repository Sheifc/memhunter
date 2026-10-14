"""Kinetic Cryptographic S-Box and Primitive Detector for Process Memory Dumps."""

from __future__ import annotations

import math
import struct
from typing import Any
from ..models import CryptoPrimitiveFinding, PrimitiveType

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

AES_FORWARD_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])

AES_INVERSE_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
])

CHACHA20_CONSTANTS = [
    (b"expand 32-byte k", PrimitiveType.CHACHA20_CONSTANT),
    (b"expand 16-byte k", PrimitiveType.SALSA20_CONSTANT),
]

# Cryptographic initialization vectors and constants
MD5_INIT_BYTES = struct.pack("<4I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
SHA1_INIT_BYTES = struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
SHA256_INIT_BYTES = struct.pack(
    ">8I", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
)
CRC32_TABLE_START = struct.pack("<4I", 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)

STATIC_CRYPTO_PATTERNS = [
    (MD5_INIT_BYTES, PrimitiveType.MD5_INIT_CONSTANTS, "MD5 Initial State Constants"),
    (SHA1_INIT_BYTES, PrimitiveType.SHA1_INIT_CONSTANTS, "SHA-1 Initial State Constants"),
    (SHA256_INIT_BYTES, PrimitiveType.SHA256_INIT_CONSTANTS, "SHA-256 Initial State Constants"),
    (CRC32_TABLE_START, PrimitiveType.CRC32_TABLE, "CRC32 Standard Polynomial Table"),
]

RC4_IDENTITY_STATE = bytes(range(256))
EXPECTED_PERMUTATION_SUM = 32640  # sum(0..255)


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte buffer."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_arithmetic_ramp(seq: bytes) -> bool:
    """Detects whether a 256-byte sequence is merely a shifted arithmetic ramp (0..255)."""
    if len(seq) != 256:
        return False
    # Check if consecutive steps are predominantly +1 mod 256
    consecutive_steps = sum(1 for i in range(255) if seq[i + 1] == (seq[i] + 1) % 256)
    if consecutive_steps > 8:
        return True
    # Check reverse ramp
    reverse_steps = sum(1 for i in range(255) if seq[i + 1] == (seq[i] - 1) % 256)
    if reverse_steps > 8:
        return True
    return False


class SBoxDetector:
    """Detector for active cryptographic tables, S-boxes, and cipher states."""

    def __init__(self, check_rc4: bool = True, check_aes: bool = True, check_stream: bool = True):
        self.check_rc4 = check_rc4
        self.check_aes = check_aes
        self.check_stream = check_stream

    def scan(self, buffer: bytes) -> list[CryptoPrimitiveFinding]:
        """Scans buffer for all supported cryptographic primitives."""
        findings: list[CryptoPrimitiveFinding] = []
        buf_len = len(buffer)
        if buf_len < 16:
            return findings

        # 1. Constant String Searches (ChaCha20 / Salsa20)
        if self.check_stream:
            for const_str, prim_type in CHACHA20_CONSTANTS:
                start = 0
                while True:
                    idx = buffer.find(const_str, start)
                    if idx == -1:
                        break
                    findings.append(
                        CryptoPrimitiveFinding(
                            primitive=prim_type,
                            offset=idx,
                            size=len(const_str),
                            confidence="confirmed",
                            entropy=calculate_entropy(const_str),
                            hex_preview=const_str.hex(),
                            metadata={"constant": const_str.decode("latin1", errors="replace")},
                        )
                    )
                    start = idx + len(const_str)

        # 2. Hash and Polynomial Table Searches
        for pattern_bytes, prim_type, desc in STATIC_CRYPTO_PATTERNS:
            start = 0
            while True:
                idx = buffer.find(pattern_bytes, start)
                if idx == -1:
                    break
                findings.append(
                    CryptoPrimitiveFinding(
                        primitive=prim_type,
                        offset=idx,
                        size=len(pattern_bytes),
                        confidence="confirmed",
                        entropy=calculate_entropy(pattern_bytes),
                        hex_preview=pattern_bytes.hex(),
                        metadata={"description": desc},
                    )
                )
                start = idx + len(pattern_bytes)

        # 3. AES Tables Search
        if self.check_aes and buf_len >= 256:
            for sbox_bytes, ptype in [
                (AES_FORWARD_SBOX, PrimitiveType.AES_FORWARD_SBOX),
                (AES_INVERSE_SBOX, PrimitiveType.AES_INVERSE_SBOX),
            ]:
                start = 0
                while True:
                    idx = buffer.find(sbox_bytes, start)
                    if idx == -1:
                        break
                    findings.append(
                        CryptoPrimitiveFinding(
                            primitive=ptype,
                            offset=idx,
                            size=256,
                            confidence="confirmed",
                            entropy=8.0,
                            hex_preview=sbox_bytes[:32].hex() + "...",
                            metadata={"type": ptype.value},
                        )
                    )
                    start = idx + 256

        # 4. Kinetic RC4 KSA S-Box Permutation Discovery
        if self.check_rc4 and buf_len >= 256:
            candidate_offsets: list[int] = []

            if HAS_NUMPY:
                # Fast numpy prefix-sum implementation
                arr = np.frombuffer(buffer, dtype=np.uint8)
                csum = np.pad(np.cumsum(arr, dtype=np.int64), (1, 0))
                win_sum = csum[256:] - csum[:-256]
                candidate_offsets = list(np.where(win_sum == EXPECTED_PERMUTATION_SUM)[0])
            else:
                window_sum = sum(buffer[:256])
                stride_limit = buf_len - 256
                for offset in range(stride_limit + 1):
                    if offset > 0:
                        window_sum += buffer[offset + 255] - buffer[offset - 1]
                    if window_sum == EXPECTED_PERMUTATION_SUM:
                        candidate_offsets.append(offset)

            for offset in candidate_offsets:
                candidate = buffer[offset : offset + 256]
                if candidate == RC4_IDENTITY_STATE:
                    continue
                # Eliminate simple shifted arithmetic ramps (false positives)
                if is_arithmetic_ramp(candidate):
                    continue
                if len(set(candidate)) == 256:
                    ent = calculate_entropy(candidate)
                    if ent >= 7.8:
                        findings.append(
                            CryptoPrimitiveFinding(
                                primitive=PrimitiveType.RC4_KSA_SBOX,
                                offset=offset,
                                size=256,
                                confidence="confirmed",
                                entropy=ent,
                                hex_preview=candidate[:32].hex() + "...",
                                metadata={"permutation_sum": 32640, "unique_bytes": 256},
                            )
                        )

        return findings
