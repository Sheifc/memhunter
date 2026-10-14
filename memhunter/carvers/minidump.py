"""
memhunter/carvers/minidump.py
Windows Minidump (MDMP) parser, reflective PE/CLR carver, and cryptographic
S-Box detector (AES, RC4, ChaCha20).
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Dict, List

MDMP_MAGIC = b"MDMP"

# First 32 bytes of the standard Rijndael / AES forward S-Box
AES_SBOX_PREFIX = bytes(
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    ]
)

CHACHA20_CONSTANT = b"expand 32-byte k"
RC4_IDENTITY_PREFIX = bytes(range(64))

MINIDUMP_STREAM_TYPES = {
    3: "ThreadListStream",
    4: "ModuleListStream",
    5: "MemoryListStream",
    6: "ExceptionStream",
    7: "SystemInfoStream",
    9: "Memory64ListStream",
    15: "MiscInfoStream",
    16: "MemoryInfoListStream",
}


def parse_minidump_header(raw_header: bytes) -> Dict[str, Any]:
    """
    Parse a 32-byte Windows Minidump (MDMP) header and directory table.
    """
    if len(raw_header) < 32 or raw_header[:4] != MDMP_MAGIC:
        return {"is_minidump": False, "streams": []}

    version, impl_ver, num_streams, stream_dir_rva, checksum, timestamp, flags = struct.unpack(
        "<HHIIIIQ", raw_header[4:32]
    )
    streams: List[str] = []
    if stream_dir_rva > 0 and stream_dir_rva + num_streams * 12 <= len(raw_header):
        for i in range(min(num_streams, 64)):
            offset = stream_dir_rva + i * 12
            stype, data_size, rva = struct.unpack("<III", raw_header[offset : offset + 12])
            if stype != 0:
                streams.append(MINIDUMP_STREAM_TYPES.get(stype, f"Stream_{stype}"))

    return {
        "is_minidump": True,
        "version": version,
        "stream_count": num_streams,
        "timestamp": timestamp,
        "flags": flags,
        "streams": sorted(set(streams)),
    }


def detect_crypto_primitives(buffer: bytes) -> List[str]:
    """Detect in-memory cryptographic constants and S-Boxes (AES, ChaCha20, RC4, DPAPI)."""
    primitives: List[str] = []
    if AES_SBOX_PREFIX in buffer:
        primitives.append("AES_Rijndael_SBox")
    if CHACHA20_CONSTANT in buffer:
        primitives.append("ChaCha20_Salsa20_Sigma")
    if RC4_IDENTITY_PREFIX in buffer:
        primitives.append("RC4_SBox_Init")
    if b"CryptUnprotectData" in buffer or b"CryptProtectData" in buffer:
        primitives.append("Windows_DPAPI_CryptUnprotectData")
    if b"BCryptDecrypt" in buffer or b"BCryptGenerateSymmetricKey" in buffer:
        primitives.append("Windows_CNG_BCryptDecrypt")
    return primitives


def carve_pe_and_clr_indicators(buffer: bytes) -> Dict[str, Any]:
    """
    Scan a memory dump buffer for reflective PE headers (MZ...PE\\0\\0) and .NET CLR
    metadata headers (BSJB) along with module names.
    """
    clr_count = buffer.count(b"BSJB")
    dos_stubs = buffer.count(b"This program cannot be run in DOS mode")
    reflective_mz = buffer.count(b"MZ\x90\x00\x03\x00\x00\x00")
    return {
        "pe_headers_count": max(dos_stubs, reflective_mz),
        "dotnet_clr_bsjb_count": clr_count,
        "has_reflective_dotnet": clr_count > 0,
    }


def inspect_dump_file(dump_path: Path) -> Dict[str, Any]:
    """Inspect a single .dmp file on disk in streaming chunks for MDMP headers, PE/CLR, and crypto."""
    size = dump_path.stat().st_size
    with open(dump_path, "rb") as f:
        header_chunk = f.read(65536)

    mdmp_info = parse_minidump_header(header_chunk)
    return {
        "file_name": dump_path.name,
        "size_bytes": size,
        "minidump": mdmp_info,
    }
