"""In-memory Portable Executable (PE) Carver and Reflective Loader Detector."""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from typing import Any
from ..models import CarvedPEFinding, PESectionInfo
from .sbox_detector import calculate_entropy

SUSPICIOUS_STEALER_APIS = {
    b"CryptUnprotectData": "DPAPI Password Decryption",
    b"InternetOpenA": "WinINet C2 Exfiltration",
    b"InternetOpenW": "WinINet C2 Exfiltration",
    b"HttpSendRequestA": "HTTP C2 Exfiltration",
    b"HttpSendRequestW": "HTTP C2 Exfiltration",
    b"URLDownloadToFileA": "Payload Staging / Dropper",
    b"GetClipboardData": "Clipboard Stealing",
    b"sqlite3_open": "Browser SQLite Cookie/History Theft",
    b"sqlite3_step": "Browser SQLite Query Execution",
    b"RegOpenKeyExA": "Credential Registry Harvesting",
    b"CreateToolhelp32Snapshot": "Process Enumeration / Injection",
    b"VirtualAllocEx": "Process Injection / Memory Allocation",
    b"WriteProcessMemory": "Process Hollowing / In-Flight Injection",
}


class PECarver:
    """Carves executable PE binaries (DLLs, EXEs) from unmapped or virtual memory dumps."""

    def __init__(self, min_size: int = 1024):
        self.min_size = min_size

    def scan(self, buffer: bytes) -> list[CarvedPEFinding]:
        findings: list[CarvedPEFinding] = []
        buf_len = len(buffer)
        if buf_len < 512:
            return findings

        start = 0
        while True:
            # Look for MZ header
            idx = buffer.find(b"MZ", start)
            if idx == -1 or idx + 64 > buf_len:
                break

            start = idx + 2
            # Read e_lfanew at offset 0x3C
            try:
                e_lfanew = struct.unpack_from("<I", buffer, idx + 0x3C)[0]
            except Exception:
                continue

            if e_lfanew < 0x40 or idx + e_lfanew + 24 > buf_len:
                continue

            # Verify PE signature
            pe_sig = buffer[idx + e_lfanew : idx + e_lfanew + 4]
            if pe_sig != b"PE\x00\x00":
                continue

            # Parse COFF Header
            coff_offset = idx + e_lfanew + 4
            machine, num_sections, timedatestamp = struct.unpack_from("<HHI", buffer, coff_offset)

            is_64bit = machine == 0x8664
            machine_name = "x64" if is_64bit else ("x86" if machine == 0x014C else f"0x{machine:04x}")
            try:
                compile_time = datetime.fromtimestamp(timedatestamp, tz=timezone.utc)
            except Exception:
                compile_time = None

            size_of_optional_header = struct.unpack_from("<H", buffer, coff_offset + 16)[0]
            optional_offset = coff_offset + 20

            entry_point = 0
            image_size = 0
            if size_of_optional_header >= 28 and optional_offset + size_of_optional_header <= buf_len:
                entry_point = struct.unpack_from("<I", buffer, optional_offset + 16)[0]
                if is_64bit and size_of_optional_header >= 56:
                    image_size = struct.unpack_from("<I", buffer, optional_offset + 56)[0]
                elif not is_64bit and size_of_optional_header >= 56:
                    image_size = struct.unpack_from("<I", buffer, optional_offset + 56)[0]

            # Parse Sections
            sections_start = optional_offset + size_of_optional_header
            sections: list[PESectionInfo] = []
            max_virtual_extent = 0
            max_raw_extent = 0

            for sec_idx in range(min(num_sections, 32)):
                sec_off = sections_start + (sec_idx * 40)
                if sec_off + 40 > buf_len:
                    break

                sec_name = buffer[sec_off : sec_off + 8].split(b"\x00")[0].decode("latin1", errors="replace")
                vsize, va, rsize, rptr = struct.unpack_from("<IIII", buffer, sec_off + 8)
                chars = struct.unpack_from("<I", buffer, sec_off + 36)[0]

                if va + vsize > max_virtual_extent:
                    max_virtual_extent = va + vsize
                if rptr + rsize > max_raw_extent:
                    max_raw_extent = rptr + rsize

                # Calculate section entropy
                sec_data_start = idx + va if (idx + va + rsize <= buf_len) else (idx + rptr)
                sec_data_end = sec_data_start + min(rsize, 4096)
                sec_entropy = calculate_entropy(buffer[sec_data_start:sec_data_end]) if sec_data_start < buf_len else 0.0

                sections.append(
                    PESectionInfo(
                        name=sec_name,
                        virtual_address=va,
                        virtual_size=vsize,
                        raw_size=rsize,
                        entropy=sec_entropy,
                        characteristics=chars,
                    )
                )

            total_carved_len = max(max_raw_extent, max_virtual_extent, image_size, 4096)
            carved_end = min(idx + total_carved_len, buf_len)
            carved_bytes = buffer[idx:carved_end]

            if len(carved_bytes) < self.min_size:
                continue

            # Scan for Stealer APIs in the carved image
            suspicious_found = []
            for api_str, desc in SUSPICIOUS_STEALER_APIS.items():
                if api_str in carved_bytes:
                    suspicious_found.append(f"{api_str.decode('latin1')} ({desc})")

            # Detect reflective / in-memory unpacked image
            is_reflective = max_virtual_extent > max_raw_extent and num_sections > 0

            pe_hash = hashlib.sha256(carved_bytes).hexdigest()
            findings.append(
                CarvedPEFinding(
                    offset=idx,
                    size=len(carved_bytes),
                    is_64bit=is_64bit,
                    machine_type=machine_name,
                    compile_time=compile_time,
                    entry_point=entry_point,
                    sections=sections,
                    suspicious_imports=suspicious_found,
                    sha256=pe_hash,
                    is_reflective_injection=is_reflective,
                )
            )

        return findings
