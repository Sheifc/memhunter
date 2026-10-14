"""Kinetic API Hashing and Shellcode Resolver Detector."""

from __future__ import annotations

import re
import struct
from typing import Any
from ..models import APIHashingFinding

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class APIHashingDetector:
    """Scans and analyzes API hashing resolver routines and hash lookup tables in memory."""

    def __init__(self):
        # Call $+5 followed by pop reg (e8 00 00 00 00 58-5f)
        self._call_pop_pattern = re.compile(rb"\xe8\x00\x00\x00\x00[\x58-\x5f]")

        # ROR13 byte pattern: ror <reg32>, 13 -> c1 c8-cf 0d
        self._ror13_pattern = re.compile(rb"\xc1[\xc8-\xcf]\x0d")

        if HAS_CAPSTONE:
            self._cs_x86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            self._cs_x86 = None

    def scan(self, buffer: bytes) -> list[APIHashingFinding]:
        """Scans buffer for API hashing resolvers and tables."""
        findings: list[APIHashingFinding] = []
        buf_len = len(buffer)
        if buf_len < 32:
            return findings

        seen_offsets: set[int] = set()

        # 1. Detect Call $+5 / Pop EIP Delta Sequences (Position-Independent Resolvers)
        for match in self._call_pop_pattern.finditer(buffer):
            offset = match.start()
            # Avoid closely clustered matches
            if any(abs(offset - prev) < 64 for prev in seen_offsets):
                continue

            chunk = buffer[offset : min(offset + 64, buf_len)]
            hex_dump = chunk.hex()
            disasm = self._disassemble_snippet(chunk, offset)
            hashes = self._extract_candidate_hashes(chunk)

            seen_offsets.add(offset)
            findings.append(
                APIHashingFinding(
                    offset=offset,
                    pattern_type="CALL_POP_DELTA",
                    disassembly_snippet=disasm,
                    hex_dump=hex_dump,
                    hashes_detected=hashes,
                )
            )

        # 2. Detect Explicit ROR13 Hash Algorithms
        for match in self._ror13_pattern.finditer(buffer):
            offset = match.start()
            if any(abs(offset - prev) < 64 for prev in seen_offsets):
                continue

            start_ctx = max(0, offset - 16)
            end_ctx = min(buf_len, offset + 48)
            chunk = buffer[start_ctx:end_ctx]
            hex_dump = chunk.hex()
            disasm = self._disassemble_snippet(chunk, start_ctx)
            hashes = self._extract_candidate_hashes(chunk)

            seen_offsets.add(offset)
            findings.append(
                APIHashingFinding(
                    offset=offset,
                    pattern_type="ROR13_RESOLVER",
                    disassembly_snippet=disasm,
                    hex_dump=hex_dump,
                    hashes_detected=hashes,
                )
            )

        return findings

    def _disassemble_snippet(self, chunk: bytes, base_addr: int) -> str:
        """Disassembles binary chunk into readable instructions using Capstone."""
        if not self._cs_x86:
            return chunk.hex()

        lines: list[str] = []
        try:
            for insn in self._cs_x86.disasm(chunk, base_addr):
                lines.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
        except Exception:
            return chunk.hex()

        return "; ".join(lines[:8]) if lines else chunk.hex()

    def _extract_candidate_hashes(self, chunk: bytes) -> list[str]:
        """Finds 32-bit constants loaded via mov or cmp instructions."""
        hashes: list[str] = []
        for i in range(len(chunk) - 4):
            # mov reg, imm32 (b8-bf) or cmp reg, imm32 (81 f8-ff)
            b = chunk[i]
            if 0xB8 <= b <= 0xBF and i + 5 <= len(chunk):
                val = struct.unpack("<I", chunk[i + 1 : i + 5])[0]
                if 0x10000000 <= val <= 0xFFFFFFFF and val != 0xFFFFFFFF:
                    h_str = f"0x{val:08x}"
                    if h_str not in hashes:
                        hashes.append(h_str)
        return hashes[:5]
