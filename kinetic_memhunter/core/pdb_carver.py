"""Kinetic In-Memory PDB Debug Path Carver for Process Memory Dumps."""

from __future__ import annotations

import re
import struct
import uuid
from typing import Iterator
from ..models import PDBFinding

SYSTEM_PDB_NAMES = {
    "ntdll.pdb",
    "kernel32.pdb",
    "kernelbase.pdb",
    "wow64cpu.pdb",
    "wow64.pdb",
    "wow64win.pdb",
    "user32.pdb",
    "gdi32.pdb",
    "advapi32.pdb",
    "shell32.pdb",
    "msvcrt.pdb",
    "ucrtbase.pdb",
    "combase.pdb",
    "rpcrt4.pdb",
    "ole32.pdb",
    "oleaut32.pdb",
}


class PDBCarver:
    """Scans and carves CodeView RSDS/NB10 debug headers and PDB paths from memory."""

    def __init__(self):
        # CodeView RSDS signature: "RSDS" + GUID (16) + Age (4) + Path (null-terminated)
        self._rsds_pattern = re.compile(
            rb"RSDS(?P<guid>.{16})(?P<age>.{4})(?P<path>[^\x00\r\n\t]{3,260}\.pdb)\x00",
            re.IGNORECASE | re.DOTALL,
        )

        # Standard Windows absolute PDB file path pattern
        self._path_pattern = re.compile(
            rb"[a-zA-Z]:\\[^:\*\?\"\<\>\|\r\n\t\x00]{2,260}\.pdb",
            re.IGNORECASE,
        )

    def scan(self, buffer: bytes) -> list[PDBFinding]:
        """Scans buffer and returns carved PDB findings."""
        findings: list[PDBFinding] = []
        seen_paths: set[str] = set()

        # 1. Structured CodeView RSDS Headers
        for match in self._rsds_pattern.finditer(buffer):
            raw_path = match.group("path")
            try:
                pdb_path = raw_path.decode("latin1").strip()
            except Exception:
                continue

            if pdb_path.lower() in seen_paths:
                continue

            raw_guid = match.group("guid")
            raw_age = match.group("age")

            guid_str = None
            try:
                # Win32 GUID byte layout: Data1 (LE), Data2 (LE), Data3 (LE), Data4 (BE)
                p1, p2, p3 = struct.unpack("<IHH", raw_guid[:8])
                p4 = raw_guid[8:16]
                guid_obj = uuid.UUID(
                    fields=(p1, p2, p3, p4[0], p4[1], int.from_bytes(p4[2:], "big"))
                )
                guid_str = str(guid_obj)
            except Exception:
                guid_str = raw_guid.hex()

            age_val = None
            try:
                age_val = struct.unpack("<I", raw_age)[0]
            except Exception:
                pass

            seen_paths.add(pdb_path.lower())
            findings.append(
                PDBFinding(
                    pdb_path=pdb_path,
                    offset=match.start(),
                    guid=guid_str,
                    age=age_val,
                    project_name=self._extract_project_name(pdb_path),
                )
            )

        # 2. Raw File Path Fallback Scan
        for match in self._path_pattern.finditer(buffer):
            try:
                pdb_path = match.group(0).decode("latin1").strip()
            except Exception:
                continue

            if pdb_path.lower() in seen_paths:
                continue

            seen_paths.add(pdb_path.lower())
            findings.append(
                PDBFinding(
                    pdb_path=pdb_path,
                    offset=match.start(),
                    guid=None,
                    age=None,
                    project_name=self._extract_project_name(pdb_path),
                )
            )

        # Sort findings: Put non-system (malware/custom) PDBs first
        findings.sort(key=lambda x: (self._is_system_pdb(x.pdb_path), x.offset))
        return findings

    def _extract_project_name(self, pdb_path: str) -> str | None:
        parts = pdb_path.replace("/", "\\").split("\\")
        if len(parts) >= 2:
            return parts[-1].replace(".pdb", "")
        return None

    def _is_system_pdb(self, pdb_path: str) -> bool:
        filename = pdb_path.replace("/", "\\").split("\\")[-1].lower()
        return filename in SYSTEM_PDB_NAMES
