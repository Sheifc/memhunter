"""Kinetic Persistence and COM CLSID Carver."""

from __future__ import annotations

import re
from ..models import PersistenceFinding

# Well-known benign Windows Shell COM CLSIDs to filter from high-severity persistence
COMMON_BENIGN_CLSIDS = {
    "{00000000-0000-0000-C000-000000000046}",  # IUnknown
    "{00000001-0000-0000-C000-000000000046}",  # IClassFactory
    "{00020400-0000-0000-C000-000000000046}",  # IDispatch
    "{20D04FE0-3AEA-1069-A2D8-08002B30309D}",  # My Computer
    "{450D8FBA-AD25-11D0-98E8-006008551716}",  # My Documents
    "{645FF040-5081-101B-9F08-00AA002F954E}",  # Recycle Bin
}

REGISTRY_PERSISTENCE_PATTERNS = [
    (re.compile(rb"CurrentVersion\\Run\b", re.IGNORECASE), "Registry_Run", "CurrentVersion\\Run"),
    (re.compile(rb"CurrentVersion\\RunOnce\b", re.IGNORECASE), "Registry_RunOnce", "CurrentVersion\\RunOnce"),
    (re.compile(rb"CurrentVersion\\RunServices\b", re.IGNORECASE), "Registry_RunServices", "CurrentVersion\\RunServices"),
    (re.compile(rb"Winlogon\\Userinit\b", re.IGNORECASE), "Registry_Winlogon", "Winlogon\\Userinit"),
    (re.compile(rb"Winlogon\\Shell\b", re.IGNORECASE), "Registry_Winlogon", "Winlogon\\Shell"),
    (re.compile(rb"Image File Execution Options\b", re.IGNORECASE), "Registry_IFEO", "Image File Execution Options"),
    (re.compile(rb"SCRNSAVE\.EXE\b", re.IGNORECASE), "Registry_ScreenSave", "ScreenSaver Persistence (SCRNSAVE.EXE)"),
    (re.compile(rb"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\b", re.IGNORECASE), "Registry_Policy", "Explorer Policy Tampering"),
]


class PersistenceCarver:
    """Scans and carves COM CLSIDs and Registry persistence keys from memory dumps."""

    def __init__(self):
        # COM CLSID regex pattern: {8-4-4-4-12}
        self._clsid_pattern = re.compile(
            rb"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}"
        )

    def scan(self, buffer: bytes) -> list[PersistenceFinding]:
        """Carves CLSIDs and Registry persistence artifacts."""
        findings: list[PersistenceFinding] = []
        seen_clsids: set[str] = set()

        # 1. Carve COM CLSIDs
        for match in self._clsid_pattern.finditer(buffer):
            clsid = match.group(0).decode("latin1").upper()
            if clsid in seen_clsids or clsid in COMMON_BENIGN_CLSIDS:
                continue
            seen_clsids.add(clsid)

            findings.append(
                PersistenceFinding(
                    persistence_type="COM_CLSID",
                    target_value=clsid,
                    offset=match.start(),
                    is_malicious=True,
                )
            )
            if len(seen_clsids) >= 50:
                break

        # 2. Carve Registry Persistence Keys
        for pattern, p_type, name in REGISTRY_PERSISTENCE_PATTERNS:
            match = pattern.search(buffer)
            if match:
                findings.append(
                    PersistenceFinding(
                        persistence_type=p_type,
                        target_value=name,
                        offset=match.start(),
                        is_malicious=True,
                    )
                )

        return findings
