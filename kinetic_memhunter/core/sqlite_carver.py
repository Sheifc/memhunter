"""Kinetic In-Memory SQLite Database Carver and Credential Extractor."""

from __future__ import annotations

import re
import struct
from typing import Any
from ..models import SQLiteCarvedFinding

SQLITE_HEADER = b"SQLite format 3\x00"

TABLE_SCHEMA_PATTERN = re.compile(
    rb"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_`\"\[\]]+)",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    rb"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"
)


class SQLiteCarver:
    """Carves and analyzes in-memory SQLite database fragments copied by stealers."""

    def __init__(self, max_carve_size: int = 10 * 1024 * 1024):
        self.max_carve_size = max_carve_size

    def scan(self, buffer: bytes) -> list[SQLiteCarvedFinding]:
        """Carves SQLite databases and extracts table schemas and stolen credential strings."""
        findings: list[SQLiteCarvedFinding] = []
        buf_len = len(buffer)
        if buf_len < 100:
            return findings

        start_offset = 0
        while True:
            idx = buffer.find(SQLITE_HEADER, start_offset)
            if idx == -1:
                break

            # Read page size at offset +16 (uint16 big-endian)
            page_size = 4096
            if idx + 18 <= buf_len:
                raw_page_size = struct.unpack(">H", buffer[idx + 16 : idx + 18])[0]
                if raw_page_size == 1:
                    page_size = 65536
                elif 512 <= raw_page_size <= 32768:
                    page_size = raw_page_size

            # Estimate database size by inspecting page count at offset +28 (uint32 big-endian)
            page_count = 10
            if idx + 32 <= buf_len:
                raw_pages = struct.unpack(">I", buffer[idx + 28 : idx + 32])[0]
                if 1 <= raw_pages <= 10000:
                    page_count = raw_pages

            db_size = min(page_size * page_count, self.max_carve_size, buf_len - idx)
            db_chunk = buffer[idx : idx + db_size]

            # 1. Carve Table Names
            tables_found: list[str] = []
            for t_match in TABLE_SCHEMA_PATTERN.finditer(db_chunk):
                raw_tbl = t_match.group(1).decode("latin1", errors="ignore").strip("`\"[]")
                if raw_tbl and raw_tbl not in tables_found:
                    tables_found.append(raw_tbl)

            # 2. Carve Emails and Usernames from database chunk
            emails: list[str] = []
            for e_match in EMAIL_PATTERN.finditer(db_chunk):
                email_str = e_match.group(0).decode("latin1", errors="ignore")
                if (
                    not email_str.endswith(".png")
                    and not email_str.endswith(".dll")
                    and not email_str.endswith(".exe")
                    and len(email_str) < 64
                    and email_str not in emails
                ):
                    emails.append(email_str)

            # 3. Carve preview records
            records_preview: list[str] = []
            for em in emails[:10]:
                records_preview.append(f"Carved Email: {em}")
            for tbl in tables_found[:10]:
                records_preview.append(f"Carved Table Schema: {tbl}")

            findings.append(
                SQLiteCarvedFinding(
                    offset=idx,
                    database_size=db_size,
                    tables_found=tables_found,
                    extracted_records_count=len(emails) + len(tables_found),
                    records_preview=records_preview,
                )
            )

            start_offset = idx + max(page_size, 16)

        return findings
