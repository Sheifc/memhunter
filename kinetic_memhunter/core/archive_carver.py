"""In-memory archive carver for compressed exfiltration payloads in memory dumps."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from typing import Any
from ..models import CarvedArchiveFinding

STEALER_ARTIFACT_NAMES = {
    "passwords.txt", "password.txt", "passwords.log",
    "cookies.txt", "cookies.sqlite", "cookies.json",
    "autofill.txt", "autofills.txt",
    "system_info.txt", "user_info.txt", "system.txt",
    "wallets", "wallet.dat", "metamask", "phantom",
    "telegram", "tdata", "discord",
    "cc.txt", "credit_cards.txt", "cards.txt",
    "keylog.txt", "history.txt", "bookmarks.txt",
}


class ArchiveCarver:
    """Carves in-memory ZIP, GZIP, and raw zlib archives staged by stealers."""

    def __init__(self, max_uncompressed_bytes: int = 50 * 1024 * 1024):
        self.max_uncompressed_bytes = max_uncompressed_bytes

    def scan(self, buffer: bytes) -> list[CarvedArchiveFinding]:
        findings: list[CarvedArchiveFinding] = []
        buf_len = len(buffer)
        if buf_len < 30:
            return findings

        # 1. Carve ZIP Archives (PK\x03\x04)
        start = 0
        while True:
            idx = buffer.find(b"PK\x03\x04", start)
            if idx == -1 or idx + 30 > buf_len:
                break
            start = idx + 4

            # Attempt to find End of Central Directory (PK\x05\x06) within 10MB
            eocd_search_limit = min(buf_len, idx + 10 * 1024 * 1024)
            eocd_idx = buffer.rfind(b"PK\x05\x06", idx, eocd_search_limit)

            if eocd_idx != -1 and eocd_idx + 22 <= buf_len:
                comment_len = struct.unpack_from("<H", buffer, eocd_idx + 20)[0]
                zip_end = eocd_idx + 22 + comment_len
                zip_data = buffer[idx:zip_end]
                try:
                    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                        infolist = zf.infolist()
                        if infolist:
                            filenames = [info.filename for info in infolist]
                            uncompressed_total = sum(info.file_size for info in infolist)

                            suspicious_artifacts = []
                            for fname in filenames:
                                fname_lower = fname.lower()
                                for art in STEALER_ARTIFACT_NAMES:
                                    if art in fname_lower:
                                        suspicious_artifacts.append(fname)
                                        break

                            findings.append(
                                CarvedArchiveFinding(
                                    archive_type="ZIP",
                                    offset=idx,
                                    compressed_size=len(zip_data),
                                    uncompressed_size=uncompressed_total,
                                    file_list=filenames[:50],
                                    stealer_artifacts_detected=suspicious_artifacts,
                                )
                            )
                            start = zip_end
                            continue
                except Exception:
                    pass

        # 2. Carve Raw Zlib / Deflate Streams (0x7801, 0x789C, 0x78DA)
        start = 0
        while True:
            zlib_idx = -1
            for header in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
                found = buffer.find(header, start)
                if found != -1 and (zlib_idx == -1 or found < zlib_idx):
                    zlib_idx = found

            if zlib_idx == -1 or zlib_idx + 32 > buf_len:
                break

            start = zlib_idx + 2
            try:
                decompressor = zlib.decompressobj()
                decompressed = decompressor.decompress(buffer[zlib_idx : zlib_idx + 2 * 1024 * 1024], self.max_uncompressed_bytes)
                consumed = len(buffer[zlib_idx : zlib_idx + 2 * 1024 * 1024]) - len(decompressor.unused_data)

                if len(decompressed) >= 64 and consumed >= 16:
                    # Check if decompressed bytes look like text or structured stealer logs
                    text_preview = decompressed[:1024].decode("utf-8", errors="ignore").lower()
                    detected_arts = []
                    for art in STEALER_ARTIFACT_NAMES:
                        if art in text_preview:
                            detected_arts.append(f"Content contains marker '{art}'")

                    if detected_arts or (b"sqlite" in decompressed[:64].lower()):
                        findings.append(
                            CarvedArchiveFinding(
                                archive_type="ZLIB_STREAM",
                                offset=zlib_idx,
                                compressed_size=consumed,
                                uncompressed_size=len(decompressed),
                                file_list=["[zlib_decompressed_payload]"],
                                stealer_artifacts_detected=detected_arts,
                            )
                        )
                        start = zlib_idx + consumed
            except Exception:
                pass

        return findings
