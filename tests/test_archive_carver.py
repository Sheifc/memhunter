"""Tests for in-memory compressed archive carving."""

import io
import zipfile
import zlib
from kinetic_memhunter.core.archive_carver import ArchiveCarver


def test_carve_zip_archive_with_passwords():
    # Build in-memory zip
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("passwords.txt", "admin:password123\n")
        zf.writestr("cookies.txt", "domain\tTRUE\t/\tFALSE\t123\tsess\tabc\n")
        zf.writestr("system_info.txt", "OS: Windows 11 Enterprise\n")
    zip_bytes = bio.getvalue()

    buffer = b"\x00" * 256 + zip_bytes + b"\x00" * 256

    carver = ArchiveCarver()
    findings = carver.scan(buffer)

    assert len(findings) == 1
    archive = findings[0]
    assert archive.archive_type == "ZIP"
    assert archive.offset == 256
    assert "passwords.txt" in archive.file_list
    assert len(archive.stealer_artifacts_detected) >= 2


def test_carve_zlib_stream_with_stealer_data():
    content = b"Staged stealer data with passwords.txt and cookies inside sqlite"
    compressed = zlib.compress(content)

    buffer = b"\x90" * 128 + compressed + b"\x90" * 128
    carver = ArchiveCarver()
    findings = carver.scan(buffer)

    assert len(findings) >= 1
    assert any(f.archive_type == "ZLIB_STREAM" for f in findings)
