"""
tests/test_memhunter.py
Hermetic offline unit tests for memhunter:
- False-positive filtering (X.509 OIDs, version numbers, anticuckoo, USER API, unicode FTP)
- Windows Minidump (MDMP) header parsing & crypto S-Box detection
- EphemeralDumpWorkspace Zip-Slip protection & auto-deletion on exit
- Stealer artifact carving (Lumma JSON config, Discord webhook, ETH/BTC wallets, family attribution)
"""

from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from memhunter.carvers.artifacts import carve_memory_buffers
from memhunter.carvers.minidump import AES_SBOX_PREFIX, detect_crypto_primitives, parse_minidump_header
from memhunter.config import (
    is_benign_or_sandbox_url,
    is_valid_ftp_indicator,
    is_valid_public_c2_ip,
)
from memhunter.workspace import EphemeralDumpWorkspace


def test_false_positive_ip_filters() -> None:
    # X.509 OIDs and assembly versions that polluted legacy service_memdump must be rejected
    assert is_valid_public_c2_ip("1.3.6.1") is False
    assert is_valid_public_c2_ip("1.3.185.21") is False
    assert is_valid_public_c2_ip("5.5.7.1") is False
    assert is_valid_public_c2_ip("5.15.2.0") is False
    assert is_valid_public_c2_ip("1.0.0.10") is False
    assert is_valid_public_c2_ip("4.0.30319") is False
    assert is_valid_public_c2_ip("127.0.0.1") is False
    # Real public C2 IPs must pass
    assert is_valid_public_c2_ip("89.23.100.155") is True
    assert is_valid_public_c2_ip("185.69.122.235") is True


def test_false_positive_url_and_ftp_filters() -> None:
    assert is_benign_or_sandbox_url("https://github.com/therealdreg/anticuckoo") is True
    assert is_benign_or_sandbox_url("https://github.com/python/cpython") is True
    assert is_benign_or_sandbox_url("https://github.com/urllib3/urllib3") is True
    assert is_benign_or_sandbox_url("https://pastebin.com/raw/rACMKa5f") is False

    assert is_valid_ftp_indicator("USER API") is False
    assert is_valid_ftp_indicator("USER INTERACTION:") is False
    assert is_valid_ftp_indicator("ftp://ftp.unicode.org/") is False
    assert is_valid_ftp_indicator("ftp://exfil.evil-server.biz/upload") is True


def test_parse_minidump_header_and_sbox() -> None:
    # Construct valid 32-byte MDMP header + 1 stream directory entry (Memory64ListStream = 9)
    header = b"MDMP" + struct.pack("<HHIIIIQ", 0xA793, 0, 1, 32, 0, 1700000000, 0x02)
    stream_dir = struct.pack("<III", 9, 1024, 64)
    parsed = parse_minidump_header(header + stream_dir)
    assert parsed["is_minidump"] is True
    assert "Memory64ListStream" in parsed["streams"]

    primitives = detect_crypto_primitives(b"padding" + AES_SBOX_PREFIX + b"expand 32-byte k")
    assert "AES_Rijndael_SBox" in primitives
    assert "ChaCha20_Salsa20_Sigma" in primitives


def test_ephemeral_workspace_auto_cleanup_and_zip_slip(tmp_path: Path) -> None:
    sha = "a" * 64
    zip_file = tmp_path / "test_dump.zip"
    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.writestr("4796.dmp", b"MDMP" + b"\x00" * 64)

    saved_work_dir: Path | None = None
    with EphemeralDumpWorkspace(sha, base_tmp_dir=tmp_path) as ws:
        saved_work_dir = ws.work_dir
        assert saved_work_dir is not None and saved_work_dir.exists()
        extracted = ws.safe_extract_zip(zip_file)
        assert len(extracted) == 1
        assert extracted[0].name == "4796.dmp"
        # Source zip is removed right after extraction
        assert not zip_file.exists()

    # After context exit, the entire temporary directory is purged
    assert saved_work_dir is not None and not saved_work_dir.exists()

    # Verify Zip-Slip blocking
    evil_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil_zip, "w") as zf:
        zf.writestr("../../etc/cron.d/pwn", b"malicious")

    with EphemeralDumpWorkspace(sha, base_tmp_dir=tmp_path) as ws:
        with pytest.raises(ValueError, match="Zip-Slip"):
            ws.safe_extract_zip(evil_zip)


def test_carve_memory_buffers_end_to_end(tmp_path: Path) -> None:
    dmp = tmp_path / "proc.dmp"
    payload = (
        b"MDMP"
        + b'{"azure": 1, "steal_discord": 1, "grabber_size_max": 100000, "token": 56707772}'
        + b" https://discord.com/api/webhooks/1553391032467456000/inaxWtjf1By7KU--L4mMz3S4TvwI78YoAZGjRYOBupglHpbHEc6Ho1UKivcCMDAJH2wJ "
        + b" https://pastebin.com/raw/rACMKa5f "
        + b" https://github.com/therealdreg/anticuckoo "
        + b" 1.3.6.1 5.5.7.1 89.23.100.155:1337 "
        + b" 0x80EB1438CF1F93f368113c54E56684c41cDc6800 bc1q88sfcjthknff8ljm7l4vjr83f3z0waezcr92v6 "
        + b" Global\\DcRatMutex_qwqdanchun Exodus MetaMask SQLite format 3\x00 "
    )
    dmp.write_bytes(payload)

    res = carve_memory_buffers([dmp], resolve_ddr=False)
    assert res["family_supposition"] == "dcrat"
    assert res["sqlite_database_count"] == 1

    ips_urls = [x["value"] for x in res["extracted_c2"]["ips_urls"]]
    assert "89.23.100.155:1337" in ips_urls
    assert "1.3.6.1" not in ips_urls
    assert "5.5.7.1" not in ips_urls

    ddrs = [x["value"] for x in res["extracted_c2"]["ddr"]]
    assert "https://pastebin.com/raw/rACMKa5f" in ddrs
    assert all("anticuckoo" not in d for d in ddrs)

    assert len(res["extracted_c2"]["webhooks"]) == 1
    assert len(res["extracted_c2"]["crypto_wallets"]) == 2
    assert len(res["behaviour_intel"]["extracted_c2_json_config"]) == 1
    assert res["behaviour_intel"]["extracted_c2_json_config"][0]["token"] == 56707772
