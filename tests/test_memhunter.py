"""
tests/test_memhunter.py
Hermetic offline unit tests for memhunter:
- False-positive filtering (X.509 OIDs, version numbers, anticuckoo, USER API, unicode FTP)
- Windows Minidump (MDMP) header parsing & crypto S-Box detection
- EphemeralDumpWorkspace Zip-Slip protection & auto-deletion on exit
- Stealer C2 artifact carving (Lumma JSON config, Discord webhook, ETH/BTC wallets, family attribution)
- Base64 C2 blob decoding, extended C2 protocols (.onion, net.tcp://, wss://, rentry.co), and RC4 heap C2 decryption
"""

from __future__ import annotations

import base64
import struct
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from memhunter.carvers.artifacts import carve_memory_buffers
from memhunter.carvers.c2_deobfuscator import (
    _rc4_crypt,
    carve_extended_c2_protocols,
    decode_base64_c2_blobs,
    solve_rc4_encrypted_c2s,
)
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
        assert not zip_file.exists()

    assert saved_work_dir is not None and not saved_work_dir.exists()

    evil_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil_zip, "w") as zf:
        zf.writestr("../../etc/cron.d/pwn", b"malicious")

    with EphemeralDumpWorkspace(sha, base_tmp_dir=tmp_path) as ws:
        with pytest.raises(ValueError, match="Zip-Slip"):
            ws.safe_extract_zip(evil_zip)


def test_base64_and_extended_c2_carving() -> None:
    b64_payload = base64.b64encode(b'{"c2": "http://185.215.113.45:8080/gate.php", "bot_id": "alpha"}')
    buf = (
        b"padding "
        + b64_payload
        + b" net.tcp://45.154.98.129:35361/IRemoteEndpoint "
        + b" wss://c2.dataminer-panel.top/bot?key=abc123 "
        + b" https://rentry.co/c2deadrop123 "
        + b" vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion "
    )
    b64_res = decode_base64_c2_blobs(buf)
    assert "http://185.215.113.45:8080/gate.php" in b64_res["decoded_c2_urls"]
    assert "185.215.113.45:8080" in b64_res["decoded_c2_urls"]
    assert len(b64_res["decoded_c2_blobs"]) == 1

    ext_res = carve_extended_c2_protocols(buf)
    assert "net.tcp://45.154.98.129:35361/IRemoteEndpoint" in ext_res["extended_c2_endpoints"]
    assert "wss://c2.dataminer-panel.top/bot?key=abc123" in ext_res["extended_c2_endpoints"]
    assert any(".onion" in ep for ep in ext_res["extended_c2_endpoints"])
    assert "https://rentry.co/c2deadrop123" in ext_res["extended_ddrs"]


def test_rc4_encrypted_c2_solver() -> None:
    key = b"SuperSecretC2Key"
    # Build KSA S-Box for key
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % len(key)]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    sbox_bytes = bytes(sbox)

    plaintext = b"http://91.92.240.58:5000/api/upload_log\x00" + bytes(range(1, 220))
    ciphertext = _rc4_crypt(key, plaintext)

    # Align S-Box at offset 0 (multiple of 64), key at offset 256, ciphertext at offset 512
    heap_buf = sbox_bytes + key.ljust(256, b"\x00") + ciphertext.ljust(512, b"\x00")
    solved = solve_rc4_encrypted_c2s(heap_buf)
    assert len(solved) >= 1
    assert solved[0]["key"] == "SuperSecretC2Key"
    assert "http://91.92.240.58:5000/api/upload_log" in solved[0]["decrypted_c2_preview"]


def test_carve_memory_buffers_end_to_end(tmp_path: Path) -> None:
    dmp = tmp_path / "proc.dmp"
    b64_c2 = base64.b64encode(b"http://194.169.175.33:9001/c2_gate")
    payload = (
        b"MDMP"
        + b'{"azure": 1, "steal_discord": 1, "grabber_size_max": 100000, "token": 56707772}'
        + b" https://discord.com/api/webhooks/1553391032467456000/inaxWtjf1By7KU--L4mMz3S4TvwI78YoAZGjRYOBupglHpbHEc6Ho1UKivcCMDAJH2wJ "
        + b" https://pastebin.com/raw/rACMKa5f "
        + b" https://github.com/therealdreg/anticuckoo "
        + b" 1.3.6.1 5.5.7.1 89.23.100.155:1337 "
        + b" net.tcp://52.237.29.81:1912/IRemoteEndpoint "
        + b" " + b64_c2 + b" "
        + b" 0x80EB1438CF1F93f368113c54E56684c41cDc6800 bc1q88sfcjthknff8ljm7l4vjr83f3z0waezcr92v6 "
        + b" Global\\DcRatMutex_qwqdanchun Exodus MetaMask SQLite format 3\x00 "
    )
    dmp.write_bytes(payload)

    res = carve_memory_buffers([dmp], resolve_ddr=False)
    assert res["family_supposition"] == "dcrat"
    assert res["sqlite_database_count"] == 1

    ips_urls = [x["value"] for x in res["extracted_c2"]["ips_urls"]]
    assert "89.23.100.155:1337" in ips_urls
    assert "net.tcp://52.237.29.81:1912/IRemoteEndpoint" in ips_urls
    assert "http://194.169.175.33:9001/c2_gate" in ips_urls
    assert "1.3.6.1" not in ips_urls
    assert "5.5.7.1" not in ips_urls

    ddrs = [x["value"] for x in res["extracted_c2"]["ddr"]]
    assert "https://pastebin.com/raw/rACMKa5f" in ddrs
    assert all("anticuckoo" not in d for d in ddrs)

    assert len(res["extracted_c2"]["webhooks"]) == 1
    assert len(res["extracted_c2"]["crypto_wallets"]) == 2
    assert len(res["behaviour_intel"]["extracted_c2_json_config"]) == 1
    assert res["behaviour_intel"]["extracted_c2_json_config"][0]["token"] == 56707772
