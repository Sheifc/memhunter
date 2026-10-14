"""Tests for end-to-end MemoryAnalyzer engine and MITRE mapping."""

import io
import zipfile
from kinetic_memhunter.analyzer import MemoryAnalyzer
from kinetic_memhunter.core.sbox_detector import AES_FORWARD_SBOX


def test_analyzer_end_to_end():
    # Build a simulated stealer memory dump:
    # 1. Zip archive with passwords.txt
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("passwords.txt", "stealer loot")
    zip_bytes = bio.getvalue()

    # 2. RC4 S-Box
    s = list(range(256))
    j = 0
    key = b"StealerKey123"
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    rc4_sbox = bytes(s)

    # 3. AI Tokens & AES S-Box
    buffer = bytearray(b"\x90" * 2048)
    buffer[100:100 + len(zip_bytes)] = zip_bytes
    buffer[800:800 + 256] = rc4_sbox
    buffer[1200:1200 + 256] = AES_FORWARD_SBOX

    token_str = b"sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    buffer[1600:1600 + len(token_str)] = token_str

    analyzer = MemoryAnalyzer()
    report = analyzer.analyze_bytes(bytes(buffer), target_name="test_dump.dmp")

    assert report.threat_score >= 60
    assert report.threat_verdict == "CONFIRMED_INFOSTEALER"
    assert report.summary["crypto_primitives_count"] >= 2
    assert report.summary["carved_archives_count"] >= 1
    assert report.summary["credentials_count"] >= 1

    mitre_ids = [m["id"] for m in report.mitre_techniques]
    assert "T1027" in mitre_ids
    assert "T1560" in mitre_ids
    assert "T1539" in mitre_ids
    assert "T1552" in mitre_ids
