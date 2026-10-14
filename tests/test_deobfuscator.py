"""Tests for StealerDeobfuscator module."""

import base64
from kinetic_memhunter.core.deobfuscator import StealerDeobfuscator


def test_deobfuscator_base64_and_c2():
    # Base64 payload containing a C2 endpoint and SQLite query
    payload = b'{"c2": "http://stealer-c2-panel.xyz/gate.php", "query": "SELECT * FROM logins"}'
    encoded_b64 = base64.b64encode(payload)

    buffer = (
        b"Padding heap buffer ... "
        + encoded_b64
        + b" ... Direct C2: https://api.threat-domain.cc/upload ... "
        + b"Telegram: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678 ... "
        + b"Discord: https://discord.com/api/webhooks/123456789012345678/abcdef123456 ... "
        + b"Targeting: AppData\\Local\\Google\\Chrome\\User Data and CREATE TABLE logins"
    )

    deobf = StealerDeobfuscator()
    res = deobf.deobfuscate(buffer)

    assert len(res["decoded_base64_payloads"]) >= 1
    assert any("stealer-c2-panel.xyz" in p["decoded_preview"] for p in res["decoded_base64_payloads"])
    assert any("api.threat-domain.cc" in u for u in res["c2_urls"])
    assert len(res["telegram_bots"]) >= 1
    assert len(res["discord_webhooks"]) >= 1
    assert len(res["browser_profiles_targeted"]) >= 2


def test_deobfuscator_context_xor():
    key = b"MalwareKey"
    target_str = b"https://c2.secret-stealer-drop.com/logs"
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(target_str))

    buffer = b"\x00" * 200 + xored + b"\x00" * 200
    deobf = StealerDeobfuscator(context_keys=["MalwareKey"])
    res = deobf.deobfuscate(buffer)

    assert len(res["xor_decrypted_strings"]) >= 1
    assert any("secret-stealer-drop" in s["decrypted_preview"] for s in res["xor_decrypted_strings"])
