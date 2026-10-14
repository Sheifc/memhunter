"""Tests for S-Box and cryptographic cipher detection."""

from kinetic_memhunter.core.sbox_detector import SBoxDetector, AES_FORWARD_SBOX, AES_INVERSE_SBOX
from kinetic_memhunter.models import PrimitiveType


def test_rc4_ksa_permutation_detection():
    detector = SBoxDetector()
    s = list(range(256))
    j = 0
    key = b"SuperSecretInfostealerKey"
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    sbox = bytes(s)
    buffer = b"\x00" * 500 + sbox + b"\xff" * 500
    findings = detector.scan(buffer)

    rc4_matches = [f for f in findings if f.primitive == PrimitiveType.RC4_KSA_SBOX]
    assert len(rc4_matches) == 1
    assert rc4_matches[0].offset == 500
    assert rc4_matches[0].entropy == 8.0


def test_rc4_rejects_identity_state():
    detector = SBoxDetector()
    identity = bytes(range(256))
    buffer = b"\xaa" * 100 + identity + b"\xbb" * 100
    findings = detector.scan(buffer)
    assert not any(f.primitive == PrimitiveType.RC4_KSA_SBOX for f in findings)


def test_aes_sbox_detection():
    detector = SBoxDetector()
    buffer = b"\x90" * 32 + AES_FORWARD_SBOX + b"\x90" * 64 + AES_INVERSE_SBOX + b"\x90" * 32
    findings = detector.scan(buffer)

    prims = [f.primitive for f in findings]
    assert PrimitiveType.AES_FORWARD_SBOX in prims
    assert PrimitiveType.AES_INVERSE_SBOX in prims


def test_chacha20_constant_detection():
    detector = SBoxDetector()
    buffer = b"padding" * 10 + b"expand 32-byte k" + b"padding" * 10
    findings = detector.scan(buffer)

    chachas = [f for f in findings if f.primitive == PrimitiveType.CHACHA20_CONSTANT]
    assert len(chachas) == 1
    assert chachas[0].metadata["constant"] == "expand 32-byte k"
