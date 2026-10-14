"""Tests for in-memory credential and AI session extraction."""

from kinetic_memhunter.core.stealer_extractor import StealerArtifactExtractor
from kinetic_memhunter.models import CredentialCategory


def test_ai_session_and_wallet_extraction():
    extractor = StealerArtifactExtractor()
    buffer = (
        b"Padding data ... "
        b"Claude: sk-ant-sid01-abcdefghijklmnopqrstuvwxyz0123456789012345678901234567890123456789\n"
        b"OpenAI: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef\n"
        b"Gemini: __Secure-1PSID=abcdefghijklmnopqrstuvwxyz0123456789012345678901234567890123456789\n"
        b"MetaMask Extension: nkbihfbeogaeaoehlefnkodbefgpgknn\n"
        b"AWS Key: AKIAIOSFODNN7EXAMPLE\n"
    )

    findings = extractor.scan(buffer)
    assert len(findings) == 5

    categories = {f.category for f in findings}
    assert CredentialCategory.AI_DEVELOPER_SESSION in categories
    assert CredentialCategory.CRYPTO_WALLET in categories
    assert CredentialCategory.CLOUD_CREDENTIAL in categories

    platforms = [f.platform for f in findings]
    assert "Anthropic Claude Session" in platforms
    assert "OpenAI Project Key" in platforms
    assert "Google Gemini Session" in platforms
    assert "MetaMask Chrome Extension ID" in platforms
    assert "AWS Access Key ID" in platforms
