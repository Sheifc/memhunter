"""In-memory stealer artifact and credential harvesting extractor."""

from __future__ import annotations

import re
from typing import Any
from ..models import CredentialCategory, StealerCredentialFinding

PATTERNS: list[tuple[CredentialCategory, str, re.Pattern[bytes]]] = [
    # --- AI Sessions & Developer Tokens ---
    (CredentialCategory.AI_DEVELOPER_SESSION, "Anthropic Claude Session", re.compile(rb"sk-ant-sid01-[a-zA-Z0-9_-]{60,}")),
    (CredentialCategory.AI_DEVELOPER_SESSION, "Anthropic Claude API Key", re.compile(rb"sk-ant-api03-[a-zA-Z0-9_-]{80,}")),
    (CredentialCategory.AI_DEVELOPER_SESSION, "Anthropic Session Cookie", re.compile(rb"sessionKey=sk-ant-[a-zA-Z0-9_-]{30,}")),
    (CredentialCategory.AI_DEVELOPER_SESSION, "OpenAI Project Key", re.compile(rb"sk-proj-[a-zA-Z0-9_-]{40,}")),
    (CredentialCategory.AI_DEVELOPER_SESSION, "OpenAI Web Session", re.compile(rb"sess-[a-zA-Z0-9_-]{30,}")),
    (CredentialCategory.AI_DEVELOPER_SESSION, "Google Gemini Session", re.compile(rb"__Secure-[13]PSID=[a-zA-Z0-9_-]{60,}")),
    (CredentialCategory.AI_DEVELOPER_SESSION, "Google AI API Key", re.compile(rb"AIzaSy[A-Za-z0-9_-]{33}")),
    (CredentialCategory.AI_DEVELOPER_SESSION, "HuggingFace Token", re.compile(rb"hf_[a-zA-Z0-9]{34,}")),

    # --- Browser DPAPI & Master Keys ---
    (CredentialCategory.BROWSER_MASTER_KEY, "DPAPI Blob Header", re.compile(rb"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb")),
    (CredentialCategory.BROWSER_MASTER_KEY, "Chrome/Edge AES-GCM v10 Header", re.compile(rb"v10[a-zA-Z0-9+/=]{28,}")),

    # --- Crypto Wallets ---
    (CredentialCategory.CRYPTO_WALLET, "MetaMask Chrome Extension ID", re.compile(rb"nkbihfbeogaeaoehlefnkodbefgpgknn")),
    (CredentialCategory.CRYPTO_WALLET, "Phantom Solana Extension ID", re.compile(rb"bfnaelmomeimhlpmgjnjophhpkkoljpa")),
    (CredentialCategory.CRYPTO_WALLET, "Coinbase Wallet Extension ID", re.compile(rb"hnfanknocfeofbddgcijnmhnfnkdnaad")),
    (CredentialCategory.CRYPTO_WALLET, "TronLink Extension ID", re.compile(rb"ibnejdfjmmkpcnlpebklmnkoeoihofec")),

    # --- Cloud & Dev Secrets ---
    (CredentialCategory.CLOUD_CREDENTIAL, "AWS Access Key ID", re.compile(rb"AKIA[0-9A-Z]{16}")),
    (CredentialCategory.CLOUD_CREDENTIAL, "GitHub Classic Token", re.compile(rb"ghp_[0-9a-zA-Z]{36}")),
    (CredentialCategory.CLOUD_CREDENTIAL, "GitHub Fine-Grained Token", re.compile(rb"github_pat_[0-9a-zA-Z_]{82}")),

    # --- Telegram & Messaging ---
    (CredentialCategory.TELEGRAM_SESSION, "Telegram Desktop Auth Key Hash", re.compile(rb"D877F783D5D3EF8C")),
    (CredentialCategory.TELEGRAM_SESSION, "Telegram tdata map marker", re.compile(rb"tdata[\\/]map[0-9]+")),
]


class StealerArtifactExtractor:
    """Scans memory buffers for staged stealer artifacts, developer tokens, and wallets."""

    def __init__(self, context_bytes: int = 40):
        self.context_bytes = context_bytes

    def scan(self, buffer: bytes) -> list[StealerCredentialFinding]:
        findings: list[StealerCredentialFinding] = []
        buf_len = len(buffer)
        seen_matches: set[str] = set()

        for category, platform, pattern in PATTERNS:
            for match in pattern.finditer(buffer):
                matched_bytes = match.group(0)
                matched_str = matched_bytes.decode("latin1", errors="replace")

                # De-duplicate identical credentials in memory
                dedup_key = f"{platform}:{matched_str}"
                if dedup_key in seen_matches:
                    continue
                seen_matches.add(dedup_key)

                offset = match.start()
                ctx_start = max(0, offset - self.context_bytes)
                ctx_end = min(buf_len, offset + len(matched_bytes) + self.context_bytes)
                context_preview = buffer[ctx_start:ctx_end].decode("latin1", errors="replace")

                # Mask sensitive key characters for safe reporting
                if len(matched_str) > 12:
                    masked_val = matched_str[:8] + "..." + matched_str[-4:]
                else:
                    masked_val = matched_str

                findings.append(
                    StealerCredentialFinding(
                        category=category,
                        platform=platform,
                        match_value=masked_val,
                        offset=offset,
                        context_snippet=context_preview.replace("\n", " ").replace("\r", " "),
                    )
                )

        return findings
