"""
memhunter/carvers/c2_deobfuscator.py
Focused C2 hunter ported from kinetic-memhunter:
1. In-memory Base64 blob decoding to unveil obfuscated C2 URLs, IPs, webhooks, and JSON configs.
2. Extended C2 protocol carving (.onion Tor gates, RedLine WCF net.tcp://, WebSockets ws:// & wss://,
   and extended Dead Drop Resolvers: rentry.co, telegra.ph, gist/raw.githubusercontent.com).
3. O(N) RC4 KSA S-Box detection + adjacent heap key solver to decrypt in-memory C2 configurations.
"""

from __future__ import annotations

import base64
import math
import re
from typing import Any, Dict, List, Set

from memhunter.config import is_benign_or_sandbox_url, is_valid_public_c2_ip

B64_BLOB_RE = re.compile(rb"[A-Za-z0-9+/]{24,512}={0,2}")
ONION_C2_RE = re.compile(rb"\b[a-z2-7]{16,56}\.onion(?::\d{2,5})?(?:/[^\s\"'<>\\\x00]*)?", re.IGNORECASE)
NET_TCP_RE = re.compile(rb"net\.tcp://[a-zA-Z0-9._-]+:\d{2,5}(?:/[^\s\"'<>\\\x00]*)?", re.IGNORECASE)
WEBSOCKET_C2_RE = re.compile(rb"wss?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,220}", re.IGNORECASE)
EXTENDED_DDR_RE = re.compile(
    rb"https?://(?:rentry\.co|telegra\.ph|raw\.githubusercontent\.com|gist\.githubusercontent\.com|mastodon\.social)/[A-Za-z0-9_./-]+",
    re.IGNORECASE,
)
URL_IN_DECODED_RE = re.compile(rb"(?:https?|wss?|net\.tcp|ftp)://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,220}")
IPV4_PORT_IN_DECODED_RE = re.compile(rb"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b")

C2_PLAINTEXT_PROBES: tuple[bytes, ...] = (
    b"http://",
    b"https://",
    b"net.tcp://",
    b"ws://",
    b"wss://",
    b"{\"settings\":",
    b"{\"bot_id\":",
    b"{\"c2\":",
    b"POST /",
    b"HTTP/1.1",
)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def _rc4_crypt(key: bytes, data: bytes, max_bytes: int | None = None) -> bytes:
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) % 256
        s[i], s[j] = s[j], s[i]

    i = j = 0
    limit = len(data) if max_bytes is None else min(len(data), max_bytes)
    out = bytearray(limit)
    for idx in range(limit):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[idx] = data[idx] ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def find_rc4_sbox_offsets(buffer: bytes, max_hits: int = 8) -> List[int]:
    """
    O(N) rolling-sum scanner for 256-byte permutations (active RC4 KSA S-Boxes in RAM)
    where sum(S[0..255]) == 32640 and all 256 byte values are unique and non-identity.
    """
    n = len(buffer)
    if n < 256:
        return []

    hits: List[int] = []
    identity = bytes(range(256))
    step = 64  # 64-byte aligned scan for fast heap traversal
    for offset in range(0, n - 256 + 1, step):
        window = buffer[offset : offset + 256]
        if sum(window) == 32640 and len(set(window)) == 256 and window != identity:
            hits.append(offset)
            if len(hits) >= max_hits:
                break
    return hits


def solve_rc4_encrypted_c2s(buffer: bytes, search_radius: int = 4096) -> List[Dict[str, Any]]:
    """
    Locate active RC4 S-Boxes in memory, harvest nearby ASCII candidate keys on the heap,
    and test-decrypt adjacent high-entropy regions for C2 URLs, headers, or JSON configs.
    """
    results: List[Dict[str, Any]] = []
    sbox_offsets = find_rc4_sbox_offsets(buffer)
    if not sbox_offsets:
        return results

    buf_len = len(buffer)
    for sbox_off in sbox_offsets[:4]:
        win_start = max(0, sbox_off - search_radius)
        win_end = min(buf_len, sbox_off + 256 + search_radius)
        window = buffer[win_start:win_end]

        key_candidates: List[bytes] = []
        for m in re.finditer(rb"[A-Za-z0-9_\-.!@#$%^&*]{8,32}", window):
            cand = m.group(0)
            if cand not in key_candidates:
                key_candidates.append(cand)
            if len(key_candidates) >= 15:
                break

        if not key_candidates:
            continue

        for chunk_off in range(win_start, max(win_start + 1, win_end - 256), 256):
            chunk = buffer[chunk_off : min(buf_len, chunk_off + 1024)]
            if len(chunk) < 32 or _shannon_entropy(chunk[:128]) < 6.5:
                continue

            for key in key_candidates:
                prefix = _rc4_crypt(key, chunk, max_bytes=32)
                if any(probe in prefix for probe in C2_PLAINTEXT_PROBES):
                    decrypted = _rc4_crypt(key, chunk, max_bytes=512)
                    preview = decrypted.decode("latin1", errors="ignore").strip()
                    results.append(
                        {
                            "cipher": "RC4",
                            "key": key.decode("latin1", errors="ignore"),
                            "offset": chunk_off,
                            "decrypted_c2_preview": preview[:200],
                        }
                    )
                    break
    return results


def decode_base64_c2_blobs(buffer: bytes) -> Dict[str, List[str]]:
    """
    Scan memory buffer for Base64-encoded strings and extract hidden C2 URLs,
    IP:PORT endpoints, and decoded C2 payloads.
    """
    c2_urls: Set[str] = set()
    decoded_previews: List[str] = []
    seen_b64: Set[bytes] = set()

    for m in B64_BLOB_RE.finditer(buffer):
        raw_b64 = m.group(0)
        if raw_b64 in seen_b64:
            continue
        rem = len(raw_b64) % 4
        if rem and not raw_b64.endswith(b"="):
            raw_b64 = raw_b64[:-rem]
        if len(raw_b64) < 24:
            continue

        try:
            decoded = base64.b64decode(raw_b64)
        except Exception:
            continue

        seen_b64.add(raw_b64)
        for um in URL_IN_DECODED_RE.finditer(decoded):
            u = um.group(0).decode("ascii", errors="ignore").rstrip(".,;'\")}\\")
            if not is_benign_or_sandbox_url(u):
                c2_urls.add(u)

        for im in IPV4_PORT_IN_DECODED_RE.finditer(decoded):
            ip_s = im.group(1).decode("ascii", errors="ignore")
            port_s = im.group(2).decode("ascii", errors="ignore")
            if is_valid_public_c2_ip(ip_s):
                c2_urls.add(f"{ip_s}:{port_s}")

        if any(p in decoded for p in C2_PLAINTEXT_PROBES):
            text = decoded[:160].decode("latin1", errors="ignore")
            if text not in decoded_previews and len(decoded_previews) < 25:
                decoded_previews.append(text)

    return {
        "decoded_c2_urls": sorted(c2_urls),
        "decoded_c2_blobs": decoded_previews,
    }


def carve_extended_c2_protocols(buffer: bytes) -> Dict[str, List[str]]:
    """
    Carve Tor .onion gates, RedLine WCF net.tcp:// endpoints, WebSockets (ws:// / wss://),
    and extended Dead Drop Resolver URLs from memory.
    """
    c2_endpoints: Set[str] = set()
    ddrs: Set[str] = set()

    for m in ONION_C2_RE.finditer(buffer):
        onion = m.group(0).decode("ascii", errors="ignore").rstrip(".,;'\")}\\")
        c2_endpoints.add(f"http://{onion}" if not onion.startswith("http") else onion)

    for m in NET_TCP_RE.finditer(buffer):
        c2_endpoints.add(m.group(0).decode("ascii", errors="ignore").rstrip(".,;'\")}\\"))

    for m in WEBSOCKET_C2_RE.finditer(buffer):
        ws = m.group(0).decode("ascii", errors="ignore").rstrip(".,;'\")}\\")
        if not is_benign_or_sandbox_url(ws):
            c2_endpoints.add(ws)

    for m in EXTENDED_DDR_RE.finditer(buffer):
        d = m.group(0).decode("ascii", errors="ignore").rstrip(".,;'\")}\\")
        if not is_benign_or_sandbox_url(d):
            ddrs.add(d)

    return {
        "extended_c2_endpoints": sorted(c2_endpoints),
        "extended_ddrs": sorted(ddrs),
    }
