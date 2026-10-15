"""
memhunter/carvers/dotnet_us_decryptor.py
In-memory .NET CLR (`BSJB`) `#US` (User Strings) heap parser and offline config decryptor:
1. Parses `#US` streams from every `BSJB` metadata root in process memory dumps, plus ordered
   UTF-16LE managed heap strings.
2. Unwraps 3-argument outer AES-CBC string obfuscators (`Decrypt(ct_b64, key_b64, iv_b64)`).
3. Authenticates and decrypts Pulsar RAT (AES-256-GCM & AES-256-CBC+HMAC), AsyncRAT, DcRat,
   and VenomRAT `Settings` fields (`Hosts`, `Ports`, `MTX`, `Group`, `Version`, `Pastebin`),
   preserving authenticated LAN/tunnel C2s (`localhost:4782`, `10.0.2.3:4782`) and `host:port` C2s.
4. Recovers RedLine Stealer `#US` configurations (both VMProtect `%before%` contiguous `#US` blocks
   and 3-step/1-step Base64+XOR encrypted `IP`/`ID`/`Key`/`Mutex` fields).
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PULSAR_SALT = bytes.fromhex("5a23f8394640cb9e40658446a04c0bbae82dc93d0470e1b2a406a90fd2520382")
ASYNCRAT_SALT = bytes.fromhex("BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941")

FAMILY_SALTS: Dict[str, bytes] = {
    "pulsar_rat": PULSAR_SALT,
    "dcrat": b"DcRatByqwqdanchun",
    "venomrat": b"VenomRATByVenom",
    "asyncrat": ASYNCRAT_SALT,
}

B64_STRICT_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
HOST_PORT_TOKEN_RE = re.compile(
    r"^(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+):(\d{2,5})$"
)
PULSAR_HOSTS_LIST_RE = re.compile(
    rb"((?:(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+):\d{2,5};)+)"
)
UUID_MUTEX_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
UTF16_TOKEN_RE = re.compile(rb"(?:[\x20-\x7e]\x00){3,120}")


def extract_dotnet_us_streams(buffer: bytes) -> List[List[str]]:
    """
    Locate all .NET CLR `BSJB` metadata roots in `buffer`, parse their `#US` stream headers,
    and decode the ordered list of UTF-16LE user strings per module.
    """
    streams: List[List[str]] = []
    buf_len = len(buffer)

    for m in re.finditer(rb"BSJB", buffer):
        bsjb_off = m.start()
        if bsjb_off + 32 > buf_len:
            continue
        try:
            v_len = struct.unpack_from("<I", buffer, bsjb_off + 12)[0]
            if v_len == 0 or v_len > 256:
                continue
            v_aligned = (v_len + 3) & ~3
            hdr_pos = bsjb_off + 16 + v_aligned
            if hdr_pos + 4 > buf_len:
                continue
            n_streams = struct.unpack_from("<H", buffer, hdr_pos + 2)[0]
            if n_streams == 0 or n_streams > 16:
                continue

            cur = hdr_pos + 4
            for _ in range(n_streams):
                if cur + 8 > buf_len:
                    break
                s_off, s_size = struct.unpack_from("<II", buffer, cur)
                cur += 8
                name_end = buffer.find(b"\x00", cur, min(buf_len, cur + 32))
                if name_end == -1:
                    break
                s_name = buffer[cur:name_end]
                name_len = name_end - cur + 1
                cur += (name_len + 3) & ~3

                if s_name == b"#US":
                    us_start = bsjb_off + s_off
                    us_end = min(buf_len, us_start + s_size)
                    if us_start < buf_len and us_end > us_start + 2 and s_size <= 16 * 1024 * 1024:
                        parsed = _parse_us_heap_bytes(buffer[us_start:us_end])
                        if parsed:
                            streams.append(parsed)
        except Exception:
            continue
    return streams


def _parse_us_heap_bytes(us_bytes: bytes) -> List[str]:
    """Decode length-prefixed UTF-16LE user strings from a raw `#US` stream."""
    out: List[str] = []
    n = len(us_bytes)
    pos = 1
    while pos < n:
        b0 = us_bytes[pos]
        if b0 == 0:
            pos += 1
            continue
        if (b0 & 0x80) == 0:
            blob_len = b0
            pos += 1
        elif (b0 & 0xC0) == 0x80:
            if pos + 1 >= n:
                break
            blob_len = ((b0 & 0x3F) << 8) | us_bytes[pos + 1]
            pos += 2
        elif (b0 & 0xE0) == 0xC0:
            if pos + 3 >= n:
                break
            blob_len = ((b0 & 0x1F) << 24) | (us_bytes[pos + 1] << 16) | (us_bytes[pos + 2] << 8) | us_bytes[pos + 3]
            pos += 4
        else:
            pos += 1
            continue

        if blob_len <= 1 or pos + blob_len > n:
            pos += max(1, blob_len)
            continue

        str_bytes = us_bytes[pos : pos + blob_len - 1]
        pos += blob_len
        if len(str_bytes) % 2 == 0 and len(str_bytes) <= 8192:
            try:
                s = str_bytes.decode("utf-16le", errors="ignore").strip("\x00")
                if s:
                    out.append(s)
            except Exception:
                pass
    return out


def _try_b64_decode(s: str) -> Optional[bytes]:
    if len(s) < 16 or len(s) % 4 != 0 or not B64_STRICT_RE.match(s):
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def deobfuscate_outer_3arg_aes_cbc(strings: List[str]) -> List[str]:
    """
    Detect and decrypt 3-argument outer AES-CBC obfuscated triples `(ct_b64, key_b64, iv_b64)`
    in `#US` streams (used by obfuscated Pulsar RAT builds like campaign ARBUZ).
    """
    decrypted_extra: List[str] = []
    b64_items: List[Tuple[int, str, bytes]] = []
    for idx, s in enumerate(strings):
        if len(s) <= 4096 and (raw := _try_b64_decode(s)) is not None:
            b64_items.append((idx, s, raw))

    for i in range(len(b64_items) - 2):
        idx0, _, ct = b64_items[i]
        idx1, _, key = b64_items[i + 1]
        idx2, _, iv = b64_items[i + 2]
        if idx2 - idx0 > 6:
            continue
        if len(key) in (16, 24, 32) and len(iv) == 16 and len(ct) >= 16 and len(ct) % 16 == 0:
            try:
                pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16).decode("utf-8")
                if pt and pt.isprintable() and pt not in decrypted_extra:
                    decrypted_extra.append(pt)
            except Exception:
                continue
    return decrypted_extra


@functools.lru_cache(maxsize=128)
def _derive_cbc_hmac_keys(master_key: str, salt: bytes) -> Tuple[bytes, bytes]:
    derived = hashlib.pbkdf2_hmac("sha1", master_key.encode("utf-8"), salt, 50000, dklen=96)
    return derived[:32], derived[32:]


@functools.lru_cache(maxsize=128)
def _derive_pulsar_gcm_key(master_key: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", master_key.encode("utf-8"), PULSAR_SALT, 100000, dklen=32)


def _try_decrypt_pulsar_gcm(master_key: str, raw: bytes) -> Optional[str]:
    if len(raw) < 29:
        return None
    aes_key = _derive_pulsar_gcm_key(master_key)
    nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
    try:
        pt = AES.new(aes_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        return pt.decode("utf-8")
    except Exception:
        return None


def _try_decrypt_cbc_hmac(master_key: str, raw: bytes, salt: bytes) -> Optional[str]:
    if len(raw) < 64 or (len(raw) - 48) % 16 != 0:
        return None
    aes_key, hmac_key = _derive_cbc_hmac_keys(master_key, salt)
    mac_expected, body = raw[:32], raw[32:]
    mac_actual = hmac.new(hmac_key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_expected, mac_actual):
        return None
    iv, ct = body[:16], body[16:]
    try:
        pt = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), 16)
        return pt.decode("utf-8")
    except Exception:
        return None


def _decrypt_redline_3step(b64_ct: str, key: str) -> Optional[str]:
    try:
        step1 = base64.b64decode(b64_ct, validate=True).decode("utf-8", errors="surrogatepass")
        step2 = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(step1))
        return base64.b64decode(step2.encode("utf-8"), validate=True).decode("utf-8").strip()
    except Exception:
        return None


def carve_dotnet_us_configs(buffer: bytes, wide_ascii: bytes = b"") -> Dict[str, Any]:
    """
    Parse all `#US` streams (and UTF-16LE heap windows around `%before%` / `Settings`) in `buffer`
    and run deterministic offline decryptors for Pulsar RAT, AsyncRAT/DcRat/VenomRAT, and RedLine.
    """
    us_streams = extract_dotnet_us_streams(buffer)

    # Also build focused UTF-16LE windows around `%before%` (RedLine) and Pulsar/AsyncRAT keys
    for anchor in (b"%\x00b\x00e\x00f\x00o\x00r\x00e\x00%\x00", b"P\x00u\x00l\x00s\x00a\x00r\x00"):
        for m in re.finditer(re.escape(anchor), buffer):
            win = buffer[max(0, m.start() - 16384) : min(len(buffer), m.end() + 32768)]
            tokens = [tm.group(0)[::2].decode("ascii", errors="ignore") for tm in UTF16_TOKEN_RE.finditer(win)]
            if tokens:
                us_streams.append(tokens)

    c2_endpoints: Set[str] = set()
    ddrs: Set[str] = set()
    mutexes: Set[str] = set()
    decrypted_blobs: List[str] = []
    detected_family: Optional[str] = None

    # Check semicolon-delimited Pulsar Settings.Hosts already decrypted in RAM (e.g. `localhost:4782;10.0.2.3:4782;`)
    for scan_b in (buffer, wide_ascii) if wide_ascii else (buffer,):
        for hm in PULSAR_HOSTS_LIST_RE.finditer(scan_b):
            raw_list = hm.group(1).decode("ascii", errors="ignore")
            for tok in raw_list.split(";"):
                tok = tok.strip()
                if HOST_PORT_TOKEN_RE.match(tok):
                    c2_endpoints.add(tok)

    for stream in us_streams:
        unwrapped = deobfuscate_outer_3arg_aes_cbc(stream)
        combined = stream + unwrapped

        # 1. RedLine VMProtect contiguous `#US` block (`%before%` -> host, port, build_id, mutex)
        for idx in range(len(combined) - 4):
            if combined[idx] == "%before%":
                host_cand, port_cand, build_id, mtx_cand = combined[idx + 1 : idx + 5]
                if port_cand.isdigit() and 1 <= int(port_cand) <= 65535:
                    ep = f"{host_cand}:{port_cand}"
                    c2_endpoints.add(ep)
                    if len(mtx_cand) >= 4 and mtx_cand.isprintable():
                        mutexes.add(mtx_cand)
                    detected_family = "redline_stealer"
                    msg = f"RedLine #US config: C2={ep} ID={build_id} Mutex={mtx_cand}"
                    if msg not in decrypted_blobs:
                        decrypted_blobs.append(msg)

        # 2. Candidate keys and ciphertexts inside this `#US` stream
        b64_cands: List[Tuple[str, bytes]] = []
        key_cands: List[str] = []
        for s in combined:
            if not s or len(s) > 1200:
                continue
            if (raw := _try_b64_decode(s)) is not None:
                b64_cands.append((s, raw))
                if 12 <= len(raw) <= 64:
                    try:
                        k_dec = raw.decode("utf-8")
                        if k_dec.isprintable() and k_dec not in key_cands:
                            key_cands.append(k_dec)
                    except UnicodeDecodeError:
                        pass
            if 6 <= len(s) <= 64 and s.isprintable() and " " not in s and s not in key_cands:
                key_cands.append(s)

        # 2a. Authenticate Pulsar GCM & Pulsar/DcRat/AsyncRAT/VenomRAT CBC+HMAC
        authenticated_key: Optional[str] = None
        authenticated_mode: Optional[str] = None
        authenticated_fam: Optional[str] = None

        for key in key_cands[:60]:
            if authenticated_key:
                break
            for _s, raw in b64_cands[:50]:
                if len(raw) >= 29 and _try_decrypt_pulsar_gcm(key, raw) is not None:
                    authenticated_key, authenticated_mode, authenticated_fam = key, "GCM", "pulsar_rat"
                    break
                for fam, salt in FAMILY_SALTS.items():
                    if len(raw) >= 64 and _try_decrypt_cbc_hmac(key, raw, salt) is not None:
                        authenticated_key, authenticated_mode, authenticated_fam = key, "CBC", fam
                        break
                if authenticated_key:
                    break

        if authenticated_key and authenticated_fam:
            detected_family = authenticated_fam
            for _s, raw in b64_cands:
                pt = (
                    _try_decrypt_pulsar_gcm(authenticated_key, raw)
                    if authenticated_mode == "GCM"
                    else _try_decrypt_cbc_hmac(authenticated_key, raw, FAMILY_SALTS[authenticated_fam])
                )
                if not pt:
                    continue
                pt_clean = pt.strip()
                if not pt_clean or pt_clean == "null" or len(pt_clean) > 300:
                    continue
                entry_str = f"{authenticated_fam} Settings: {pt_clean}"
                if entry_str not in decrypted_blobs and len(decrypted_blobs) < 25:
                    decrypted_blobs.append(entry_str)

                if pt_clean.startswith(("http://", "https://")):
                    if "pastebin.com/raw/" in pt_clean:
                        ddrs.add(pt_clean)
                    else:
                        c2_endpoints.add(pt_clean)
                elif UUID_MUTEX_RE.match(pt_clean) or pt_clean.startswith(("DcRatMutex_", "AsyncMutex_")):
                    mutexes.add(pt_clean)
                else:
                    for tok in re.split(r"[;,]", pt_clean):
                        tok = tok.strip()
                        if HOST_PORT_TOKEN_RE.match(tok):
                            c2_endpoints.add(tok)

        # 2b. RedLine 3-step Base64+XOR decryption on `#US` streams with RedLine markers
        token_set = set(combined)
        if any(m in token_set for m in ("IRemoteEndpoint", "DownloadAndExecuteUpdate", "ScanningArgs", "StringDecrypt")):
            detected_family = detected_family or "redline_stealer"
            for ct_str, _raw in b64_cands[:40]:
                for key in key_cands[:40]:
                    if key == ct_str:
                        continue
                    pt = _decrypt_redline_3step(ct_str, key)
                    if pt:
                        for tok in re.split(r"[|,;\s]+", pt):
                            if HOST_PORT_TOKEN_RE.match(tok.strip()):
                                c2_endpoints.add(tok.strip())
                                decrypted_blobs.append(f"RedLine 3-step C2: {tok.strip()} (Key={key})")

    return {
        "family": detected_family,
        "c2_endpoints": sorted(c2_endpoints),
        "ddrs": sorted(ddrs),
        "mutexes": sorted(mutexes),
        "decrypted_blobs": decrypted_blobs,
    }
