"""
memhunter/carvers/artifacts.py
High-signal RAM artifact carver for infostealers and RATs:
- Decrypted C2 JSON configurations (Lumma, Stealc, Raccoon)
- In-memory .NET #US stream decryption (Pulsar AES-GCM/CBC, 3-arg AES-CBC, RedLine Base64+XOR)
- Discord Webhooks & Telegram Bot tokens/channels
- Ethereum & Bitcoin clipper wallets
- Dead Drop Resolvers (Pastebin, Steam, Telegram) with optional live resolution
- SQLite3 databases & Chromium v10/v20/DPAPI master keys
- Deterministic family attribution (family_supposition)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import requests

from memhunter.carvers.c2_deobfuscator import (
    carve_extended_c2_protocols,
    decode_base64_c2_blobs,
    solve_rc4_encrypted_c2s,
)
from memhunter.carvers.dotnet_us_decryptor import carve_dotnet_us_configs
from memhunter.carvers.minidump import carve_pe_and_clr_indicators, detect_crypto_primitives
from memhunter.config import (
    is_benign_or_sandbox_url,
    is_valid_ftp_indicator,
    is_valid_public_c2_ip,
)

IPV4_PORT_RE = re.compile(rb"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{2,5}))?(?![0-9.])")
C2_HOST_PORT_RE = re.compile(
    rb"(?<!://)\b((?:[a-zA-Z0-9-]{1,48}\.)+(?:shop|top|xyz|ru|su|cc|pw|icu|cyou|onion|link|live|club|online|site|fun|space|tech|store|info|biz|org|net|com|ug|io|me|gg|to|sh|pro|dev|app|cloud|host)):(\d{2,5})\b"
)
UTF16LE_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
URL_RE = re.compile(rb"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,220}")
DISCORD_WEBHOOK_RE = re.compile(
    rb"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_-]{50,80}"
)
TELEGRAM_BOT_RE = re.compile(rb"https?://api\.telegram\.org/bot\d{7,12}:[A-Za-z0-9_-]{30,45}")
TELEGRAM_CHAN_RE = re.compile(rb"https?://(?:t\.me|telegram\.me)/[A-Za-z0-9_]{4,64}")
PASTEBIN_RAW_RE = re.compile(rb"https?://pastebin\.com/raw/[A-Za-z0-9]{6,12}")
STEAM_PROFILE_RE = re.compile(rb"https?://steamcommunity\.com/(?:profiles/\d{15,20}|id/[A-Za-z0-9_-]{3,40})")

ETH_WALLET_RE = re.compile(rb"\b0x[a-fA-F0-9]{40}\b")
BTC_BECH32_RE = re.compile(rb"\bbc1q[ac-hj-np-z02-9]{38,58}\b")
BTC_LEGACY_RE = re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

PDB_PATH_RE = re.compile(rb"[A-Za-z]:\\[\x20-\x7e]{4,160}\.pdb", re.IGNORECASE)
MUTEX_RE = re.compile(rb"(?<![\\A-Za-z0-9_/.])(?:Global\\|Local\\|DcRatMutex_)[A-Za-z0-9_.-]{4,64}")
FALSE_POSITIVE_MUTEX_PREFIXES = (
    "Local\\Temp",
    "Local\\Microsoft",
    "Local\\Micr",
    "Local\\Programs",
    "Local\\Packages",
    "Local\\Application",
    "Local\\Google",
    "Local\\BraveSoftware",
    "Local\\CEF",
    "Local\\CrashDumps",
    "Local\\D3DSCache",
    "Local\\Low",
    "Local\\WERReporting",
    "Global\\BFE_Notify_Event_",
    "Global\\CLR_PerfMon_",
    "Global\\CPFATE_",
    "Global\\Microsoft.Windows.",
    "Global\\WerKernelVertical",
    "Global\\OneSettingQueryMutex",
    "Global\\UFH_",
)
JSON_CONFIG_RE = re.compile(
    rb"\{[^{}]{10,650}(?:\"grabber_size_max\"|\"steal_discord\"|\"cryptocurrency\"|\"ldb\"\s*:)[^{}]{2,650}\}"
)
FTP_CMD_RE = re.compile(rb"(?:ftp://[^\s\"'<>]{6,120}|USER [A-Za-z0-9_.@-]{3,48}\r\n)")

STEALER_TARGETS = {
    b"Exodus": "Exodus",
    b"MetaMask": "MetaMask",
    b"Phantom": "Phantom",
    b"Ronin": "Ronin",
    b"TronLink": "TronLink",
    b"Trust Wallet": "Trust Wallet",
    b"FileZilla": "FileZilla",
    b"WinSCP": "WinSCP",
    b"Login Data": "Chromium Login Data",
    b"Local State": "Chromium Local State",
    b"logins.json": "Firefox logins.json",
    b"discord.com/api/v": "Discord API",
}


def resolve_dead_drop_url(url: str, timeout: int = 8) -> str | None:
    """Optionally resolve a live Pastebin raw Dead Drop URL to its C2 payload."""
    if "pastebin.com/raw/" not in url:
        return None
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and resp.text.strip():
            return resp.text.strip()[:160]
    except Exception:
        return None
    return None


def classify_family_from_memory(
    raw_blobs: List[bytes],
    pdb_paths: List[str],
    mutexes: List[str],
    json_configs: List[Dict[str, Any]],
    urls: List[str],
    webhooks: List[str],
    wallets: List[str],
    us_detected_family: Optional[str] = None,
) -> str:
    """
    Deterministic malware family classifier preventing the legacy 100% 'unknown' problem.
    """
    if us_detected_family:
        return us_detected_family

    joined_pdb = " ".join(pdb_paths).lower()
    joined_mtx = " ".join(mutexes).lower()
    joined_urls = " ".join(urls).lower()

    for blob in raw_blobs:
        if b"Pulsar.Common" in blob or b"PulsarClient" in blob or b"Quasar.Common" in blob:
            return "pulsar_rat"
        if b"DcRat" in blob or b"DcRatByqwqdanchun" in blob or "dcratmutex" in joined_mtx:
            return "dcrat"
        if "newraton" in joined_pdb or "commands.pdb" in joined_pdb or b"clientForCrypters" in blob:
            return "raton_rat"
        if (
            b"IRemoteEndpoint" in blob
            or b"DownloadAndExecuteUpdate" in blob
            or b"EmptyConfigs" in blob
            or b"GetDynamicConfigs" in blob
        ):
            return "redline_stealer"
        if b"AsyncClient" in blob or b"AsyncMutex" in blob:
            return "asyncrat"
        if b"Umbral" in blob or (b"billing/payment-sources" in blob and b"outbound-promotions/codes" in blob):
            return "umbral_stealer"
        if b"Stealerium" in blob or (b"api.gofile.io/servers" in blob and b"api.telegram.org/bot" in blob):
            return "stealerium"
        if b"1477" in blob and b"Grabber" in blob:
            return "1477_grabber"
        if b"njRAT" in blob or b"njq8" in blob:
            return "njrat"
        if b"WUpdateSvc" in blob or b"MSNetUpdater.exe" in blob:
            return "wupdatesvc_rat"

    if json_configs:
        for cfg in json_configs:
            if "grabber_size_max" in cfg and "token" in cfg:
                return "lumma_or_stealc"
            if "ldb" in cfg and "path" in cfg:
                return "chromium_ldb_stealer"

    if len(wallets) >= 2 and ("stealer.pdb" in joined_pdb or not urls):
        return "cryptocurrency_clipper"
    if webhooks:
        return "discord_webhook_stealer"
    if "niceports.shop" in joined_urls:
        return "pulsar_rat"
    return "generic_stealer_or_rat"


def _deduplicate_c2_endpoints(endpoints: Set[str]) -> List[str]:
    """
    Remove bare IPv4 strings (e.g. `150.241.66.67` or `185.230.162.2`) when a full
    `ip:port` endpoint (`150.241.66.67:5555`, `185.230.162.2:6532`) is already present.
    """
    hosts_with_ports: Set[str] = set()
    for ep in endpoints:
        if ":" in ep and not ep.startswith(("http://", "https://", "ws://", "wss://", "net.tcp://", "ftp://")):
            host_part = ep.split(":", 1)[0]
            hosts_with_ports.add(host_part)
    filtered = [ep for ep in endpoints if ep not in hosts_with_ports]
    return sorted(filtered)


def carve_memory_buffers(
    dump_paths: List[Path],
    resolve_ddr: bool = False,
) -> Dict[str, Any]:
    """
    Scan one or more .dmp files and extract filtered C2s, JSON configs, webhooks,
    wallets, DDRs, SQLite/DPAPI indicators, and family attribution.
    """
    ips_urls: Set[str] = set()
    webhooks: Set[str] = set()
    ddr_urls: Set[str] = set()
    wallets: Set[str] = set()
    ftp_items: Set[str] = set()
    pdb_paths: Set[str] = set()
    mutexes: Set[str] = set()
    targets: Set[str] = set()
    crypto_primitives: Set[str] = set()
    json_configs: List[Dict[str, Any]] = []
    decoded_c2_blobs: List[str] = []
    rc4_decrypted_c2s: List[Dict[str, Any]] = []
    chromium_keys: List[str] = []
    sqlite_hits = 0
    total_pe = 0
    total_clr = 0
    sample_blobs: List[bytes] = []
    us_detected_family: Optional[str] = None

    for dmp_path in dump_paths:
        raw = dmp_path.read_bytes()
        # Extract printable UTF-16LE sequences separated by newlines so null terminators are respected
        wide_ascii = b"\n".join(m.group(0)[::2] for m in UTF16LE_STR_RE.finditer(raw))
        scan_buffers = (raw, wide_ascii)
        sample_blobs.append(raw[:4_000_000] + b"\n" + wide_ascii[:2_000_000])

        pe_clr = carve_pe_and_clr_indicators(raw)
        total_pe += pe_clr["pe_headers_count"]
        total_clr += pe_clr["dotnet_clr_bsjb_count"]

        # Parse and decrypt .NET #US user string streams (Pulsar GCM/CBC, 3-arg AES, RedLine, DcRat)
        us_res = carve_dotnet_us_configs(raw, wide_ascii=wide_ascii)
        if us_res["family"] and not us_detected_family:
            us_detected_family = us_res["family"]
        for ep in us_res["c2_endpoints"]:
            if not is_benign_or_sandbox_url(ep):
                ips_urls.add(ep)
        for d in us_res["ddrs"]:
            ddr_urls.add(d)
        for mtx in us_res["mutexes"]:
            mutexes.add(mtx)
        for b_str in us_res["decrypted_blobs"]:
            if b_str not in decoded_c2_blobs and len(decoded_c2_blobs) < 25:
                decoded_c2_blobs.append(b_str)

        for prim in detect_crypto_primitives(raw):
            crypto_primitives.add(prim)

        sqlite_hits += raw.count(b"SQLite format 3\x00")
        if b"os_crypt" in raw or b"encrypted_key" in raw:
            chromium_keys.append("os_crypt_encrypted_key_present")

        for marker, label in STEALER_TARGETS.items():
            if marker in raw or marker in wide_ascii:
                targets.add(label)

        for buf in scan_buffers:
            for m in DISCORD_WEBHOOK_RE.finditer(buf):
                w_url = m.group(0).decode("ascii", errors="ignore")
                if not is_benign_or_sandbox_url(w_url):
                    webhooks.add(w_url)
            for m in TELEGRAM_BOT_RE.finditer(buf):
                webhooks.add(m.group(0).decode("ascii", errors="ignore"))

            for m in PASTEBIN_RAW_RE.finditer(buf):
                ddr_urls.add(m.group(0).decode("ascii", errors="ignore"))
            for m in STEAM_PROFILE_RE.finditer(buf):
                ddr_urls.add(m.group(0).decode("ascii", errors="ignore"))
            for m in TELEGRAM_CHAN_RE.finditer(buf):
                ddr_urls.add(m.group(0).decode("ascii", errors="ignore"))

            for m in URL_RE.finditer(buf):
                u = m.group(0).decode("ascii", errors="ignore").rstrip(".,;'\")}\\")
                if not is_benign_or_sandbox_url(u):
                    ips_urls.add(u)

            for m in C2_HOST_PORT_RE.finditer(buf):
                hp = m.group(0).decode("ascii", errors="ignore")
                port_num = int(m.group(2).decode("ascii"))
                if 1 <= port_num <= 65535 and port_num != 123 and not is_benign_or_sandbox_url(hp):
                    ips_urls.add(hp)

            for m in IPV4_PORT_RE.finditer(buf):
                ip_str = m.group(1).decode("ascii", errors="ignore")
                port_bytes = m.group(2)
                if is_valid_public_c2_ip(ip_str):
                    if port_bytes:
                        port_int = int(port_bytes.decode("ascii"))
                        if port_int != 123 and 1 <= port_int <= 65535:
                            ips_urls.add(f"{ip_str}:{port_int}")
                    else:
                        ips_urls.add(ip_str)

            for m in ETH_WALLET_RE.finditer(buf):
                w = m.group(0).decode("ascii")
                if len(set(w[2:].lower())) >= 6:
                    wallets.add(f"ETH:{w}")
            for m in BTC_BECH32_RE.finditer(buf):
                wallets.add(f"BTC:{m.group(0).decode('ascii')}")

            for m in PDB_PATH_RE.finditer(buf):
                pdb_val = m.group(0).decode("ascii", errors="ignore")
                if not pdb_val.lower().startswith("c:\\windows\\"):
                    pdb_paths.add(pdb_val)
            for m in MUTEX_RE.finditer(buf):
                mtx_val = m.group(0).decode("ascii", errors="ignore")
                if not any(mtx_val.startswith(fp) for fp in FALSE_POSITIVE_MUTEX_PREFIXES):
                    mutexes.add(mtx_val)

            for m in JSON_CONFIG_RE.finditer(buf):
                candidate = m.group(0).decode("utf-8", errors="ignore")
                try:
                    parsed = json.loads(candidate)
                    if isinstance(parsed, dict) and parsed not in json_configs:
                        json_configs.append(parsed)
                except Exception:
                    continue

            for m in FTP_CMD_RE.finditer(buf):
                ftp_str = m.group(0).decode("ascii", errors="ignore").strip()
                if is_valid_ftp_indicator(ftp_str):
                    ftp_items.add(ftp_str)

            ext = carve_extended_c2_protocols(buf)
            for ep in ext["extended_c2_endpoints"]:
                ips_urls.add(ep)
            for ddr in ext["extended_ddrs"]:
                ddr_urls.add(ddr)

            b64_res = decode_base64_c2_blobs(buf)
            for u in b64_res["decoded_c2_urls"]:
                ips_urls.add(u)
            for blob_str in b64_res["decoded_c2_blobs"]:
                if blob_str not in decoded_c2_blobs and len(decoded_c2_blobs) < 25:
                    decoded_c2_blobs.append(blob_str)

        for rc4_hit in solve_rc4_encrypted_c2s(raw):
            if rc4_hit not in rc4_decrypted_c2s and len(rc4_decrypted_c2s) < 15:
                rc4_decrypted_c2s.append(rc4_hit)

    ddr_entries: List[Dict[str, Any]] = []
    for durl in sorted(ddr_urls):
        if is_benign_or_sandbox_url(durl):
            continue
        entry: Dict[str, Any] = {"channel_type": "ddr", "value": durl}
        if resolve_ddr:
            resolved = resolve_dead_drop_url(durl)
            if resolved:
                entry["resolved_c2"] = resolved
        ddr_entries.append(entry)

    clean_c2_list = _deduplicate_c2_endpoints(ips_urls)

    family = classify_family_from_memory(
        raw_blobs=sample_blobs,
        pdb_paths=sorted(pdb_paths),
        mutexes=sorted(mutexes),
        json_configs=json_configs,
        urls=clean_c2_list,
        webhooks=sorted(webhooks),
        wallets=sorted(wallets),
        us_detected_family=us_detected_family,
    )

    return {
        "family_supposition": family,
        "pe_clr_summary": {
            "pe_headers_carved": total_pe,
            "dotnet_clr_bsjb_carved": total_clr,
        },
        "crypto_intel": {
            "crypto_algorithms": sorted(crypto_primitives),
            "chromium_master_keys": sorted(set(chromium_keys)),
        },
        "extracted_c2": {
            "ips_urls": [{"channel_type": "custom", "value": v} for v in clean_c2_list[:100]],
            "webhooks": [{"channel_type": "webhook", "value": w} for w in sorted(webhooks)],
            "crypto_wallets": sorted(wallets)[:50],
            "ddr": ddr_entries,
            "ftp_activity": sorted(ftp_items)[:25],
            "decoded_base64_c2_blobs": decoded_c2_blobs,
            "rc4_decrypted_c2s": rc4_decrypted_c2s,
        },
        "behaviour_intel": {
            "extracted_c2_json_config": json_configs[:10],
            "malware_targets": sorted(targets),
            "mutexes": sorted(mutexes)[:50],
            "pdb_paths": sorted(pdb_paths)[:25],
        },
        "sqlite_database_count": sqlite_hits,
        "in_memory_strings": sorted(list(webhooks) + list(ddr_urls) + list(pdb_paths) + list(mutexes))[:100],
    }
