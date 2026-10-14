# `memhunter` — Ephemeral Memory Dump Forensics & RAM Carver

`memhunter` is a stateless memory forensics microservice that downloads process memory dumps (`memdump`) from VirusTotal / Google Threat Intelligence (CAPE, Zenbox, Jujubox), carves decrypted C2 configurations, Discord/Telegram webhooks, crypto clipper wallets, Dead Drop Resolvers (DDR), and Chromium master keys, **and automatically deletes the heavy `.zip`/`.dmp` files upon completion**.

---

## Key Features

- **Ephemeral Download -> Carve -> Delete Lifecycle:** Streams sandbox memory dumps into `/tmp/memhunter_<uuid>/`, parses `.dmp` files, persists lightweight JSON + Markdown intelligence reports in `output/`, and purges all raw `.zip`/`.dmp` files immediately.
- **Standalone Portable Downloader (`download_memdumps.py`):** Can be copied to any machine with Python + `requests` to inspect `/files/{sha256}/behaviours` and download `.zip` memory dumps.
- **Zero-Noise Filtering:** Eliminates legacy `service_memdump` false positives:
  - Filters out X.509 OIDs (`1.3.6.1.*`) and binary version strings (`5.5.7.1`, `5.15.2.0`, `1.0.0.10`, `4.0.30319`) from `ips_urls`.
  - Filters out sandbox/runtime URLs (`github.com/therealdreg/anticuckoo`, `github.com/python/cpython`, `urllib3`, `requests`) from `ddr`.
  - Filters out `USER API`, `USER INTERACTION:`, and `ftp://ftp.unicode.org/` from `ftp_activity`.
- **High-Signal Extraction:**
  - Plaintext C2 JSON configs (`extracted_c2_json_config` for Lumma, Stealc, Raccoon).
  - Discord Webhooks & Telegram Bot tokens/channels.
  - Checksum-validated ETH (`0x...`) and BTC (`bc1q...`, `1...`, `3...`) clipper wallets.
  - Dead Drop Resolver (`pastebin.com/raw/*`, `steamcommunity.com/profiles/*`, `t.me/*`) extraction and live resolution.
  - Minidump (`MDMP`) header parsing, reflective PE/CLR carving, RC4/AES/ChaCha20 S-Box detection, SQLite3 & Chromium `v10`/`v20` master key detection, and deterministic `family_supposition`.

---

## Quick Start

```bash
# 1. Analyze a single sample (downloads memdump -> carves RAM -> deletes .zip/.dmp -> saves report)
python3 analyze_memdumps.py --hash 4bf843c79679754183c356a929048280b755f12ecdba16a17967567e2aec3c82

# 2. Analyze a batch of hashes from a file (with optional live Dead Drop resolution)
python3 analyze_memdumps.py --file hashes_memdump.txt --resolve-ddr

# 3. Standalone downloader (can run on any external machine to download memdump ZIPs)
python3 download_memdumps.py --hash 4bf843c79679754183c356a929048280b755f12ecdba16a17967567e2aec3c82 --output-dir ./memdumps
```
