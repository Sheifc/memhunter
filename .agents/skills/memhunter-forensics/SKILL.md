---
name: memhunter-forensics
description: >-
  Pro-level expert skill for automated memory forensics, Windows Minidump (MDMP) parsing,
  in-memory C2/JSON configuration carving, DPAPI/Chromium master key extraction, Dead Drop
  Resolver (DDR) resolution, and false-positive filtering in headless worker pipelines.
  Activates when the user requests "memhunter", "memdump", "memory forensics", "carving RAM",
  "service_memdump", "forensic_memory_report", "analizar memdump", or extracting C2 configs,
  Discord webhooks, Telegram bots, and crypto clipper wallets from process memory dumps.
---

# MemHunter Forensics: In-Memory Carving & Intelligence Extraction Skill

This skill governs all memory dump triage, binary stream carving, deobfuscation, and structured telemetry generation within the `memhunter` repository.

---

## 1. Ephemeral Download-Analyze-Purge Lifecycle

1. **Zero Persistent Dump Blobs:**
   - Raw sandbox memory dump ZIPs (`15 MB – 500 MB`) and uncompressed process dumps (`*.dmp`, `50 MB – 1.5 GB`) must **never** be committed to Git or left on disk after analysis.
   - Every analysis run MUST execute inside `EphemeralDumpWorkspace` (`tempfile.TemporaryDirectory`), guaranteeing that `.zip` and `.dmp` files are deleted in `__exit__` even if an exception occurs.
2. **Confinement & Zip-Slip / Bomb Protection:**
   - Validate every ZIP member path (`os.path.abspath(target).startswith(os.path.abspath(dest))`) before extraction.
   - Enforce `MEMHUNTER_MAX_DUMP_MB` bounds prior to decompression.

---

## 2. Core Carving Capabilities

1. **Minidump (`MDMP`) & Reflective PE Carving (`memhunter/carvers/minidump.py`):**
   - Parse Windows Minidump headers (`MDMP`, `0x504D444D`), directory streams (`SystemInfoStream`, `ModuleListStream`, `MemoryListStream`, `Memory64ListStream`).
   - Detect cryptographic key schedules and S-Boxes in memory (`RC4` identity/permuted S-Box, `AES` S-Box `0x63, 0x7c, 0x77, 0x7b...`, `ChaCha20` sigma `"expand 32-byte k"`).
   - Detect reflective PE headers (`MZ` + `PE\x00\x00`) and `.NET` CLR metadata (`BSJB`) mapped in unbacked memory regions.
2. **High-Signal Stealer Artifact Extraction (`memhunter/carvers/artifacts.py`):**
   - **Plaintext C2 JSON Configs (`extracted_c2_json_config`):** Carve decrypted Lumma / Stealc / Raccoon campaign JSON configurations (`token`, `grabber_size_max`, `steal_discord`, `cryptocurrency`, `.ldb` extension rules).
   - **Exfiltration Channels (`webhooks` & `telegram_bots`):** Extract Discord webhooks (`https://discord.com/api/webhooks/<id>/<token>`) and Telegram bot tokens/channels (`api.telegram.org/bot...`, `t.me/...`, `telegram.me/...`).
   - **Clipper Wallets (`crypto_wallets`):** Extract and validate Ethereum (`0x[a-fA-F0-9]{40}`) and Bitcoin (`bc1q...` Bech32 SegWit and `1...`/`3...` Base58Check) addresses.
   - **Dead Drop Resolvers (`ddr`):** Extract Pastebin (`pastebin.com/raw/*`), Steam (`steamcommunity.com/profiles/*`), and Telegram dead drops, and optionally resolve live `IP:PORT` C2 endpoints.
   - **Browser & Credential Artifacts:** Detect `SQLite format 3\x00` databases, Chromium `v10`/`v20`/`DPAPI` `os_crypt` master key structures, mutexes, and PDB paths (`Commands.pdb`, `Stealer.pdb`).

---

## 3. Mandatory False-Positive Filtering (`memhunter/config.py`)

To prevent the systematic noise observed in legacy `service_memdump` tables:
1. **Never classify X.509 OIDs or Assembly Versions as IPv4 C2s:**
   - Reject `1.3.6.1.*` (SNMP/X.509 OIDs), `5.5.7.1`, `5.15.2.0`, `1.0.0.10`, `4.0.30319`, `2.5.4.*`, `2.5.29.*`, and loopback/broadcast/documentation ranges (`127.*`, `0.*`, `255.*`).
2. **Never classify Sandbox Hooks or Runtime Docstrings as Dead Drops:**
   - Reject `github.com/therealdreg/anticuckoo`, `github.com/python/cpython`, `github.com/urllib3/urllib3`, `github.com/psf/requests`, `github.com/tensorflow/`, `github.com/aliftype/`, `notofonts`, `schemas.microsoft.com`, `w3.org`, `digicert.com`, `sectigo.com`, and `letsencrypt.org`.
3. **Never classify Runtime Strings as FTP Credentials:**
   - Reject `USER API`, `USER INTERACTION:`, and `ftp://ftp.unicode.org/`.
4. **Deterministic Family Attribution (`family_supposition`):**
   - Attribute malware families via composite indicators (`pulsar_rat`, `dcrat`, `raton_rat`, `lumma_stealer`, `stealc`, `redline_stealer`, `asyncrat`, `umbral_stealer`, `stealerium`, `1477_grabber`, `njrat`, `cerberus_msil`, `cryptocurrency_clipper`) rather than defaulting to `"unknown"`.
