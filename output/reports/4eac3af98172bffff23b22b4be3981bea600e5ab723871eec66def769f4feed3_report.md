# Memory Dump Forensic Report: `4eac3af98172bffff23b22b4be3981bea600e5ab723871eec66def769f4feed3`

## 1. Executive Summary
- **SHA-256**: `4eac3af98172bffff23b22b4be3981bea600e5ab723871eec66def769f4feed3`
- **Attributed Family (`family_supposition`)**: **redline_stealer**
- **Sandbox Memory Sources**: `CAPE Sandbox, Zenbox`
- **Carved PE Headers in RAM**: `8`
- **Carved .NET CLR (`BSJB`) Modules in RAM**: `2`
- **In-Memory SQLite3 Databases**: `0`

## 2. Carved C2 & Exfiltration Channels (`extracted_c2`)
- **Discord / Telegram Webhooks (0)**:
- **Dead Drop Resolvers (0)**:
- **Validated Clipper Wallets (0)**:
- **Filtered Public C2 IPs / URLs / WCF / WebSockets / .onion (2)**:
  - `31.77.12.184:5460`
  - `http://ip-api.com/json/`
- **Base64-Decoded In-Memory C2 Payloads (1)**:
  - `RedLine #US config: C2=31.77.12.184:5460 ID=hubzero Mutex=MVQrAdSxOFGcABA`

## 3. In-Memory Behavioural & Cryptographic Intelligence
- **Crypto Primitives Detected**: `ChaCha20_Salsa20_Sigma, RC4_SBox_Init, Windows_CNG_BCryptDecrypt, Windows_DPAPI_CryptUnprotectData`
- **Chromium Master Key Indicators**: `None`
- **Stealer Targets in RAM**: `Chromium Local State, Exodus, MetaMask, Phantom, Ronin`
- **Mutexes Carved**: `Global\HFCEgMpv5960, Global\vqyxYfsv, MVQrAdSxOFGcABA`
- **PDB Paths Carved**: `None`
