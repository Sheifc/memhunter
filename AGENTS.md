# Autonomous Agent Operating Standards & Development Governance (memhunter)

This document establishes the mandatory technical guidelines, architectural standards, memory forensics rigor, and security constraints for AI agents developing and operating within the `memhunter` repository.

All agents operating in this repository MUST comply with the specifications defined herein, alongside the active skills in `.agents/skills/memhunter-forensics`, `.agents/skills/code-auditor-pro`, `.agents/skills/clean-domain-refactor`, and `.agents/skills/git-commit-pro`.

---

## 1. Conceptual Rigor: Offline Memory Dump Forensics & Ephemeral Storage

1. **Offline Memory Carving (Zero Live Execution):**
   - `memhunter` is a **strictly offline memory forensics and RAM carving microservice**. Under no circumstances are target malware binaries or carved PE/CLR modules executed or dynamically detonated.
   - All inputs are immutable process memory dump archives (`.zip` / `.dmp` from CAPE, Zenbox, or Jujubox sandboxes) and all outputs derive purely from binary stream parsing (`MDMP`), cryptographic S-Box detection, and structured artifact carving.
2. **Download-Analyze-Purge Lifecycle:**
   - Memory dump archives are large (`15 MB – 500+ MB` compressed, `100 MB – 1.5 GB` uncompressed).
   - Every worker run MUST download the dump into an ephemeral temporary directory governed by a Context Manager (`EphemeralDumpWorkspace`), carve the intelligence, persist the lightweight JSON/Markdown report (`output/configs/<sha256>_memdump.json` and `output/reports/<sha256>_report.md`), and **immediately delete the raw `.zip` and `.dmp` files**.
3. **No-Fallback Rule:**
   - Never fabricate findings or silently swallow extraction errors. Record structured diagnostics if a sandbox memdump is unavailable or corrupted.

---

## 2. Noise Immunity & False-Positive Elimination

Legacy memory scanners suffered from four systemic noise patterns that `memhunter` strictly eliminates:
1. **OID & Version String Exclusion in IPv4 Carving:** Reject X.509/ASN.1 OIDs (`1.3.6.1.*`, `2.5.4.*`, `2.5.29.*`) and runtime version strings (`5.5.7.1`, `5.15.2.0`, `1.0.0.10`, `4.0.30319`).
2. **Sandbox & Runtime URL Exclusion in Dead Drops:** Reject `github.com/therealdreg/anticuckoo`, `github.com/python/cpython`, `github.com/urllib3/urllib3`, `github.com/psf/requests`, `github.com/tensorflow/*`, `github.com/aliftype/*`, and font/certificate authority URLs.
3. **FTP False-Positive Filtering:** Reject `USER API`, `USER INTERACTION:`, and `ftp://ftp.unicode.org/`.
4. **High-Signal Family Attribution (`family_supposition`):** Combine PDB paths (`Commands.pdb`, `Stealer.pdb`), mutexes (`DcRatMutex_*`), JSON config schemas (`grabber_size_max` + `token`), and YARA/string markers to classify families deterministically.

---

## 3. Clean Domain Architecture & Testing

1. **Modular Decomposition (<300 lines per file):**
   - `memhunter/config.py`: Environment settings and false-positive blocklists.
   - `memhunter/workspace.py`: Ephemeral workspace context manager, Zip-Slip & Zip-Bomb guards.
   - `memhunter/downloader.py`: Portable VirusTotal v3 `/files/{sha256}/behaviours` -> `/file_behaviours/{sandbox_id}/memdump` client.
   - `memhunter/carvers/minidump.py`: `MDMP` header parser, `PECarver`, and `SBoxDetector`.
   - `memhunter/carvers/artifacts.py`: C2 JSON config carver, Discord/Telegram extractor, ETH/BTC wallet validator, DDR resolver, SQLite/DPAPI detector, and family classifier.
   - `memhunter/reporting.py`: JSON (`service_memdump` + `reverserk-ai` compatible) and Markdown report builders.
   - `memhunter/service.py`: Stateless Download -> Carve -> Purge orchestrator.
   - `download_memdumps.py`: Standalone portable CLI script runnable on any machine.
   - `analyze_memdumps.py`: Declarative CLI entrypoint for ephemeral batch carving.
2. **Hermetic Offline Testing (`tests/`):**
   - All unit tests must run in `< 5 seconds` with zero live network calls (`unittest.mock`).
