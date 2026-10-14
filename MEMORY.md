# Project Memory & Architectural Decisions (memhunter)

## 1. Context & Motivation
- **Why `memhunter` was created:**
  1. The external `service_memdump` consumer stopped ingesting new samples on `2026-10-07 13:01 UTC`, leaving new `has_memdump=True` samples from `reverserk-ai` campaigns (`KITM`, `Office04`, `ARBUZ`, `RedLine`) unprocessed.
  2. Auditing the 605 historical rows in `stealers_analysis.service_memdump` revealed four critical defects in the legacy scanner:
     - `family_supposition` was `"unknown"` in `605 / 605` rows (100%).
     - X.509 OIDs (`1.3.6.1`) and binary version strings (`5.5.7.1`, `5.15.2.0`, `1.0.0.10`) were misclassified as IPv4 C2s.
     - Sandbox hooks (`github.com/therealdreg/anticuckoo` in 318/605 samples) and Python docstrings (`github.com/python/cpython`, `urllib3`, `requests`) polluted `ddr`.
     - Runtime strings (`USER API`, `USER INTERACTION:`, `ftp://ftp.unicode.org/`) polluted `ftp_activity`.
- **Solution:**
  - `memhunter` provides a self-contained, portable memory dump downloader (`download_memdumps.py`) and an ephemeral Download -> Carve -> Purge analyzer (`analyze_memdumps.py`) that saves clean JSON (`output/configs/<sha256>_memdump.json`) and Markdown (`output/reports/<sha256>_report.md`) reports locally while deleting raw `.zip`/`.dmp` files immediately after analysis.

## 2. Key Technical Decisions
- **Ephemeral Disk Footprint:** Process memory dumps weigh 50 MB – 1.5 GB each. `EphemeralDumpWorkspace` guarantees 0 bytes of `.zip`/`.dmp` residue after each sample completes.
- **Portable Downloader (`download_memdumps.py`):** Engineered with zero internal package dependencies beyond `requests` and `python-dotenv` so it can be copied and executed standalone on any external VM.
- **Dead Drop Resolution:** Automatically resolves Pastebin (`pastebin.com/raw/*`) and Telegram dead drops found in process memory to concrete `IP:PORT` endpoints when reachable.
