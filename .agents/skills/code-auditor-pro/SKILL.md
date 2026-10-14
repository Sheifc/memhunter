---
name: code-auditor-pro
description: >-
  Use when the user asks to audit, review or assess code, a diff, a commit or the repository
  (quality, security, isolation, microservice reliability, static reversing integrity).
  Produces evidence-based findings with impact and exact fixes tailored for mobile static reverse engineering pipelines (Android & iOS).
---

# Code Auditor Pro: Mobile Reverse Engineering Microservice

Audit code, diffs, pull requests, or the entire repository against the security, architectural, and operational standards of the **reverse-apps** mobile static analysis microservice (covering both Android APKs and iOS IPAs). Report only findings supported by concrete evidence.

---

## Core Audit Pillars

### 1. Untrusted Sample Input & Archive Security (Android & iOS)
* **Strict Static Purity:** Verify that sample APKs, IPAs, DEX bytecode, and native binaries (ELF `.so` or Mach-O) are **never executed, dynamically loaded, or evaluated**. Analysis must remain 100% static and sandboxed.
* **Zip-Slip & Path Traversal:** When reading or extracting APK or IPA entries (including `Payload/` bundles), verify that destination file paths are strictly validated against directory traversal (i.e. `resolved_target.startswith(target_dir)`).
* **Zip-Bomb & Decompression Limits:** Guard against adversarial compression ratios in both APK and IPA archives. Ensure uncompressed entry sizes and total extraction sizes are checked before unpacking.
* **Binary Property List & XML Parser Safety:** Ensure XML and binary plist parsing logic cannot be exploited via XML External Entity (XXE) injection or recursive entity expansions (Billion Laughs attack).
* **Subprocess Security:** Inspect all external command calls (`jadx`, `apktool`, `objdump`). Prohibit `shell=True`. Arguments must be passed as validated lists (`[bin_path, "-d", out_dir, ...]`) with sample paths properly resolved.

### 2. Microservice Reliability & Resource Bounds
* **JVM & Memory Bounds:** Ensure invocations of Java-based decompilers (`jadx`, `apktool`) explicitly set `-Xmx` (e.g. `JAVA_OPTS="-Xmx4g"`). Unbounded processes will trigger container OOM kills.
* **FairPlay DRM Validation (iOS):** Verify that iOS analysis pipelines check Mach-O `LC_ENCRYPTION_INFO_64` (`cryptid`) before attempting disassembly or string extraction. Flag encrypted App Store binaries early to avoid wasted compute cycles.
* **Subprocess Timeouts:** Every external decompiler or disassembler execution must specify a strict `timeout` parameter and handle `subprocess.TimeoutExpired` without crashing the parent worker or leaking child processes.
* **Ephemeral Workspace Teardown:** Ensure decompiled source trees, extracted IPA payloads, and temporary files in `/tmp` are managed via context managers and purged upon job completion or error.
* **Graceful Shutdown:** Verify that workers capture `SIGTERM` and `SIGINT` to cleanly complete or discard in-flight analysis jobs before container eviction.

### 3. Secrets, Credentials, & Token Hygiene
* **Zero Hardcoding:** No GTI API keys, VirusTotal tokens, Google Cloud service accounts, or private credentials committed, logged, or printed.
* **Header / Secret Masking:** API authentication headers and tokens must be masked in logs.
* **Credential Isolation:** Service credentials must reside exclusively in `.env` (ignored by VCS) or mounted secret volumes with restricted read permissions (`chmod 600`).

### 4. Code Standards & Architecture
* **Single Source of Truth (`.env.example`):** All configurations, timeouts, and directories must derive from `.env.example`. Reject invented fallback aliases, shadow classes, or hardcoded local paths.
* **Clean Domain Structure:** Enforce Separation of Concerns between microservice ingress (HTTP/PubSub), workspace lifecycle, platform analyzers (`android/`, `ios/`), and report builders.
* **Error Handling Context:** Catch specific exceptions (e.g. `zipfile.BadZipFile`, `plistlib.InvalidFileException`, `subprocess.TimeoutExpired`, `FileNotFoundError`) and include sample SHA-256 context in error logs.

### 5. Verification Integrity & Hermetic Testing
* **Checks Must Be Able to Fail:** Flag silenced exceptions (`except: pass` or `|| true`), skipped assertions, or relaxed validations.
* **Hermetic Offline Testing:** Unit and integration tests in `tests/` must remain completely offline and mock all external API requests (e.g. GTI / VirusTotal API). Tests must never make live outbound network calls.

---

## Methodology

1. **Collect Evidence First:** Read the actual source code, diff, or system state. Never base a finding on assumptions or file names.
2. **Structure Each Finding:**
   * **Location:** File and line range (`path/to/file.py:L10-L25`).
   * **Severity:** Blocking (Security / Data Loss / Worker Crash) | Should Fix (Reliability / Architecture) | Minor (Style / Cleanliness).
   * **Concrete Impact:** Explain the specific failure mode (e.g., "A malicious IPA with `../../` in a payload zip entry will overwrite host files", "Missing timeout will cause worker to hang indefinitely on obfuscated DEX").
   * **Exact Fix:** Provide the precise code replacement.
3. **Language Standards:** Findings, technical descriptions, and code are written in English; the executive summary follows the user's preferred language.
