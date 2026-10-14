---
name: git-commit-pro
description: >-
  MANDATORY before creating any Git commit in this repository (git commit, amend, squash,
  or preparing a commit message), whether or not the user mentions this skill.
  Enforces the repository's semantic header conventions ([TYPE] scope: summary), structured
  Why/Key Changes body format, pre-commit validation, atomic changes, and strict secrets exclusion.
---

# Git Commit Pro: Standards & Best Practices

This skill outlines the strict standards for authoring Git commits in the **reverse-apps** repository. All commits must be high-signal, self-explanatory, auditable, and adhere to semantic conventions.

---

## 1. Commit Message Structure

Every commit message consists of three distinct components:
1. **Header**: Imperative title with semantic category tag and scope.
2. **Why (Rationale)**: High-level explanation of the problem, motivation, or architectural requirement.
3. **Key Changes (What)**: Bulleted breakdown of concrete edits.

```text
[TYPE] scope: imperative concise summary

Why:
- Explain the background, necessity, or problem addressed by this commit.
- Focus on architectural decisions, bug causality, or feature requirements.
- Answer: "Why was this change needed?"

Key Changes:
- path/to/component: Specific modification, function added, or contract change.
- path/to/config: Configuration update, environment variable change, or flag adjustment.
```

---

## 2. Header Conventions & Semantic Types

The header must not exceed **72 characters** and must follow the format:
`[TYPE] scope: imperative short summary`

### Permitted Semantic Types (`[TYPE]`):
* `[FEAT]`: A new feature, worker capability, or static analysis engine.
* `[FIX]`: A bug fix, decompiler error resolution, or timeout prevention.
* `[REFACTOR]`: Code restructuring, decomposition, or Clean Domain modularization.
* `[PERF]`: Performance enhancement, regex optimization, or concurrency tuning.
* `[CHORE]`: Routine maintenance, dependencies, toolchain updates (`jadx`/`apktool`), `.gitignore`.
* `[TEST]`: Adding, updating, or fixing offline unit or mock tests.
* `[DOCS]`: Documentation updates, architecture guides, or API specifications.

### Scope Guidelines (`scope`):
The scope must be lowercase, concise, and identify the primary component affected:
* **Toolchain & Setup:** `repo`, `tools`, `jadx`, `apktool`, `env`, `gitignore`, `docker`
* **Static Reversing Pipeline:** `downloader`, `triage`, `manifest`, `plist`, `macho`, `decompiler`, `worker`, `analyzer`, `iocs`, `dataset`, `service`
* **Platform Specifics:** `android`, `apk`, `dex`, `ios`, `ipa`, `provision`
* **Agentic & Quality:** `agents`, `auditor`, `threat-intel`, `documenter`
* **Testing & CI:** `tests`, `ci`

---

## 3. Atomic Commits & Pre-Commit Hygiene

Before running `git commit`, always execute the following hygiene checklist:

1. **Atomic Responsibility:**
   * A commit must address **one logical change**. Do not mix unrelated bug fixes with structural refactorings or cosmetic formatting.
2. **Review Staged Diff:**
   * Inspect exactly what is staged:
     ```bash
     git status -s
     git diff --staged
     ```
   * Ensure no untracked binaries, massive sample packages (`data/mobile_samples/*.apk`, `*.ipa`), temporary decompilation trees, or scratch files are committed.
3. **Validate Tests:**
   * Run the test suite offline before committing:
     ```bash
     pytest tests/
     ```
4. **Configuration Fidelity Check:**
   * Verify that any configuration changes maintain `.env.example` as the immutable single source of truth.

---

## 4. Strict Security & Secrets Prohibition

Under NO circumstances may sensitive data be committed:
* **Never Stage Private Tokens:** Never add `.env`, `GTI_KEY`, VirusTotal tokens, GCP service account JSON keys, or private SSH keys.
* **Inspect Ignore Rules:** Verify that `.gitignore` correctly filters temporary files (`__pycache__/`, `.pytest_cache/`, `download_waves.log`).

---

## 5. Reference Examples from Repository History

### Example 1: iOS Static Analysis Feature
```text
[FEAT] ios: implement Mach-O header triage and FairPlay DRM verification

Why:
- The static reversing microservice required support for iOS application packages (IPAs) alongside Android APKs.
- Analyzing App Store-encrypted binaries wastes compute resources; verifying cryptid before static disassembly is mandatory.

Key Changes:
- triage_ipa.py: Added pure Python Mach-O slice parser detecting arm64/arm64e architectures and LC_ENCRYPTION_INFO_64 status.
- triage_ipa.py: Added Info.plist and embedded.mobileprovision entitlement parser.
- triage_mobile_app.py: Created unified entrypoint auto-detecting APK vs IPA containers.
- extract_mobile_iocs.py: Extended regex scanning to include IPA bundles and iOS URL schemes.
```

### Example 2: Decompiler Worker Resilience
```text
[FIX] jadx: enforce memory limits and timeout handling in microservice worker

Why:
- Complex or obfuscated APKs containing anti-decompilation recursions caused Jadx subprocesses to hang indefinitely, depleting worker container memory and blocking the job queue.

Key Changes:
- tools/runner.py: Injected JAVA_OPTS="-Xmx4g" into Jadx execution environment and configured 300s subprocess timeout.
- pipeline/worker.py: Wrapped decompiler runner in a temporary workspace context manager ensuring /tmp staging trees are wiped on failure.
- tests/test_runner.py: Added unit test validating subprocess timeout handling and fallback telemetry.
```

### Example 3: Modular Refactoring
```text
[REFACTOR] analyzer: decouple manifest parsing from extraction worker

Why:
- The worker script combined network polling, APK unpacking, XML decoding, and IOC extraction into a single 600-line God File, violating Single Responsibility principles and preventing isolated testing.

Key Changes:
- analyzers/manifest.py: Extracted standalone AndroidManifest parser for permissions, intent filters, and exported components.
- analyzers/iocs.py: Moved regex-based C2 and API key extractors into pure functional modules.
- worker.py: Reduced main worker to a 40-line declarative orchestrator.
```
