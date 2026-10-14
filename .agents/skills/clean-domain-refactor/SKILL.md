---
name: clean-domain-refactor
description: >-
  Activates the Refactoring Architect mode using the "Clean Domain" pattern. Transforms massive God Functions and God Files into highly cohesive, maintainable, and cloud-native Python codebases without losing original business logic or heuristics. Tailored for mobile static reverse engineering microservices across Android and iOS.
---

# Skill: Python Refactoring & Modularization Architect ("Clean Domain" Pattern)

## Description

This skill transforms monolithic scripts and massive "God Files" (such as sprawling downloader scripts or monolithic multi-platform analyzers) into highly cohesive, maintainable, and **Cloud-Native / Microservice-Ready** Python architectures, guaranteeing that **business logic and mobile reverse engineering heuristics are never lost**.

---

## Fundamental Principles (The Core Rules)

### 1. Decomposition by Functional Domains (SRP)
* No file should exceed **300-400 lines** and no orchestrator function should exceed 30-40 lines.
* Divide responsibilities into independent, testable modules:
  * `config.py`: Environment configuration, constants, and validation models. **Mandatory Standard**: `.env.example` is the immutable single source of truth. Prohibit hardcoded paths, ports, or hidden defaults.
  * `workspace.py` / `storage.py`: Ephemeral working directories, temporary APK/IPA staging, safe extraction, and guaranteed teardown context managers.
  * `decompiler/`: Subprocess runners for external engines (`jadx`, `apktool`, `objdump`) enforcing memory limits and execution timeouts.
  * `analyzers/android/`: Pure static analyzers for Android (`AndroidManifest.xml`, Dalvik/Smali opcodes, native ELF `.so` libraries, commercial packer detection).
  * `analyzers/ios/`: Pure static analyzers for iOS (`Info.plist`, `embedded.mobileprovision`, Mach-O architecture slices, FairPlay DRM verification, linked frameworks).
  * `builders.py`: Pure functions dedicated exclusively to structuring normalized JSON reports, telemetry events, and MITRE ATT&CK for Mobile matrices.
  * `worker.py` / `service.py`: Headless microservice entrypoint, queue subscriber (e.g., Pub/Sub, Redis), or HTTP endpoint coordinator routing jobs by platform.

### 2. Lifecycle Management with Context Managers
* Eliminate fragile `try/except/finally` ladders for handling temporary decompiler trees and mobile package extractions by using **Context Managers (`__enter__` and `__exit__`)**.
* Guarantees atomic cleanup: regardless of whether analysis completes, times out, or crashes on malformed binaries, temporary directories in `/tmp` are wiped cleanly without leaking disk space.

### 3. Syntactic Density and Idiomatic Python
* Write concise, modern Python without sacrificing readability:
  * **Walrus Operator (`:=`)** to evaluate and bind variables inline during stream reads.
  * **List/Set/Dict Comprehensions** for high-throughput string and permission filtering.
  * **Set Operations (`&`, `|`, `-`)** to compare requested permissions, URL schemes, or detected ABIs instantly.

### 4. Isolation of Pure Analysis Logic
* Decouple all parsing, entropy calculations, regex scanning, and token matching from I/O or subprocess calls.
* Pure functions must have zero side effects, enabling rapid, hermetic unit testing without requiring real APK/IPA packages or decompiler binaries.

### 5. Microservice & Cloud-Native Adaptability
* Treat the runtime container as **stateless and ephemeral**:
  * Write only to designated temporary directories (`/tmp` or configured `TEMP_DIR`).
  * Decouple local artifact caching from cloud storage (GCS/S3) or event streaming (Pub/Sub).
  * Design every job to be **idempotent**, keyed by the sample's SHA-256 digest.

---

## Methodological Execution Plan (Step-by-Step)

When refactoring a monolithic mobile static reversing component:

1. **Responsibility Audit:** Map all distinct operations (e.g., GTI API querying, APK/IPA downloading, hash verification, Mach-O/Jadx parsing, IOC extraction).
2. **Configuration Extraction:** Move all environment variables, constants, and path resolvers to `config.py`, verified against `.env.example`.
3. **Workspace Abstraction:** Encapsulate ephemeral scratch directories and extraction folders in a dedicated `WorkspaceManager` context manager.
4. **Platform Decoupling:** Separate Android-specific and iOS-specific analysis logic into dedicated domain subpackages (`analyzers/android/`, `analyzers/ios/`).
5. **Pure Builder Extraction:** Move report generation and JSON assembly into pure builder functions with common schemas.
6. **Orchestrator Simplification:** Leave the main worker/script as a concise declarative coordinator that chains together the specialized domain modules.
7. **Regression Testing:** Run existing test suites (e.g., `pytest tests/`) to verify that zero behavior, signatures, or error contracts were broken.
