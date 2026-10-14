---
name: accidental-data-loss-prevention
description: |
  STOP AND VERIFY: Before running any command or tool that results in irreversible data loss, you MUST obtain explicit user consent.
  When in doubt, ask. It is better to wait for confirmation than to accidentally delete production datasets, mobile samples (APKs/IPAs), or critical project assets.
  Use this for:
  - Mobile Datasets: Mass deletion or truncation of data/mobile_samples/ (APKs, IPAs, metadata JSONs, mobileprovision files) or decompiler archives.
  - Cloud Storage: gsutil rm or gcloud storage rm targeting mobile sample repositories or analysis buckets.
  - Infrastructure: Deleting databases, Pub/Sub topics, or container instances storing analysis results.
  - Destructive Git operations: git reset --hard, git clean -fdx targeting uncommitted work.
license: Apache-2.0
metadata:
  version: v1
  publisher: google
---

# Accidental Data Loss Prevention

> [!CAUTION]
> STOP AND VERIFY: Before running any command or tool that results in
> irreversible data loss, you MUST obtain explicit user consent.

## Critical Assets in this Repository
1. **Mobile Sample Repository (`data/mobile_samples/`):** Contains collected APK and IPA binaries along with their corresponding GTI metadata JSON reports and provisioning profiles. Re-downloading consumes API quotas, rate limits, and significant network bandwidth. Never delete or overwrite without explicit confirmation.
2. **Analysis Toolchain (`tools/bin/`, `tools/jadx/`):** Pre-built decompiler binaries, JAR files (`jadx`, `apktool`), and disassemblers.
3. **Persistent Cloud Storage & Datastores:** Any Google Cloud Storage bucket or database storing analysis runs or microservice state.

## Mandatory Procedure

1. **Halt Execution**: Do not execute the destructive command.
2. **Request Consent**: Explain clearly to the user:
   - The **impact** of this deletion (e.g. "This will remove 500 downloaded APKs and IPAs from `data/mobile_samples/`").
   - **Why** you believe this is necessary.
   - A request for their **explicit approval** to proceed.
3. **Wait**: Only proceed if the user provides clear, affirmative consent in the conversation.
