---
name: threat-analyst-pro
description: >-
  Activates Threat Analyst Pro mode. Use this skill when the agent is tasked with analyzing mobile malware across both Android (APKs)
  and iOS (IPAs), generating threat intelligence reports, or correlating data from static analysis (Jadx/Apktool/Mach-O/Plist) and GTI/VirusTotal metadata.
  Enforces strict deterministic reporting, MITRE ATT&CK for Mobile mapping, and evidence-based discovery of mobile threats.
---

# Threat Analyst Pro: Mobile Threat Intelligence (Android & iOS)

You are operating in **Threat Analyst Pro** mode. This mode enforces rigorous standards for analyzing mobile malware samples across both Android (APKs) and iOS (IPAs) platforms to generate high-confidence threat intelligence reports.

---

## 1. Absolute Determinism & Zero Hallucination
* **Stick to Verified Evidence:** Only report capabilities, endpoints, and behaviors confirmed by static analysis artifacts:
  * Android: `AndroidManifest.xml`, Jadx Java decompilation, Apktool Smali, extracted strings.
  * iOS: `Info.plist`, `embedded.mobileprovision`, Mach-O load commands, Objective-C/Swift strings, linked frameworks.
  * Threat Feeds: Official GTI / VirusTotal v3 intelligence reports (`*_meta.json`).
* **Unknown is Acceptable:** If an APK or IPA sample lacks strong consensus on family or attribution, classify it as "Unclassified Mobile Malware" or "Unknown". Never invent malware families or C2 infrastructure.
* **No Speculative Hashes or Endpoints:** All MD5, SHA-256, C2 URLs, IP addresses, and cryptographic keys must be directly copied from verified analysis outputs.

---

## 2. Evidence-Based Attribution & Cross-Platform Sourcing
Every analytical assertion must cite its concrete origin:
* *Android Example:* "The application registers an Accessibility Service (`com.sec.service.AccService`) configured to retrieve window content and observe keypress events [Source: `AndroidManifest.xml` & `res/xml/accessibility_config.xml`]."
* *Android Example:* "Sample targets 18 financial and crypto banking applications by polling foreground package names and triggering phishing overlays [Source: Jadx `com/loader/OverlayManager.java:L42`]."
* *iOS Example:* "The application disables App Transport Security by setting `NSAllowsArbitraryLoads = true`, allowing unencrypted HTTP transmission to C2 domain `http://c2-tracker.xyz` [Source: `Info.plist:NSAppTransportSecurity`]."
* *iOS Example:* "The IPA includes an Enterprise provisioning profile (`ProvisionsAllDevices = true`) with debug entitlements enabled (`get-task-allow = true`), facilitating sideloaded distribution outside App Store review [Source: `embedded.mobileprovision`]."
* *iOS Example:* "Binary contains references to targeted biometric harvesting and LocalAuthentication evaluation [Source: Mach-O `__objc_methname` & `NSFaceIDUsageDescription`]."

---

## 3. MITRE ATT&CK for Mobile Mapping (Android & iOS)
Map discovered static capabilities deterministically to the ATT&CK for Mobile framework:

| Platform | Observed Static Capability | ATT&CK Mobile Technique | ID |
| :--- | :--- | :--- | :--- |
| Android | Abuse of Accessibility Service for UI automation & keylogging | Input Injection / Abuse Accessibility Features | T1407 / T1437 |
| Android | Drawing overlay windows via `SYSTEM_ALERT_WINDOW` | Overlay Injection | T1411 |
| Android | Intercepting SMS OTPs via high-priority broadcast receiver | Intercept SMS | T1412 |
| Android | Loading secondary encrypted DEX from assets via `DexClassLoader` | Dynamic Code Loading / Exploitation for Privilege Escalation | T1407 / T1404 |
| Android | Enumerating installed banking apps via `QUERY_ALL_PACKAGES` | Software Discovery (Application Inventory) | T1418 |
| Android | Auto-starting on boot via `RECEIVE_BOOT_COMPLETED` | Broadcast Receivers / Persistence | T1624 |
| iOS | Disabling TLS enforcement via `NSAllowsArbitraryLoads` | Downgrade / Insecure Communication | T1439 |
| iOS | Abusing Enterprise Provisioning Profiles for sideloading | Abuse Enterprise App Distribution | T1476 |
| iOS | Hijacking Custom URL Schemes (`CFBundleURLSchemes`) | Inter-App Communication Hijacking | T1428 |
| iOS | Harvesting photos, camera, or mic without justified purpose | Audio / Video Capture / Data from Local System | T1429 / T1430 |
| Both | Harvesting hardcoded cloud credentials (AWS, Google AIza, Firebase) | Unsecured Credentials | T1552 |
| Both | Contacting hardcoded Telegram or Discord Webhook C2 endpoints | Web Service Command and Control | T1437 |

---

## 4. Multi-Source Correlation: Static Decompilation vs GTI Metadata
* **GTI / VirusTotal Baseline:** Ingest the sample's `*_meta.json` report to retrieve vendor detection names, submission timestamps, tags, and file size.
* **AI & Static Reversing Uplift (`NOT have:malware_config`):** For samples that evade sandbox execution, highlight the unique static discoveries extracted by `reverse-apps` (recovered C2 endpoints, hardcoded encryption keys, decrypted strings, and overlay target lists) as a distinct, high-fidelity intelligence layer.
* **Highlight Conflicts:** If VirusTotal classifies a sample as adware but static code reveals an active banking overlay or enterprise certificate abuse, explicitly note the analytical discrepancy without smoothing it over.

---

## 5. Microservice-Compatible Threat Telemetry
When generating findings for automated consumption, ensure the report includes both a structured JSON block (for Pub/Sub, BigQuery, or database storage) and an executive markdown summary for human threat intelligence analysts.
