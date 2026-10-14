"""Kinetic Anti-Analysis, Evasion, and Sandbox Detection Scanner."""

from __future__ import annotations

import re
from ..models import AntiAnalysisFinding

EVASION_SIGNATURES: list[tuple[bytes, str, str]] = [
    # (Byte Pattern, Category, Technique Name)
    (b"IsDebuggerPresent", "anti_debug", "PEB BeingDebugged Check (IsDebuggerPresent)"),
    (b"CheckRemoteDebuggerPresent", "anti_debug", "Remote Debugger Check (CheckRemoteDebuggerPresent)"),
    (b"NtQueryInformationProcess", "anti_debug", "ProcessDebugPort Query (NtQueryInformationProcess)"),
    (b"ZwQueryInformationProcess", "anti_debug", "Native Debug Port Query (ZwQueryInformationProcess)"),
    (b"NtSetInformationThread", "anti_debug", "ThreadHideFromDebugger (NtSetInformationThread)"),
    (b"OutputDebugString", "anti_debug", "Debug Exception Handler (OutputDebugString)"),
    (b"ProcessDebugPort", "anti_debug", "ProcessDebugPort Flag Access"),
    (b"VBOX", "anti_vm", "VirtualBox Hypervisor String Check (VBOX)"),
    (b"VirtualBox", "anti_vm", "VirtualBox VM Environment Check"),
    (b"vboxguest", "anti_vm", "VirtualBox Guest Integration Driver Check"),
    (b"VMware", "anti_vm", "VMware Hypervisor Environment Check (VMware)"),
    (b"VMwareTools", "anti_vm", "VMware Guest Tools Detection"),
    (b"QEMU", "anti_vm", "QEMU Virtual Hardware Detection (QEMU)"),
    (b"Xen", "anti_vm", "Xen Hypervisor String Check"),
    (b"Hyper-V", "anti_vm", "Hyper-V Virtualization Detection"),
    (b"SbieDll", "anti_sandbox", "Sandboxie Isolation DLL Check (SbieDll)"),
    (b"anticuckoo", "anti_sandbox", "Cuckoo Sandbox Bypass (anticuckoo)"),
    (b"cuckoo", "anti_sandbox", "Cuckoo Sandbox Environment Check"),
    (b"wine_get_version", "anti_sandbox", "Wine Environment Detection (wine_get_version)"),
    (b"QueryPerformanceCounter", "timing", "Timing Attack / Sleep Acceleration Bypass (QPC)"),
    (b"GetTickCount", "timing", "Timing Attack (GetTickCount)"),
    (b"timeGetTime", "timing", "Multimedia Timer Evasion Check"),
    (b"Indirect hooking selected", "anti_hooking", "EDR Indirect Syscall / Hook Evasion"),
    (b"Hook watch enabled", "anti_hooking", "Memory Inline Hook Watchdog"),
    (b"x64dbg", "anti_debug", "Debugger Process Detection (x64dbg)"),
    (b"x32dbg", "anti_debug", "Debugger Process Detection (x32dbg)"),
    (b"ProcessHacker", "anti_debug", "Process Hacker Tool Detection"),
    (b"Wireshark", "anti_analysis", "Network Sniffer Detection (Wireshark)"),
    (b"Fiddler", "anti_analysis", "HTTP Proxy Detection (Fiddler)"),
]


class AntiAnalysisDetector:
    """Scans process memory for anti-analysis, anti-debugging, and anti-VM artifacts."""

    def __init__(self):
        self._signatures = EVASION_SIGNATURES

    def scan(self, buffer: bytes) -> list[AntiAnalysisFinding]:
        """Returns all detected anti-analysis mechanisms in the buffer."""
        findings: list[AntiAnalysisFinding] = []
        seen: set[str] = set()

        for pattern, category, technique in self._signatures:
            idx = buffer.find(pattern)
            if idx != -1:
                key = f"{category}:{pattern.decode('latin1', errors='ignore')}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        AntiAnalysisFinding(
                            technique=technique,
                            category=category,
                            indicator_string=pattern.decode("latin1", errors="ignore"),
                            offset=idx,
                        )
                    )

        return findings
