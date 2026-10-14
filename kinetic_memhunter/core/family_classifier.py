"""Kinetic Infostealer Family Attribution and Classification Engine."""

from __future__ import annotations

import re
from typing import Any
from ..models import FamilyAttribution


class FamilyClassifier:
    """Classifies infostealer family from carved memory artifacts, mutexes, PDBs, and network telemetry."""

    def classify(
        self,
        mutexes: list[str],
        pdbs: list[str],
        c2_endpoints: list[str],
        anti_analysis: list[str],
        targets: list[str],
        vt_reference_family: str | None = None,
    ) -> FamilyAttribution:
        """Determines the malware family and provides confidence score and evidentiary reasons."""
        reasons: list[str] = []
        scores: dict[str, float] = {}

        def boost(family: str, weight: float, reason: str):
            scores[family] = scores.get(family, 0.0) + weight
            reasons.append(f"[{family}] {reason}")

        all_text = " ".join(mutexes + pdbs + c2_endpoints + targets).lower()

        # 1. QueenBee / BotGenStudio / Nitro Bot
        if any("botgenstudio" in p.lower() or "nitro" in p.lower() for p in pdbs):
            boost("QueenBee (BotGenStudio)", 0.60, "PDB path matches BotGenStudio / Nitro development tree")
        if any("fzymet" in m.lower() for m in mutexes):
            boost("QueenBee (BotGenStudio)", 0.35, "Mutex pattern Global\\FzYmEt matches QueenBee campaign")
        if any("pptplsa" in m.lower() for m in mutexes) or "pptplsa" in all_text:
            boost("QueenBee (BotGenStudio)", 0.25, "Process name pptplsa.exe matches QueenBee loader")

        # 2. Lumma Stealer
        if any("yltbnw" in m.lower() for m in mutexes):
            boost("Lumma Stealer", 0.50, "Mutex Global\\yLtBNw characteristic of Lumma Stealer")
        if any("anticuckoo" in c2.lower() for c2 in c2_endpoints):
            boost("Lumma Stealer", 0.20, "DDR / anti-cuckoo repository context indicative of Lumma loader")
        if any("/api" in c2.lower() for c2 in c2_endpoints):
            boost("Lumma Stealer", 0.15, "Standard Lumma /api exfiltration gateway")

        # 3. RedLine Stealer
        if any("net.tcp://" in c2.lower() for c2 in c2_endpoints):
            boost("RedLine Stealer", 0.60, "WCF net.tcp:// endpoint detected")
        if any("redline" in p.lower() for p in pdbs) or any("redline" in m.lower() for m in mutexes):
            boost("RedLine Stealer", 0.70, "Explicit RedLine identifier found")

        # 4. Vidar / Taurus Stealer
        if any("steamcommunity.com" in c2.lower() or "t.me" in c2.lower() for c2 in c2_endpoints):
            boost("Vidar Stealer", 0.30, "Dead Drop Resolver (Steam/Telegram) typical of Vidar/Taurus")
        if any("127.0.0.1" in c2 for c2 in c2_endpoints) and any("/gate" in c2 for c2 in c2_endpoints):
            boost("Vidar Stealer", 0.40, "Vidar killswitch and gate structure")

        # 5. Stealc
        if any("stealc" in p.lower() for p in pdbs) or any("stealc" in m.lower() for m in mutexes):
            boost("Stealc", 0.70, "Explicit Stealc artifact identified")

        # 6. AgentTesla
        if any("password_type integer" in t.lower() for t in targets):
            boost("AgentTesla", 0.35, "AgentTesla SQLite query signature (password_type INTEGER)")
        if any(t in ["7Star Browser", "Coowon Browser", "FileZilla FTP Client"] for t in targets) and any(
            "smtp" in c2.lower() or "ftp://" in c2.lower() for c2 in c2_endpoints
        ):
            boost("AgentTesla", 0.30, "Multi-browser target profile with FTP/SMTP exfiltration")

        # 7. FormBook / XLoader
        if any("formbook" in p.lower() for p in pdbs) or any("xloader" in p.lower() for p in pdbs):
            boost("FormBook / XLoader", 0.70, "FormBook/XLoader binary artifact")

        # 8. Cross-Reference with VirusTotal GTI data if available
        if vt_reference_family and vt_reference_family.lower() not in ["unknown", "none", ""]:
            vt_fam_norm = vt_reference_family.strip().lower()
            matching_key = None
            for key in scores:
                if vt_fam_norm in key.lower():
                    matching_key = key
                    break
            if matching_key:
                boost(matching_key, 0.40, f"Confirmed by VirusTotal GTI threat label: {vt_reference_family}")
            else:
                boost(vt_reference_family.capitalize(), 0.50, f"Attributed via VirusTotal GTI intelligence: {vt_reference_family}")

        if not scores:
            return FamilyAttribution(
                family_name="Generic Infostealer",
                confidence=0.50,
                attribution_reasons=["Targeted browser and credential stores identified in process memory"],
                vt_family_reference=vt_reference_family,
            )

        best_family = max(scores, key=lambda k: scores[k])
        confidence = min(0.98, max(0.40, scores[best_family]))

        # Filter relevant reasons
        filtered_reasons = [r for r in reasons if best_family in r or "VirusTotal" in r]

        return FamilyAttribution(
            family_name=best_family,
            confidence=round(confidence, 2),
            attribution_reasons=filtered_reasons,
            vt_family_reference=vt_reference_family,
        )
