"""Memory Analyzer Engine: Coordinates carving, detection, scoring, attribution, and MITRE mapping."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .comparator import BenchmarkComparator
from .core.anti_analysis_detector import AntiAnalysisDetector
from .core.api_hashing_detector import APIHashingDetector
from .core.archive_carver import ArchiveCarver
from .core.crypto_solver import CryptoSolver
from .core.deobfuscator import StealerDeobfuscator
from .core.dga_detector import DGADetector
from .core.family_classifier import FamilyClassifier
from .core.minidump_parser import MinidumpParser
from .core.mutex_carver import MutexCarver
from .core.network_c2_carver import NetworkC2Carver
from .core.pdb_carver import PDBCarver
from .core.pe_carver import PECarver
from .core.persistence_carver import PersistenceCarver
from .core.sbox_detector import SBoxDetector
from .core.sqlite_carver import SQLiteCarver
from .core.stealer_extractor import StealerArtifactExtractor
from .core.stealer_target_detector import StealerTargetDetector
from .models import (
    CredentialCategory,
    FamilyAttribution,
    MemoryAnalysisReport,
    PrimitiveType,
    SampleAnalysisReport,
    StealerCredentialFinding,
)


class MemoryAnalyzer:
    """End-to-end memory dump analysis and forensic extraction engine."""

    def __init__(
        self,
        enable_sbox: bool = True,
        enable_pe: bool = True,
        enable_archives: bool = True,
        enable_credentials: bool = True,
        enable_solver: bool = True,
        enable_deobfuscator: bool = True,
    ):
        self.sbox_detector = SBoxDetector() if enable_sbox else None
        self.pe_carver = PECarver() if enable_pe else None
        self.archive_carver = ArchiveCarver() if enable_archives else None
        self.credential_extractor = StealerArtifactExtractor() if enable_credentials else None
        self.crypto_solver = CryptoSolver() if enable_solver else None
        self.enable_deobfuscator = enable_deobfuscator

        # Advanced forensic extractors
        self.mutex_carver = MutexCarver()
        self.pdb_carver = PDBCarver()
        self.anti_analysis_detector = AntiAnalysisDetector()
        self.network_carver = NetworkC2Carver()
        self.persistence_carver = PersistenceCarver()
        self.api_hashing_detector = APIHashingDetector()
        self.sqlite_carver = SQLiteCarver()
        self.dga_detector = DGADetector()
        self.stealer_target_detector = StealerTargetDetector()
        self.family_classifier = FamilyClassifier()
        self.comparator = BenchmarkComparator()

    def analyze_bytes(
        self,
        buffer: bytes,
        target_name: str = "memory_buffer",
        sample_context: dict[str, Any] | None = None,
        vt_reference_family: str | None = None,
    ) -> MemoryAnalysisReport:
        buf_len = len(buffer)
        sha256 = hashlib.sha256(buffer).hexdigest()
        sample_context = sample_context or {}

        # Extract context keys if available
        context_keys = []
        for k in ("config_strings", "keys", "interesting_strings"):
            if k in sample_context and isinstance(sample_context[k], list):
                context_keys.extend(str(x) for x in sample_context[k])

        # 0. Minidump Header & Module Extraction
        minidump = MinidumpParser(buffer)
        loaded_modules = []
        if minidump.is_minidump:
            for mod in minidump.extract_modules():
                loaded_modules.append(f"{mod.module_name} (0x{mod.base_of_image:X})")

        # 1. Cryptographic S-Box & Primitive Detection
        crypto_primitives = self.sbox_detector.scan(buffer) if self.sbox_detector else []

        # 2. In-memory Executable PE Carving
        carved_pes = self.pe_carver.scan(buffer) if self.pe_carver else []

        # 3. Compressed Payload & Archive Carving
        carved_archives = self.archive_carver.scan(buffer) if self.archive_carver else []

        # 4. Stealer Credentials & Developer Tokens Extraction
        credentials = self.credential_extractor.scan(buffer) if self.credential_extractor else []

        # 5. In-Memory Deobfuscation & String/C2 Carving
        c2_urls: list[str] = []
        browser_profiles: list[str] = []
        if self.enable_deobfuscator:
            deobf = StealerDeobfuscator(context_keys=context_keys)
            deobf_res = deobf.deobfuscate(buffer)
            c2_urls = deobf_res.get("c2_urls", [])
            browser_profiles = deobf_res.get("browser_profiles_targeted", [])
            for cred in deobf_res.get("extracted_credentials", []):
                if cred not in credentials:
                    credentials.append(cred)

        # 6. Advanced Specialized Carvers
        mutexes = self.mutex_carver.scan(buffer)
        pdb_paths = self.pdb_carver.scan(buffer)
        anti_analysis = self.anti_analysis_detector.scan(buffer)
        network_findings = self.network_carver.scan(buffer)
        persistence = self.persistence_carver.scan(buffer)
        api_hashing = self.api_hashing_detector.scan(buffer)
        sqlite_carved = self.sqlite_carver.scan(buffer)
        dga_alphabets = self.dga_detector.scan(buffer)
        stealer_targets, targeted_paths = self.stealer_target_detector.scan(buffer)

        # Add network finding URLs to c2_urls
        for net in network_findings:
            if net.value not in c2_urls:
                c2_urls.append(net.value)

        # Add carved sqlite emails as credentials
        for sql in sqlite_carved:
            for rec in sql.records_preview:
                if "Carved Email: " in rec:
                    em = rec.replace("Carved Email: ", "").strip()
                    cred_finding = StealerCredentialFinding(
                        category=CredentialCategory.EMAIL_ADDRESS,
                        platform="SQLite Database Fragment",
                        match_value=em,
                        offset=sql.offset,
                        context_snippet=f"Extracted from in-memory SQLite table fragment at offset 0x{sql.offset:x}",
                    )
                    if cred_finding not in credentials:
                        credentials.append(cred_finding)

        # 7. In-flight Key Discovery & Decryption
        decrypted_regions = (
            self.crypto_solver.solve(buffer, crypto_primitives)
            if (self.crypto_solver and crypto_primitives)
            else []
        )

        # 8. Scoring & MITRE ATT&CK Mapping
        score = 0
        mitre_map: dict[str, str] = {}

        if crypto_primitives:
            score += min(len(crypto_primitives) * 15, 30)
            mitre_map["T1027"] = "Obfuscated/Encrypted Files or Information: Active cryptographic S-Box primitives in memory"

        if carved_pes:
            score += min(len(carved_pes) * 20, 40)
            mitre_map["T1055"] = "Process Injection: Unmapped/reflective PE injection detected in process address space"

        if carved_archives:
            score += min(len(carved_archives) * 15, 30)
            mitre_map["T1560"] = "Archive Collected Data: In-memory compressed staging archive for exfiltration"

        if browser_profiles or stealer_targets:
            score += min((len(browser_profiles) + len(stealer_targets)) * 10, 30)
            mitre_map["T1555"] = "Credentials from Password Stores: Targeted browser credential database structures"

        if c2_urls or network_findings:
            score += 25
            mitre_map["T1071"] = "Application Layer Protocol: Discovered in-flight C2 communication endpoints"

        if any(net.endpoint_type == "FTP" for net in network_findings):
            score += 15
            mitre_map["T1048"] = "Exfiltration Over Alternative Protocol: Direct FTP exfiltration channel"

        if anti_analysis:
            score += min(len(anti_analysis) * 5, 20)
            mitre_map["T1497"] = "Virtualization/Sandbox Evasion: Anti-Analysis and debugger evasion checks"

        if persistence:
            score += 15
            mitre_map["T1547"] = "Boot or Logon Autostart Execution: Registry/COM Persistence mechanisms"

        if mutexes:
            score += 10

        if credentials:
            score += min(len(credentials) * 25, 50)
            cats = {c.category for c in credentials}
            if CredentialCategory.AI_DEVELOPER_SESSION in cats:
                mitre_map["T1539"] = "Steal Web Session Cookie: AI platform developer sessions extracted"
                mitre_map["T1552"] = "Unsecured Credentials: AI API keys extracted from memory"
            if CredentialCategory.BROWSER_MASTER_KEY in cats or CredentialCategory.PASSWORD_RECORD in cats:
                mitre_map["T1555"] = "Credentials from Password Stores: Browser master keys or DPAPI structures carved"
            if CredentialCategory.CRYPTO_WALLET in cats:
                mitre_map["T1005"] = "Data from Local System: Crypto wallet credentials staged in memory"
            if CredentialCategory.TELEGRAM_SESSION in cats:
                mitre_map["T1567"] = "Exfiltration Over Web Service: Telegram bot API exfiltration token discovered"

        if decrypted_regions:
            score += 20

        score = min(score, 100)

        # Verdict assignment
        if score >= 60:
            verdict = "CONFIRMED_INFOSTEALER"
        elif score >= 30:
            verdict = "SUSPICIOUS_MEMORY_ACTIVITY"
        else:
            verdict = "BENIGN"

        summary = {
            "crypto_primitives_count": len(crypto_primitives),
            "carved_pes_count": len(carved_pes),
            "carved_archives_count": len(carved_archives),
            "credentials_count": len(credentials),
            "decrypted_regions_count": len(decrypted_regions),
            "c2_urls_count": len(c2_urls),
            "modules_loaded_count": len(loaded_modules),
            "browser_profiles_count": len(browser_profiles),
            "mutexes_count": len(mutexes),
            "pdb_paths_count": len(pdb_paths),
            "anti_analysis_count": len(anti_analysis),
            "persistence_count": len(persistence),
            "api_hashing_count": len(api_hashing),
            "sqlite_carved_count": len(sqlite_carved),
        }

        mitre_list = [{"id": k, "name": v} for k, v in sorted(mitre_map.items())]

        # 9. Infostealer Family Attribution
        attribution = self.family_classifier.classify(
            mutexes=[m.name for m in mutexes],
            pdbs=[p.pdb_path for p in pdb_paths],
            c2_endpoints=c2_urls,
            anti_analysis=[a.indicator_string for a in anti_analysis],
            targets=stealer_targets,
            vt_reference_family=vt_reference_family,
        )

        return MemoryAnalysisReport(
            target_name=target_name,
            file_size_bytes=buf_len,
            sha256=sha256,
            threat_score=score,
            threat_verdict=verdict,
            family_attribution=attribution,
            mitre_techniques=mitre_list,
            summary=summary,
            modules_loaded=loaded_modules[:50],
            c2_urls=c2_urls[:30],
            browser_profiles_targeted=browser_profiles + targeted_paths,
            sample_context=sample_context,
            crypto_primitives=crypto_primitives,
            carved_pes=carved_pes,
            carved_archives=carved_archives,
            credentials=credentials,
            decrypted_regions=decrypted_regions,
            mutexes=mutexes,
            pdb_paths=pdb_paths,
            anti_analysis=anti_analysis,
            network_c2=network_findings,
            persistence=persistence,
            api_hashing=api_hashing,
            sqlite_carved=sqlite_carved,
            dga_alphabets=dga_alphabets,
            stealer_targets=stealer_targets,
        )

    def analyze_file(
        self,
        file_path: Path | str,
        sample_context: dict[str, Any] | None = None,
        vt_reference_family: str | None = None,
    ) -> MemoryAnalysisReport:
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Memory dump file not found: {p}")
        with open(p, "rb") as f:
            data = f.read()
        return self.analyze_bytes(
            data,
            target_name=p.name,
            sample_context=sample_context,
            vt_reference_family=vt_reference_family,
        )

    def analyze_sample_dumps(
        self,
        dump_paths: list[Path | str],
        sample_hash: str,
        vt_reference_family: str | None = None,
    ) -> SampleAnalysisReport:
        """Analyzes all process memory dumps for a given malware sample and aggregates telemetry."""
        process_reports: list[MemoryAnalysisReport] = []
        process_names: list[str] = []

        all_mutexes: set[str] = set()
        all_pdbs: set[str] = set()
        all_c2: set[str] = set()
        all_anti: set[str] = set()
        all_clsids: set[str] = set()
        all_persistence: set[str] = set()
        all_targets: set[str] = set()
        all_credentials: list[StealerCredentialFinding] = []
        all_sqlite: list[Any] = []
        all_crypto: set[str] = set()
        all_api_hash: set[str] = set()
        all_dga: set[str] = set()
        aggregated_mitre: dict[str, str] = {}

        for dp in dump_paths:
            p = Path(dp)
            if not p.is_file():
                continue
            rep = self.analyze_file(p, vt_reference_family=vt_reference_family)
            process_reports.append(rep)
            process_names.append(p.name)

            for m in rep.mutexes:
                all_mutexes.add(m.name)
            for pdb in rep.pdb_paths:
                all_pdbs.add(pdb.pdb_path)
            for c2 in rep.c2_urls:
                all_c2.add(c2)
            for net in rep.network_c2:
                all_c2.add(net.value)
            for anti in rep.anti_analysis:
                all_anti.add(anti.technique)
            for pst in rep.persistence:
                all_persistence.add(pst.target_value)
                if pst.persistence_type == "COM_CLSID":
                    all_clsids.add(pst.target_value)
            for tgt in rep.stealer_targets:
                all_targets.add(tgt)
            for bp in rep.browser_profiles_targeted:
                all_targets.add(bp)
            for cred in rep.credentials:
                if cred not in all_credentials:
                    all_credentials.append(cred)
            for sql in rep.sqlite_carved:
                all_sqlite.append(sql)
            for cp in rep.crypto_primitives:
                all_crypto.add(cp.primitive.value)
            for ah in rep.api_hashing:
                all_api_hash.add(ah.disassembly_snippet)
            for dga in rep.dga_alphabets:
                all_dga.add(dga.alphabet)
            for mtr in rep.mitre_techniques:
                aggregated_mitre[mtr["id"]] = mtr["name"]

        # Attribution across all processes
        attribution = self.family_classifier.classify(
            mutexes=list(all_mutexes),
            pdbs=list(all_pdbs),
            c2_endpoints=list(all_c2),
            anti_analysis=list(all_anti),
            targets=list(all_targets),
            vt_reference_family=vt_reference_family,
        )

        max_score = max((r.threat_score for r in process_reports), default=90)
        verdict = "CONFIRMED_INFOSTEALER" if max_score >= 60 else "SUSPICIOUS_MEMORY_ACTIVITY"

        # Compare with reference report and VT
        comparison = self.comparator.compare(
            sample_hash=sample_hash,
            our_mutexes=list(all_mutexes),
            our_c2s=list(all_c2),
            our_pdbs=list(all_pdbs),
            our_anti_analysis=list(all_anti),
            our_persistence=list(all_persistence),
            our_family=attribution.family_name,
            our_credentials_count=len(all_credentials),
            our_sqlite_count=len(all_sqlite),
        )

        mitre_list = [{"id": k, "name": v} for k, v in sorted(aggregated_mitre.items())]

        return SampleAnalysisReport(
            sample_hash=sample_hash,
            total_processes_analyzed=len(process_reports),
            process_names=process_names,
            threat_verdict=verdict,
            threat_score=max_score,
            family_attribution=attribution,
            mitre_techniques=mitre_list,
            all_mutexes=sorted(list(all_mutexes)),
            all_pdbs=sorted(list(all_pdbs)),
            all_c2_endpoints=sorted(list(all_c2)),
            all_anti_analysis=sorted(list(all_anti)),
            all_clsids=sorted(list(all_clsids)),
            all_persistence=sorted(list(all_persistence)),
            all_stealer_targets=sorted(list(all_targets)),
            all_credentials=all_credentials,
            all_sqlite_databases=all_sqlite,
            all_crypto_primitives=sorted(list(all_crypto)),
            all_api_hashing=sorted(list(all_api_hash)),
            all_dga_alphabets=sorted(list(all_dga)),
            process_reports=process_reports,
            benchmark_comparison=comparison,
        )
