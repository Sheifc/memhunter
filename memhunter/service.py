"""
memhunter/service.py
Stateless orchestrator implementing the Download -> Carve (memhunter + kinetic_memhunter) -> Delete -> Report lifecycle.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

from kinetic_memhunter.analyzer import MemoryAnalyzer
from memhunter.carvers.artifacts import carve_memory_buffers
from memhunter.carvers.minidump import inspect_dump_file
from memhunter.config import (
    DEFAULT_BASE_URL,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_TMP_DIR,
    is_benign_or_sandbox_url,
)
from memhunter.downloader import download_behaviour_memdump_zip, list_memdump_behaviours
from memhunter.reporting import build_memdump_json_report, save_memdump_outputs
from memhunter.workspace import EphemeralDumpWorkspace

logger = logging.getLogger("memhunter.service")


def _extract_kinetic_summary(kinetic_report: Any) -> Dict[str, Any]:
    """Serialize deep kinetic_memhunter SampleAnalysisReport into a clean dict."""
    clean_c2s = [
        c for c in getattr(kinetic_report, "all_c2_endpoints", [])
        if not is_benign_or_sandbox_url(str(c))
    ]
    creds = []
    for c in getattr(kinetic_report, "all_credentials", [])[:50]:
        creds.append(
            {
                "category": getattr(c.category, "value", str(c.category)),
                "platform": c.platform,
                "value": c.match_value[:160],
                "confidence": c.confidence,
            }
        )
    sql_dbs = []
    for s in getattr(kinetic_report, "all_sqlite_databases", [])[:25]:
        sql_dbs.append(
            {
                "offset": getattr(s, "offset", 0),
                "page_size": getattr(s, "page_size", 0),
                "tables": getattr(s, "tables_detected", []),
            }
        )
    attr = getattr(kinetic_report, "family_attribution", None)
    return {
        "threat_verdict": getattr(kinetic_report, "threat_verdict", "UNKNOWN"),
        "threat_score": getattr(kinetic_report, "threat_score", 0),
        "kinetic_family": getattr(attr, "family_name", "Unknown") if attr else "Unknown",
        "kinetic_confidence": getattr(attr, "confidence_score", 0.0) if attr else 0.0,
        "mitre_techniques": getattr(kinetic_report, "mitre_techniques", []),
        "anti_analysis": getattr(kinetic_report, "all_anti_analysis", []),
        "persistence": getattr(kinetic_report, "all_persistence", []),
        "com_clsids": getattr(kinetic_report, "all_clsids", []),
        "api_hashing": getattr(kinetic_report, "all_api_hashing", [])[:25],
        "dga_alphabets": getattr(kinetic_report, "all_dga_alphabets", [])[:25],
        "credentials": creds,
        "sqlite_databases": sql_dbs,
        "crypto_primitives": getattr(kinetic_report, "all_crypto_primitives", []),
        "c2_endpoints": clean_c2s[:100],
    }


def analyze_sample_memdump(
    sha256: str,
    api_key: str,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    base_url: str = DEFAULT_BASE_URL,
    tmp_dir: Path = DEFAULT_TMP_DIR,
    resolve_ddr: bool = False,
    local_zip_or_dmp: Path | None = None,
) -> Dict[str, Any]:
    """
    Download all available sandbox memory dumps for sha256 into an ephemeral workspace,
    carve C2s/configs/artifacts with both memhunter and kinetic_memhunter engines,
    automatically delete all .zip/.dmp files on exit, and persist JSON + Markdown reports.
    """
    clean_sha = sha256.lower().strip()
    sandbox_sources: List[Dict[str, Any]] = []
    dump_inspections: List[Dict[str, Any]] = []

    with EphemeralDumpWorkspace(clean_sha, base_tmp_dir=tmp_dir) as ws:
        assert ws.work_dir is not None
        extracted_dumps: List[Path] = []

        if local_zip_or_dmp and local_zip_or_dmp.exists():
            if local_zip_or_dmp.suffix.lower() == ".zip":
                temp_copy = ws.work_dir / local_zip_or_dmp.name
                temp_copy.write_bytes(local_zip_or_dmp.read_bytes())
                extracted_dumps.extend(ws.safe_extract_zip(temp_copy))
            else:
                extracted_dumps.append(local_zip_or_dmp)
            sandbox_sources.append({"sandbox_id": f"{clean_sha}_local", "sandbox_name": "Local", "has_pcap": False})
        else:
            sandbox_sources = list_memdump_behaviours(clean_sha, api_key=api_key, base_url=base_url)
            if not sandbox_sources:
                logger.warning("[%s] No sandbox behaviours with has_memdump=True found.", clean_sha)
                return {"sha256": clean_sha, "status": "no_memdump_available", "sandbox_sources": []}

            for sb in sandbox_sources[:2]:
                sb_id = sb["sandbox_id"]
                logger.info("[%s] Downloading memdump from %s...", clean_sha[:12], sb_id)
                zip_path = download_behaviour_memdump_zip(
                    sandbox_id=sb_id,
                    dest_dir=ws.work_dir,
                    api_key=api_key,
                    base_url=base_url,
                )
                if zip_path and zip_path.is_file():
                    members = ws.safe_extract_zip(zip_path)
                    extracted_dumps.extend(members)
                    if extracted_dumps:
                        break

        if not extracted_dumps:
            return {"sha256": clean_sha, "status": "empty_memdump", "sandbox_sources": sandbox_sources}

        for dmp in extracted_dumps:
            dump_inspections.append(inspect_dump_file(dmp))

        carved = carve_memory_buffers(extracted_dumps, resolve_ddr=resolve_ddr)

        kinetic_analyzer = MemoryAnalyzer()
        kinetic_rep = kinetic_analyzer.analyze_sample_dumps(
            [p for p in extracted_dumps if p.stat().st_size <= 250 * 1024 * 1024],
            sample_hash=clean_sha,
        )
        carved["kinetic_forensics"] = _extract_kinetic_summary(kinetic_rep)

        if (
            carved.get("family_supposition") in (None, "unknown", "generic_stealer_or_rat")
            and carved["kinetic_forensics"]["kinetic_family"] not in ("Unknown", "Generic Stealer")
        ):
            carved["family_supposition"] = carved["kinetic_forensics"]["kinetic_family"].lower().replace(" ", "_")

        for dmp in extracted_dumps:
            if ws.work_dir in dmp.parents:
                dmp.unlink(missing_ok=True)

    report_data = build_memdump_json_report(
        sha256=clean_sha,
        sandbox_sources=sandbox_sources,
        dump_inspections=dump_inspections,
        carved=carved,
    )
    json_path, md_path = save_memdump_outputs(output_dir=output_dir, sha256=clean_sha, report_data=report_data)
    logger.info(
        "[%s] Analysis complete (family=%s) -> %s (raw .dmp purged)",
        clean_sha[:12],
        report_data["family_supposition"],
        json_path.name,
    )
    return {
        "sha256": clean_sha,
        "status": "ok",
        "family_supposition": report_data["family_supposition"],
        "json_path": str(json_path),
        "md_path": str(md_path),
        "report": report_data,
    }
