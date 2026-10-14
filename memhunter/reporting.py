"""
memhunter/reporting.py
Deterministic JSON and Markdown report builders for memory forensics findings.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple


def build_memdump_json_report(
    sha256: str,
    sandbox_sources: List[Dict[str, Any]],
    dump_inspections: List[Dict[str, Any]],
    carved: Dict[str, Any],
) -> Dict[str, Any]:
    """Build structured JSON report compatible with service_memdump and reverserk-ai."""
    return {
        "hash": sha256,
        "sha256": sha256,
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "family_supposition": carved.get("family_supposition", "generic_stealer_or_rat"),
        "sandbox_sources": [
            {
                "sandbox_id": s.get("sandbox_id"),
                "sandbox_name": s.get("sandbox_name"),
                "has_pcap": s.get("has_pcap"),
            }
            for s in sandbox_sources
        ],
        "minidump_files": dump_inspections,
        "pe_clr_summary": carved.get("pe_clr_summary", {}),
        "crypto_intel": carved.get("crypto_intel", {}),
        "extracted_c2": carved.get("extracted_c2", {}),
        "behaviour_intel": carved.get("behaviour_intel", {}),
        "sqlite_database_count": carved.get("sqlite_database_count", 0),
        "in_memory_strings": carved.get("in_memory_strings", []),
        "kinetic_forensics": carved.get("kinetic_forensics", {}),
    }


def build_memdump_markdown_report(report: Dict[str, Any]) -> str:
    """Render a human-readable forensic Markdown report for a single sample."""
    sha256 = report.get("sha256", "")
    family = report.get("family_supposition", "unknown")
    sandboxes = [s.get("sandbox_name") or s.get("sandbox_id") for s in report.get("sandbox_sources", [])]
    pe_clr = report.get("pe_clr_summary", {})
    c2 = report.get("extracted_c2", {})
    beh = report.get("behaviour_intel", {})
    crypto = report.get("crypto_intel", {})

    lines = [
        f"# Memory Dump Forensic Report: `{sha256[:16]}...`",
        "",
        "## 1. Executive Summary",
        f"- **SHA-256**: `{sha256}`",
        f"- **Attributed Family (`family_supposition`)**: **{family}**",
        f"- **Sandbox Memory Sources**: `{', '.join(sandboxes) or 'Local Dump'}`",
        f"- **Carved PE Headers in RAM**: `{pe_clr.get('pe_headers_carved', 0)}`",
        f"- **Carved .NET CLR (`BSJB`) Modules in RAM**: `{pe_clr.get('dotnet_clr_bsjb_carved', 0)}`",
        f"- **In-Memory SQLite3 Databases**: `{report.get('sqlite_database_count', 0)}`",
        "",
        "## 2. Carved C2 & Exfiltration Channels (`extracted_c2`)",
    ]

    webhooks = [w.get("value") for w in c2.get("webhooks", [])]
    ddrs = c2.get("ddr", [])
    wallets = c2.get("crypto_wallets", [])
    ips_urls = [x.get("value") for x in c2.get("ips_urls", [])]

    lines.append(f"- **Discord / Telegram Webhooks ({len(webhooks)})**:")
    for w in webhooks[:15]:
        lines.append(f"  - `{w}`")
    lines.append(f"- **Dead Drop Resolvers ({len(ddrs)})**:")
    for d in ddrs[:15]:
        resolved = f" -> Resolved: `{d['resolved_c2']}`" if d.get("resolved_c2") else ""
        lines.append(f"  - `{d.get('value')}`{resolved}")
    lines.append(f"- **Validated Clipper Wallets ({len(wallets)})**:")
    for w in wallets[:15]:
        lines.append(f"  - `{w}`")
    lines.append(f"- **Filtered Public C2 IPs / URLs ({len(ips_urls)})**:")
    for u in ips_urls[:25]:
        lines.append(f"  - `{u}`")

    lines.extend(
        [
            "",
            "## 3. In-Memory Behavioural & Cryptographic Intelligence",
            f"- **Crypto Primitives Detected**: `{', '.join(crypto.get('crypto_algorithms', [])) or 'None'}`",
            f"- **Chromium Master Key Indicators**: `{', '.join(crypto.get('chromium_master_keys', [])) or 'None'}`",
            f"- **Stealer Targets in RAM**: `{', '.join(beh.get('malware_targets', [])) or 'None'}`",
            f"- **Mutexes Carved**: `{', '.join(beh.get('mutexes', [])[:15]) or 'None'}`",
            f"- **PDB Paths Carved**: `{', '.join(beh.get('pdb_paths', [])[:10]) or 'None'}`",
        ]
    )

    json_cfgs = beh.get("extracted_c2_json_config", [])
    if json_cfgs:
        lines.append("")
        lines.append("## 4. Plaintext C2 JSON Configurations Carved from RAM")
        for cfg in json_cfgs:
            lines.append("```json")
            lines.append(json.dumps(cfg, indent=2))
            lines.append("```")

    return "\n".join(lines) + "\n"


def save_memdump_outputs(
    output_dir: Path,
    sha256: str,
    report_data: Dict[str, Any],
) -> Tuple[Path, Path]:
    """Persist `<sha256>_memdump.json` and `<sha256>_report.md` under `output_dir`."""
    configs_dir = Path(output_dir) / "configs"
    reports_dir = Path(output_dir) / "reports"
    configs_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    json_path = configs_dir / f"{sha256}_memdump.json"
    md_path = reports_dir / f"{sha256}_report.md"

    json_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(build_memdump_markdown_report(report_data), encoding="utf-8")
    return json_path, md_path
