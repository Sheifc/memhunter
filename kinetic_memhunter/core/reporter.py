"""Forensic Report Formatter for Kinetic MemHunter."""

from __future__ import annotations


def format_report_markdown(report_dict: dict) -> str:
    md = [
        "# Kinetic MemHunter Forensic Report",
        f"- **Target File**: `{report_dict.get('target_name')}`",
        f"- **Size**: {report_dict.get('file_size_bytes', 0):,} bytes",
        f"- **SHA256**: `{report_dict.get('sha256')}`",
        f"- **Verdict**: **{report_dict.get('threat_verdict')}** (Score: {report_dict.get('threat_score', 0)}/100)",
        "",
        "## Summary of Findings",
        f"- **Cryptographic Primitives / S-Boxes**: {len(report_dict.get('crypto_primitives', []))}",
        f"- **Carved Executable PEs**: {len(report_dict.get('carved_pes', []))}",
        f"- **Carved Staging Archives**: {len(report_dict.get('carved_archives', []))}",
        f"- **Stealer Credentials & Tokens**: {len(report_dict.get('credentials', []))}",
        f"- **Decrypted In-Flight Regions**: {len(report_dict.get('decrypted_regions', []))}",
        f"- **Discovered C2 Endpoints**: {len(report_dict.get('c2_urls', []))}",
        "",
        "## MITRE ATT&CK Mapping",
    ]
    for m in report_dict.get("mitre_techniques", []):
        md.append(f"- **{m.get('id')}**: {m.get('name')}")

    if report_dict.get("crypto_primitives"):
        md.append("\n## Cryptographic Primitives")
        for p in report_dict["crypto_primitives"]:
            md.append(f"- **{p['primitive']}** at offset `0x{p['offset']:X}` (Entropy: {p['entropy']})")

    if report_dict.get("credentials"):
        md.append("\n## Extracted Credentials & Developer Tokens")
        for c in report_dict["credentials"]:
            md.append(f"- `[{c['category']}]` **{c['platform']}**: `{c['match_value']}` at offset `0x{c['offset']:X}`")

    if report_dict.get("c2_urls"):
        md.append("\n## Discovered C2 Infrastructure")
        for u in report_dict["c2_urls"]:
            md.append(f"- `{u}`")

    return "\n".join(md)
