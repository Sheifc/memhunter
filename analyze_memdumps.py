#!/usr/bin/env python3
"""
analyze_memdumps.py
Declarative CLI orchestrator for ephemeral memory dump downloading, RAM carving,
automatic .zip/.dmp deletion, and local JSON/Markdown report persistence.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from memhunter.config import DEFAULT_OUTPUT_DIR, GTI_KEY, SHA256_RE
from memhunter.service import analyze_sample_memdump

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("analyze_memdumps")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download VT memdumps into ephemeral storage, carve intelligence, and delete raw dumps."
    )
    parser.add_argument(
        "--hash",
        "--sha256",
        dest="hashes",
        action="append",
        default=[],
        help="SHA-256 sample hash to analyze (can be specified multiple times)",
    )
    parser.add_argument("--file", "--hashes-file", dest="file", type=Path, default=None, help="File containing SHA-256 hashes (one per line)")
    parser.add_argument("--local-dump", type=Path, default=None, help="Optional local .zip or .dmp file to analyze")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Output directory for JSON/MD")
    parser.add_argument("--resolve-ddr", action="store_true", help="Resolve live Pastebin Dead Drop URLs")
    parser.add_argument("--skip-existing", action="store_true", help="Skip hashes that already have a generated JSON report")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if not GTI_KEY and not args.local_dump:
        logger.error("Missing GTI_KEY / VT_API_KEY in environment or .env.")
        return 1

    hashes: List[str] = []
    for raw_h in args.hashes or []:
        h = raw_h.strip().lower()
        if SHA256_RE.match(h) and h not in hashes:
            hashes.append(h)
    if args.file and args.file.is_file():
        for line in args.file.read_text(encoding="utf-8").splitlines():
            h = line.strip().lower()
            if SHA256_RE.match(h) and h not in hashes:
                hashes.append(h)

    if not hashes:
        logger.error("Provide --hash <sha256> or --file <hashes.txt>.")
        return 1

    start_ts = time.time()
    summary: Dict[str, Any] = {
        "total": len(hashes),
        "succeeded": 0,
        "no_memdump": 0,
        "errors": 0,
        "families": {},
        "samples": [],
    }

    no_memdump_cache_path = args.output_dir / ".no_memdump_cache.txt"
    no_memdump_cache = set()
    if args.skip_existing and no_memdump_cache_path.is_file():
        no_memdump_cache = {
            line.strip().lower()
            for line in no_memdump_cache_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

    for idx, sha in enumerate(hashes, start=1):
        existing_json = args.output_dir / "configs" / f"{sha}_memdump.json"
        if args.skip_existing and existing_json.is_file():
            try:
                rpt = json.loads(existing_json.read_text(encoding="utf-8"))
                summary["succeeded"] += 1
                fam = rpt.get("family_supposition", "unknown")
                summary["families"][fam] = summary["families"].get(fam, 0) + 1
                c2 = rpt.get("extracted_c2", {})
                summary["samples"].append(
                    {
                        "sha256": sha,
                        "family": fam,
                        "ips_urls_count": len(c2.get("ips_urls", [])),
                        "webhooks_count": len(c2.get("webhooks", [])),
                        "wallets_count": len(c2.get("crypto_wallets", [])),
                        "ddr_count": len(c2.get("ddr", [])),
                        "targets": rpt.get("behaviour_intel", {}).get("malware_targets", []),
                    }
                )
                continue
            except Exception:
                pass
        if args.skip_existing and sha in no_memdump_cache:
            summary["no_memdump"] += 1
            continue

        logger.info("=== [%d/%d] Processing %s ===", idx, len(hashes), sha)
        try:
            res = analyze_sample_memdump(
                sha256=sha,
                api_key=GTI_KEY,
                output_dir=args.output_dir,
                resolve_ddr=args.resolve_ddr,
                local_zip_or_dmp=args.local_dump if len(hashes) == 1 else None,
            )
            status = res.get("status")
            if status == "ok":
                summary["succeeded"] += 1
                fam = res.get("family_supposition", "unknown")
                summary["families"][fam] = summary["families"].get(fam, 0) + 1
                rpt = res.get("report", {})
                c2 = rpt.get("extracted_c2", {})
                summary["samples"].append(
                    {
                        "sha256": sha,
                        "family": fam,
                        "ips_urls_count": len(c2.get("ips_urls", [])),
                        "webhooks_count": len(c2.get("webhooks", [])),
                        "wallets_count": len(c2.get("crypto_wallets", [])),
                        "ddr_count": len(c2.get("ddr", [])),
                        "targets": rpt.get("behaviour_intel", {}).get("malware_targets", []),
                    }
                )
            else:
                summary["no_memdump"] += 1
                args.output_dir.mkdir(parents=True, exist_ok=True)
                with no_memdump_cache_path.open("a", encoding="utf-8") as cf:
                    cf.write(f"{sha}\n")
        except Exception as exc:
            logger.error("[%s] Error during memdump analysis: %s", sha[:12], exc)
            summary["errors"] += 1

    summary["elapsed_sec"] = round(time.time() - start_ts, 2)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.output_dir / "batch_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Batch finished in %.2fs -> %s", summary["elapsed_sec"], summary_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
