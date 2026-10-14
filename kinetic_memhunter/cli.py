"""Command Line Interface for Kinetic MemHunter."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

from .analyzer import MemoryAnalyzer
from .core.reporter import format_report_markdown
from .syncer import MemdumpSyncer

# Auto-load .env from package dir or current dir
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
load_dotenv()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="kinetic-memhunter",
        description="Kinetic Memory & Cryptographic State Hunter for Infostealers",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single process memory dump or raw binary buffer")
    analyze_parser.add_argument("dump_file", type=str, help="Path to the memory dump (.dmp, .raw, .bin)")
    analyze_parser.add_argument("--json", type=str, default=None, help="Save structured JSON report to path")
    analyze_parser.add_argument("--markdown", type=str, default=None, help="Save Markdown forensic report to path")
    analyze_parser.add_argument("--carve-dir", type=str, default=None, help="Directory to save carved PEs and archives")

    # sync-and-analyze command
    sync_parser = subparsers.add_parser("sync-and-analyze", help="Sync memdumps from GTI to GCS artifact/ and analyze all")
    sync_parser.add_argument("--limit", type=int, default=None, help="Maximum number of sandbox dumps to process")
    sync_parser.add_argument("--workers", type=int, default=5, help="Number of concurrent worker threads")
    sync_parser.add_argument("--bucket", type=str, default="gti-samples-vt-multiagent-demo", help="GCS bucket name")
    sync_parser.add_argument("--results-dir", type=str, default="results", help="Directory to save results")
    sync_parser.add_argument("--publish-bigquery", action="store_true", default=False, help="Publish findings to BigQuery table stealers_analysis.forensic_memory_report")

    # batch-nfs command
    batch_parser = subparsers.add_parser("batch-nfs", help="Run parallel forensic extraction on NFS memory dumps")
    batch_parser.add_argument("--limit", type=int, default=None, help="Maximum number of sample directories to process")
    batch_parser.add_argument("--workers", type=int, default=4, help="Number of concurrent worker processes")
    batch_parser.add_argument("--nfs-path", type=str, default="/mnt/shared_nfs/mem_dumps", help="Path to NFS memory dumps")
    batch_parser.add_argument("--results-dir", type=str, default="results", help="Directory to save output reports")

    # benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Benchmark a single sample against reference reports and VT GTI")
    bench_parser.add_argument("sample_hash", type=str, help="SHA-256 hash of the sample to analyze and benchmark")
    bench_parser.add_argument("--nfs-path", type=str, default="/mnt/shared_nfs/mem_dumps", help="Path to NFS memory dumps")
    # dashboard command
    dash_parser = subparsers.add_parser("dashboard", help="Generate an interactive HTML forensic intelligence dashboard")
    dash_parser.add_argument("--results-dir", type=str, default="results", help="Directory containing benchmark results")
    dash_parser.add_argument("--output", type=str, default=None, help="Output HTML file path (default: results/DASHBOARD.html)")

    args = parser.parse_args()

    if args.command == "analyze":
        dump_path = Path(args.dump_file)
        if not dump_path.is_file():
            print(f"[ERROR] Target file does not exist: {dump_path}", file=sys.stderr)
            return 1

        print("=" * 65)
        print("   KINETIC MEMHUNTER - In-Memory Forensics & Stealer Engine")
        print("=" * 65)
        print(f"[*] Target: {dump_path.name} ({dump_path.stat().st_size:,} bytes)")

        analyzer = MemoryAnalyzer()
        report = analyzer.analyze_file(dump_path)
        report_dict = report.model_dump(mode="json")

        print(f"[*] Threat Score   : {report.threat_score}/100")
        print(f"[*] Threat Verdict : {report.threat_verdict}")
        print(f"[*] S-Boxes Found  : {len(report.crypto_primitives)}")
        print(f"[*] Injected PEs   : {len(report.carved_pes)}")
        print(f"[*] Staged Archives: {len(report.carved_archives)}")
        print(f"[*] Credentials    : {len(report.credentials)}")
        print("=" * 65)

        if report.credentials:
            print("\n[+] Extracted Staged Credentials:")
            for cred in report.credentials:
                print(f"    - [{cred.category.value}] {cred.platform}: {cred.match_value}")

        if report.crypto_primitives:
            print("\n[+] Cryptographic States & S-Boxes:")
            for prim in report.crypto_primitives:
                print(f"    - {prim.primitive.value} at 0x{prim.offset:08X} (Entropy: {prim.entropy})")

        if args.json:
            out_json = Path(args.json)
            out_json.write_text(json.dumps(report_dict, indent=2))
            print(f"\n[+] Saved JSON report to {out_json}")

        if args.markdown:
            out_md = Path(args.markdown)
            out_md.write_text(format_report_markdown(report_dict))
            print(f"[+] Saved Markdown report to {out_md}")

    elif args.command == "batch-nfs":
        from .batch_runner import BatchRunner
        print("=" * 65)
        print("   KINETIC MEMHUNTER - Parallel NFS Forensic Batch Runner")
        print("=" * 65)
        runner = BatchRunner(
            nfs_base=args.nfs_path,
            output_dir=args.results_dir,
            max_workers=args.workers,
        )
        runner.run(limit=args.limit)

    elif args.command == "benchmark":
        from .batch_runner import process_single_sample
        print("=" * 65)
        print(f"   KINETIC MEMHUNTER - Forensic Benchmark: {args.sample_hash[:16]}...")
        print("=" * 65)
        res = process_single_sample(
            sample_hash=args.sample_hash,
            nfs_base=args.nfs_path,
            output_dir=args.results_dir,
        )
        print(f"[*] Status: {res.get('status')}")
        print(f"[*] Attributed Family: {res.get('family')} (Confidence: {res.get('confidence', 0)*100:.0f}%)")
        print(f"[*] Threat Score: {res.get('threat_score')}/100")
        print(f"[*] Advantage Ratio: {res.get('advantage_ratio')}x")
        print(f"[*] Our Indicators : {res.get('our_indicators')} vs {res.get('ref_indicators')} reference")
        print(f"[*] Carved SQLite DBs : {res.get('sqlite_count')}")
        print(f"[*] Stolen Credentials : {res.get('credentials_count')}")
        print("=" * 65)

    elif args.command == "dashboard":
        from .dashboard import generate_dashboard_html
        out = generate_dashboard_html(results_dir=args.results_dir, output_file=args.output)
        print("=" * 65)
        print("   KINETIC MEMHUNTER - Interactive Forensic Dashboard")
        print("=" * 65)
        print(f"[+] Successfully generated dashboard at: {out.resolve()}")
        print("=" * 65)

    elif args.command == "sync-and-analyze":
        print("=" * 65)
        print("   KINETIC MEMHUNTER - Batch Pipeline & GCS Artifact Syncer")
        print("=" * 65)
        syncer = MemdumpSyncer(
            bucket_name=args.bucket,
            results_dir=args.results_dir,
            max_workers=args.workers,
            publish_bigquery=args.publish_bigquery,
        )
        reports = syncer.run_batch(limit=args.limit)
        print("=" * 65)
        print(f"[+] Completed batch analysis! Processed {len(reports)} memory dumps.")
        print(f"[+] Results saved in: {Path(args.results_dir).resolve()}")
        print(f"[+] Executive summary: {Path(args.results_dir).resolve() / 'CONSOLIDATED_FORENSIC_REPORT.md'}")
        print("=" * 65)

    return 0


if __name__ == "__main__":
    sys.exit(main())
