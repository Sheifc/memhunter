"""GTI Memory Dump Syncer and Batch Pipeline Orchestrator."""

from __future__ import annotations

import io
import json
import logging
import os
import re
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
try:
    from google.cloud import bigquery, storage
except ImportError:
    bigquery = None  # type: ignore[assignment]
    storage = None  # type: ignore[assignment]

from .analyzer import MemoryAnalyzer
from .core.reporter import format_report_markdown
from .models import MemoryAnalysisReport

logger = logging.getLogger("kinetic_memhunter.syncer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


@dataclass
class MemdumpTarget:
    sha256: str
    sandbox_id: str
    sandbox_name: str
    memory_dumps_count: int
    context: dict[str, Any]


class MemdumpSyncer:
    """Discovers, downloads, stores in GCS artifact/, and analyzes all sandbox memory dumps."""

    def __init__(
        self,
        gti_api_key: str | None = None,
        bucket_name: str = "gti-samples-vt-multiagent-demo",
        artifact_prefix: str = "artifact",
        results_dir: str | Path = "results",
        max_workers: int = 10,
        publish_bigquery: bool = False,
    ):
        self.gti_api_key = gti_api_key or os.getenv("GTI_API_KEY")
        self.bucket_name = bucket_name
        self.artifact_prefix = artifact_prefix.strip("/")
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        self.publish_bigquery = publish_bigquery

        self.storage_client = storage.Client()
        self.bucket = self.storage_client.bucket(self.bucket_name)
        self.bq_client = bigquery.Client() if publish_bigquery else None
        self.analyzer = MemoryAnalyzer()

    def discover_targets(self, limit: int | None = None) -> list[MemdumpTarget]:
        """Discovers all samples and sandboxes that contain memory dumps in GCS behaviours/."""
        logger.info(f"Scanning gs://{self.bucket_name}/behaviours/ for memdump candidates...")
        blobs = list(self.bucket.list_blobs(prefix="behaviours/"))
        logger.info(f"Found {len(blobs)} total behaviour blobs in GCS.")

        def inspect_blob(b: storage.Blob) -> list[MemdumpTarget]:
            targets: list[MemdumpTarget] = []
            try:
                content = b.download_as_text()
                data = json.loads(content)
                sha = b.name.split("/")[-1].replace(".json", "")
                reports = data.get("behaviours", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                for rep in reports:
                    if not isinstance(rep, dict):
                        continue
                    attrs = rep.get("attributes", {}) if isinstance(rep.get("attributes"), dict) else rep
                    has_mem = (
                        attrs.get("has_memdump") is True
                        or attrs.get("has_memory_dump") is True
                        or attrs.get("has_mem_dump") is True
                        or bool(attrs.get("memory_dumps"))
                    )
                    if has_mem:
                        s_name = attrs.get("sandbox_name") or "sandbox"
                        s_id = rep.get("id") or f"{sha}_{s_name}"
                        # Extract sample context for enhanced deobfuscation
                        ctx = {
                            "sandbox_name": s_name,
                            "verdicts": attrs.get("verdicts", []),
                            "verdict_labels": attrs.get("verdict_labels", []),
                            "threat_severity": attrs.get("threat_severity"),
                        }
                        # Check memory_dumps structure for process names
                        mem_dumps = attrs.get("memory_dumps", [])
                        if isinstance(mem_dumps, list):
                            ctx["processes"] = [
                                m.get("process_name") for m in mem_dumps if isinstance(m, dict) and m.get("process_name")
                            ]
                        targets.append(
                            MemdumpTarget(
                                sha256=sha,
                                sandbox_id=s_id,
                                sandbox_name=s_name,
                                memory_dumps_count=len(mem_dumps) if isinstance(mem_dumps, list) else 0,
                                context=ctx,
                            )
                        )
            except Exception as e:
                logger.debug(f"Error inspecting {b.name}: {e}")
            return targets

        all_targets: list[MemdumpTarget] = []
        with ThreadPoolExecutor(max_workers=30) as pool:
            futures = [pool.submit(inspect_blob, b) for b in blobs]
            for f in as_completed(futures):
                all_targets.extend(f.result())

        logger.info(f"Discovered {len(all_targets)} total sandbox reports with memdump across {len({t.sha256 for t in all_targets})} unique samples.")
        if limit:
            all_targets = all_targets[:limit]
            logger.info(f"Applying run limit: processing {len(all_targets)} targets.")
        return all_targets

    def _sanitize_name(self, name: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name)

    def fetch_or_download_memdump_zip(self, target: MemdumpTarget) -> bytes | None:
        """Checks GCS artifact/ for cached memdump zip, or downloads via GTI API and uploads to GCS."""
        clean_sandbox = self._sanitize_name(target.sandbox_name)
        gcs_path = f"{self.artifact_prefix}/{target.sha256}/{clean_sandbox}_memdump.zip"
        blob = self.bucket.blob(gcs_path)

        # 1. Check if already uploaded to GCS artifact/
        if blob.exists():
            logger.info(f"[*] Found cached memdump in GCS: gs://{self.bucket_name}/{gcs_path}")
            return blob.download_as_bytes()

        # 2. Download from VirusTotal / GTI v3 API
        if not self.gti_api_key:
            logger.warning("[-] GTI_API_KEY is not configured; cannot download missing memdumps from GTI.")
            return None

        quoted_id = urllib.parse.quote(target.sandbox_id)
        url = f"https://www.virustotal.com/api/v3/file_behaviours/{quoted_id}/memdump"
        headers = {"x-apikey": self.gti_api_key, "accept": "*/*"}

        logger.info(f"[*] Requesting memdump from GTI API for sandbox '{target.sandbox_id}'...")
        try:
            with httpx.Client(timeout=60.0, follow_redirects=False) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 404:
                    logger.warning(f"[-] Memdump not found (404) on GTI for {target.sandbox_id}")
                    return None
                if resp.status_code == 403:
                    logger.error(f"[!] 403 Forbidden downloading memdump for {target.sandbox_id}. Check API key permissions.")
                    return None

                redirect_url = resp.headers.get("location")
                if not redirect_url and resp.is_redirect:
                    logger.warning(f"[-] Redirect without location for {target.sandbox_id}")
                    return None

                # Follow redirect to GCS without x-apikey
                target_url = redirect_url if redirect_url else url
                req_headers = {"accept": "*/*"}
                if not redirect_url:
                    req_headers["x-apikey"] = self.gti_api_key

                resp2 = client.get(target_url, headers=req_headers, follow_redirects=True)
                if resp2.status_code != 200:
                    logger.error(f"[-] Failed downloading payload: HTTP {resp2.status_code}")
                    return None

                zip_bytes = resp2.content
                logger.info(f"[+] Downloaded {len(zip_bytes):,} bytes for {target.sandbox_id}")

                # 3. Store in GCS under artifact/{sha256}/{sandbox}_memdump.zip
                blob.upload_from_string(zip_bytes, content_type="application/zip")
                logger.info(f"[+] Uploaded memdump to gs://{self.bucket_name}/{gcs_path}")
                return zip_bytes
        except Exception as ex:
            logger.error(f"[!] Error downloading memdump for {target.sandbox_id}: {ex}")
            return None

    def process_target(self, target: MemdumpTarget) -> list[MemoryAnalysisReport]:
        """Downloads memdump, unpacks all .dmp files inside, runs analysis, and saves reports."""
        zip_bytes = self.fetch_or_download_memdump_zip(target)
        if not zip_bytes:
            return []

        reports: list[MemoryAnalysisReport] = []
        clean_sandbox = self._sanitize_name(target.sandbox_name)

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                dmp_names = [name for name in zf.namelist() if name.endswith(".dmp") or name.endswith(".raw")]
                if not dmp_names:
                    # If no .dmp extension, treat entire zip contents as dump
                    dmp_names = zf.namelist()

                for dmp_name in dmp_names:
                    logger.info(f"[*] Analyzing dump '{dmp_name}' from {target.sha256[:12]} ({target.sandbox_name})...")
                    dump_bytes = zf.read(dmp_name)

                    report = self.analyzer.analyze_bytes(
                        dump_bytes,
                        target_name=f"{target.sha256[:16]}_{clean_sandbox}_{dmp_name}",
                        sample_context=target.context,
                    )
                    reports.append(report)

                    # Save per-dump results in results/
                    base_filename = f"{target.sha256[:16]}_{clean_sandbox}_{dmp_name}"
                    json_path = self.results_dir / f"{base_filename}.json"
                    md_path = self.results_dir / f"{base_filename}.md"

                    report_dict = report.model_dump(mode="json")
                    json_path.write_text(json.dumps(report_dict, indent=2))
                    md_path.write_text(format_report_markdown(report_dict))
                    logger.info(f"[+] Saved findings to {json_path.name} and {md_path.name}")

                    # Optionally stream results into BigQuery
                    if self.publish_bigquery and self.bq_client:
                        try:
                            from datetime import datetime, timezone
                            bq_rows = [{
                                "sample_sha256": target.sha256,
                                "file_size_bytes": report.file_size_bytes,
                                "ingested_at": datetime.now(timezone.utc).isoformat(),
                                "Data": report_dict,
                            }]
                            errs = self.bq_client.insert_rows_json("stealers_analysis.forensic_memory_report", bq_rows)
                            if errs:
                                logger.warning(f"BigQuery streaming error: {errs}")
                            else:
                                logger.info(f"[+] Synced finding to BigQuery forensic_memory_report ({target.sha256[:12]})")
                        except Exception as bqe:
                            logger.debug(f"BigQuery publish error: {bqe}")
        except Exception as e:
            logger.error(f"[!] Failed unpacking or analyzing memdump for {target.sandbox_id}: {e}")

        return reports

    def run_batch(self, limit: int | None = None) -> list[MemoryAnalysisReport]:
        """Runs the complete end-to-end sync and analysis batch over all targets."""
        targets = self.discover_targets(limit=limit)
        all_reports: list[MemoryAnalysisReport] = []

        logger.info(f"Starting analysis for {len(targets)} targets with {self.max_workers} concurrent workers...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.process_target, t): t for t in targets}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    reps = fut.result()
                    all_reports.extend(reps)
                except Exception as ex:
                    logger.error(f"[!] Target {t.sandbox_id} generated exception: {ex}")

        # Generate Consolidated Report
        self._generate_consolidated_report(all_reports)
        return all_reports

    def _generate_consolidated_report(self, reports: list[MemoryAnalysisReport]) -> None:
        """Generates executive summary Markdown and JSON in results/."""
        total_dumps = len(reports)
        confirmed_stealera = sum(1 for r in reports if r.threat_verdict == "CONFIRMED_INFOSTEALER")
        suspicious = sum(1 for r in reports if r.threat_verdict == "SUSPICIOUS_MEMORY_ACTIVITY")
        benign = sum(1 for r in reports if r.threat_verdict == "BENIGN")

        total_sboxes = sum(len(r.crypto_primitives) for r in reports)
        total_pes = sum(len(r.carved_pes) for r in reports)
        total_archives = sum(len(r.carved_archives) for r in reports)
        total_credentials = sum(len(r.credentials) for r in reports)
        total_c2s = sum(len(r.c2_urls) for r in reports)

        summary_data = {
            "total_dumps_analyzed": total_dumps,
            "confirmed_infostealer_count": confirmed_stealera,
            "suspicious_count": suspicious,
            "benign_count": benign,
            "total_sboxes_carved": total_sboxes,
            "total_pes_carved": total_pes,
            "total_archives_carved": total_archives,
            "total_credentials_harvested": total_credentials,
            "total_c2s_discovered": total_c2s,
        }

        # Save summary JSON
        summary_json_path = self.results_dir / "summary.json"
        summary_json_path.write_text(json.dumps(summary_data, indent=2))

        # Generate Consolidated Markdown
        md = [
            "# Kinetic MemHunter - Consolidated Memory Forensics Executive Summary",
            "",
            "## Global Statistics",
            f"- **Total Process Memory Dumps Analyzed**: {total_dumps}",
            f"- **Confirmed Infostealer Verdicts**: {confirmed_stealera} ({round(confirmed_stealera / max(total_dumps, 1) * 100, 1)}%)",
            f"- **Suspicious Activity Verdicts**: {suspicious}",
            f"- **Benign Memory Dumps**: {benign}",
            "",
            "## Forensic Artefacts Carved",
            f"- **Cryptographic S-Boxes (RC4/AES/ChaCha20)**: {total_sboxes}",
            f"- **Injected Executable PEs (Reflective Loaders)**: {total_pes}",
            f"- **In-Memory Staged Archives (ZIP/zlib)**: {total_archives}",
            f"- **Stolen Credentials & Developer Tokens**: {total_credentials}",
            f"- **In-Flight C2 Endpoints Discovered**: {total_c2s}",
            "",
            "## Notable Findings by Sample",
        ]

        for r in reports:
            if r.credentials or r.crypto_primitives or r.carved_pes or r.c2_urls:
                md.append(f"### `{r.target_name}` (Score: {r.threat_score}/100 - {r.threat_verdict})")
                if r.credentials:
                    md.append("- **Credentials Harvested**:")
                    for c in r.credentials[:5]:
                        md.append(f"  - `[{c.category.value}]` {c.platform}: `{c.match_value}`")
                if r.crypto_primitives:
                    md.append("- **Active Cipher Primitives**:")
                    for p in r.crypto_primitives[:3]:
                        md.append(f"  - {p.primitive.value} at offset `0x{p.offset:X}` (Entropy: {p.entropy})")
                if r.c2_urls:
                    md.append(f"- **Discovered C2s**: {', '.join(r.c2_urls[:3])}")
                md.append("")

        consolidated_md_path = self.results_dir / "CONSOLIDATED_FORENSIC_REPORT.md"
        consolidated_md_path.write_text("\n".join(md))
        logger.info(f"[+] Generated executive report at {consolidated_md_path}")
