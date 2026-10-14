"""Kinetic Benchmark Comparator against Reference Reports and VirusTotal GTI Telemetry."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any


class BenchmarkComparator:
    """Benchmarks kinetic-memhunter forensic findings against static/dynamic reports and VT."""

    def __init__(self, nfs_base_path: str = "/mnt/shared_nfs/mem_dumps"):
        self.nfs_base_path = nfs_base_path

    def load_reference_report(self, sample_hash: str) -> dict[str, Any] | None:
        """Loads reference report from /mnt/shared_nfs/mem_dumps/report or sample directory (Read-Only)."""
        # Try dynamic report in sample folder
        dyn_path = os.path.join(
            self.nfs_base_path,
            sample_hash,
            "reports",
            f"dynamic_report_{sample_hash}.json",
        )
        if os.path.exists(dyn_path):
            try:
                with open(dyn_path, "r", encoding="utf-8", errors="ignore") as f:
                    return json.load(f)
            except Exception:
                pass

        # Try memory report in report/
        mem_path = os.path.join(self.nfs_base_path, "report", f"memory_{sample_hash}.json")
        if os.path.exists(mem_path):
            try:
                with open(mem_path, "r", encoding="utf-8", errors="ignore") as f:
                    return json.load(f)
            except Exception:
                pass

        return None

    def load_vt_gti_data(self, sample_hash: str) -> dict[str, Any]:
        """Attempts to retrieve VT behaviour or malware config from local cache or GCS."""
        vt_intel: dict[str, Any] = {
            "family": None,
            "c2_network": [],
            "mutexes": [],
            "injected_pes": [],
        }

        # 1. Fast local cache lookup
        local_mc = f"/home/sheilafe/kinetic-memhunter/cache/vt_gti/malware_config/{sample_hash}.json"
        if os.path.exists(local_mc):
            try:
                with open(local_mc, "r", encoding="utf-8") as f:
                    mc_data = json.load(f)
                    if "family" in mc_data:
                        vt_intel["family"] = mc_data["family"]
                    families = mc_data.get("malware_config", {}).get("families", [])
                    for fam in families:
                        if "family" in fam and not vt_intel["family"]:
                            vt_intel["family"] = fam["family"]
                        for cfg in fam.get("configs", []):
                            for conn in cfg.get("net_info", {}).get("connections", []):
                                host = conn.get("host")
                                port = conn.get("port")
                                if host:
                                    vt_intel["c2_network"].append(f"{host}:{port}" if port else host)
            except Exception:
                pass

        local_beh = f"/home/sheilafe/kinetic-memhunter/cache/vt_gti/behaviours/{sample_hash}.json"
        if os.path.exists(local_beh):
            try:
                with open(local_beh, "r", encoding="utf-8") as f:
                    beh_data = json.load(f)
                    data_attrs = beh_data.get("data", {}).get("attributes", {})
                    for m in data_attrs.get("mutexes_created", []):
                        vt_intel["mutexes"].append(m)
                    for conn in data_attrs.get("ip_traffic", []):
                        dest = conn.get("destination_ip")
                        port = conn.get("destination_port")
                        if dest:
                            vt_intel["c2_network"].append(f"{dest}:{port}" if port else dest)
                return vt_intel
            except Exception:
                pass

        # 2. Fallback to GCS query if not in local cache
        try:
            cmd = ["gcloud", "storage", "cat", f"gs://gti-samples-vt-multiagent-demo/malware_config/{sample_hash}.json"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=4)
            mc_data = json.loads(out)
            if "family" in mc_data:
                vt_intel["family"] = mc_data["family"]
        except Exception:
            pass

        try:
            cmd = ["gcloud", "storage", "cat", f"gs://gti-samples-vt-multiagent-demo/behaviours/{sample_hash}.json"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=4)
            beh_data = json.loads(out)
            data_attrs = beh_data.get("data", {}).get("attributes", {})
            for m in data_attrs.get("mutexes_created", []):
                vt_intel["mutexes"].append(m)
            for conn in data_attrs.get("ip_traffic", []):
                dest = conn.get("destination_ip")
                port = conn.get("destination_port")
                if dest:
                    vt_intel["c2_network"].append(f"{dest}:{port}" if port else dest)
        except Exception:
            pass

        return vt_intel


    def compare(
        self,
        sample_hash: str,
        our_mutexes: list[str],
        our_c2s: list[str],
        our_pdbs: list[str],
        our_anti_analysis: list[str],
        our_persistence: list[str],
        our_family: str,
        our_credentials_count: int,
        our_sqlite_count: int,
    ) -> dict[str, Any]:
        """Executes deep comparison and calculates improvement statistics."""
        ref_report = self.load_reference_report(sample_hash) or {}
        vt_intel = self.load_vt_gti_data(sample_hash)

        # 1. Reference Mutexes
        ref_mutexes: set[str] = set()
        if "mutexes" in ref_report and isinstance(ref_report["mutexes"], list):
            ref_mutexes.update(ref_report["mutexes"])
        if "behaviour_intel" in ref_report and "mutex" in ref_report["behaviour_intel"]:
            ref_mutexes.update(ref_report["behaviour_intel"]["mutex"])

        # 2. Reference C2s
        ref_c2s: set[str] = set()
        if "extracted_c2" in ref_report:
            c2_obj = ref_report["extracted_c2"]
            if isinstance(c2_obj, list):
                for item in c2_obj:
                    if isinstance(item, str):
                        ref_c2s.add(item.split()[0])
            elif isinstance(c2_obj, dict):
                for k in ["ips_urls", "ddr", "ftp_activity"]:
                    val = c2_obj.get(k, [])
                    if isinstance(val, list):
                        for v in val:
                            if isinstance(v, dict) and "value" in v:
                                ref_c2s.add(v["value"])
                            elif isinstance(v, str):
                                ref_c2s.add(v)

        # 3. Reference PDBs
        ref_pdbs: set[str] = set()
        if "identity_intel" in ref_report and "PDB Debug Paths" in ref_report["identity_intel"]:
            ref_pdbs.update(ref_report["identity_intel"]["PDB Debug Paths"])
        if "behaviour_intel" in ref_report and "pdb" in ref_report["behaviour_intel"]:
            ref_pdbs.update(ref_report["behaviour_intel"]["pdb"])

        # 4. Reference Anti-Analysis
        ref_anti: set[str] = set()
        if "behavior_intel" in ref_report and "Anti-Analysis (Evasion)" in ref_report["behavior_intel"]:
            ref_anti.update(ref_report["behavior_intel"]["Anti-Analysis (Evasion)"])
        if "behaviour_intel" in ref_report and "anti_analysis" in ref_report["behaviour_intel"]:
            ref_anti.update(ref_report["behaviour_intel"]["anti_analysis"])

        # Calculate new indicators found by our tool
        our_mutex_set = set(our_mutexes)
        our_c2_set = set(our_c2s)
        our_pdb_set = set(our_pdbs)
        our_anti_set = set(our_anti_analysis)

        extra_mutexes = list(our_mutex_set - ref_mutexes)
        extra_c2s = list(our_c2_set - ref_c2s)
        extra_pdbs = list(our_pdb_set - ref_pdbs)
        extra_anti = list(our_anti_set - ref_anti)

        total_ref_indicators = (
            len(ref_mutexes) + len(ref_c2s) + len(ref_pdbs) + len(ref_anti)
        )
        total_our_indicators = (
            len(our_mutex_set)
            + len(our_c2_set)
            + len(our_pdb_set)
            + len(our_anti_set)
            + len(our_persistence)
            + our_credentials_count
            + our_sqlite_count
        )

        advantage_ratio = (
            round(total_our_indicators / max(1, total_ref_indicators), 2)
            if total_ref_indicators > 0
            else 2.0
        )

        ref_family = ref_report.get("family_supposition", "unknown")
        family_attribution_improvement = (
            ref_family == "unknown" and our_family not in ["Generic Infostealer", "unknown", "Unknown"]
        )

        return {
            "sample_hash": sample_hash,
            "has_reference_report": bool(ref_report),
            "reference_indicators_count": total_ref_indicators,
            "our_indicators_count": total_our_indicators,
            "advantage_ratio": advantage_ratio,
            "reference_family": ref_family,
            "our_attributed_family": our_family,
            "family_attribution_improved": family_attribution_improvement,
            "vt_family": vt_intel.get("family"),
            "extra_mutexes_found": extra_mutexes,
            "extra_c2s_found": extra_c2s,
            "extra_pdbs_found": extra_pdbs,
            "extra_anti_analysis_found": extra_anti,
            "sqlite_databases_carved": our_sqlite_count,
            "credentials_extracted": our_credentials_count,
        }
