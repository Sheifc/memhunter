"""
memhunter/workspace.py
Ephemeral workspace context manager with Zip-Slip path traversal defense,
Decompression Bomb bounds, and guaranteed auto-deletion of .zip and .dmp files.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import List

from memhunter.config import DEFAULT_TMP_DIR, MAX_DUMP_MB


class EphemeralDumpWorkspace:
    """
    Context manager governing an isolated temporary directory for memory dump
    downloading, safe ZIP extraction, and guaranteed cleanup on exit.
    """

    def __init__(self, sha256: str, base_tmp_dir: Path = DEFAULT_TMP_DIR, max_dump_mb: int = MAX_DUMP_MB) -> None:
        self.sha256 = sha256.lower().strip()
        self.base_tmp_dir = Path(base_tmp_dir)
        self.max_entry_bytes = max_dump_mb * 1024 * 1024
        self.max_total_bytes = max_dump_mb * 3 * 1024 * 1024
        self.work_dir: Path | None = None

    def __enter__(self) -> "EphemeralDumpWorkspace":
        self.base_tmp_dir.mkdir(parents=True, exist_ok=True)
        prefix = f"memhunter_{self.sha256[:12]}_{uuid.uuid4().hex[:8]}_"
        self.work_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=str(self.base_tmp_dir)))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.work_dir and self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)

    def safe_extract_zip(self, zip_path: Path) -> List[Path]:
        """
        Safely extract memory dump files from a sandbox ZIP archive while enforcing
        Zip-Slip path traversal immunity and decompression size limits.
        Deletes the source ZIP immediately after extraction to save disk space.
        """
        if self.work_dir is None:
            raise RuntimeError("EphemeralDumpWorkspace must be entered before extracting.")

        dest_root = os.path.abspath(self.work_dir)
        extracted_files: List[Path] = []
        cumulative_bytes = 0

        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or info.filename.endswith("/"):
                    continue

                # 1. Zip-Slip path traversal check
                safe_rel = os.path.normpath(info.filename).lstrip("/\\")
                target_abs = os.path.abspath(os.path.join(dest_root, safe_rel))
                if not target_abs.startswith(dest_root + os.sep):
                    raise ValueError(f"Zip-Slip path traversal blocked: {info.filename!r}")

                # 2. Decompression bomb check
                if info.file_size > self.max_entry_bytes:
                    raise ValueError(
                        f"Archive member {info.filename!r} ({info.file_size} bytes) exceeds max_entry_bytes"
                    )
                cumulative_bytes += info.file_size
                if cumulative_bytes > self.max_total_bytes:
                    raise ValueError("Cumulative uncompressed size exceeds workspace safety limit")

                target_path = Path(target_abs)
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
                extracted_files.append(target_path)

        # Immediately remove the compressed ZIP after extracting its .dmp members
        zip_path.unlink(missing_ok=True)
        return extracted_files
