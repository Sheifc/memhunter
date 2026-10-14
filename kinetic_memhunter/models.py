"""Data models for kinetic-memhunter memory forensic findings."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class PrimitiveType(str, Enum):
    RC4_KSA_SBOX = "RC4_KSA_SBOX"
    AES_FORWARD_SBOX = "AES_FORWARD_SBOX"
    AES_INVERSE_SBOX = "AES_INVERSE_SBOX"
    CHACHA20_CONSTANT = "CHACHA20_CONSTANT"
    SALSA20_CONSTANT = "SALSA20_CONSTANT"
    DES_EXPANSION_TABLE = "DES_EXPANSION_TABLE"
    MD5_INIT_CONSTANTS = "MD5_INIT_CONSTANTS"
    SHA1_INIT_CONSTANTS = "SHA1_INIT_CONSTANTS"
    SHA256_INIT_CONSTANTS = "SHA256_INIT_CONSTANTS"
    CRC32_TABLE = "CRC32_TABLE"


class CredentialCategory(str, Enum):
    AI_DEVELOPER_SESSION = "AI_DEVELOPER_SESSION"
    BROWSER_MASTER_KEY = "BROWSER_MASTER_KEY"
    CRYPTO_WALLET = "CRYPTO_WALLET"
    TELEGRAM_SESSION = "TELEGRAM_SESSION"
    CLOUD_CREDENTIAL = "CLOUD_CREDENTIAL"
    PASSWORD_RECORD = "PASSWORD_RECORD"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    CREDIT_CARD = "CREDIT_CARD"


class CryptoPrimitiveFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    primitive: PrimitiveType
    offset: int
    size: int
    confidence: str = "high"
    entropy: float = Field(..., ge=0.0, le=8.0)
    hex_preview: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class PESectionInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int


class CarvedPEFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    offset: int
    size: int
    is_64bit: bool
    machine_type: str
    compile_time: datetime | None = None
    entry_point: int
    sections: list[PESectionInfo] = Field(default_factory=list)
    suspicious_imports: list[str] = Field(default_factory=list)
    sha256: str
    is_reflective_injection: bool = False
    imphash: str | None = None
    pdb_path: str | None = None


class CarvedArchiveFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    archive_type: str
    offset: int
    compressed_size: int
    uncompressed_size: int
    file_list: list[str] = Field(default_factory=list)
    stealer_artifacts_detected: list[str] = Field(default_factory=list)


class StealerCredentialFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: CredentialCategory
    platform: str
    match_value: str
    offset: int
    context_snippet: str


class DecryptedRegionFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    cipher: str
    key_hex: str
    offset: int
    size: int
    entropy_before: float
    entropy_after: float
    plaintext_preview: str


class MutexFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    scope: str
    offset: int
    is_suspicious: bool = True
    associated_family: str | None = None


class PDBFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    pdb_path: str
    offset: int
    guid: str | None = None
    age: int | None = None
    project_name: str | None = None


class AntiAnalysisFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    technique: str
    category: str  # anti_debug, anti_vm, anti_sandbox, timing, anti_hooking
    indicator_string: str
    offset: int | None = None


class NetworkC2Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    endpoint_type: str  # IPv4, URL, DDR, FTP, Telegram_Bot, Discord_Webhook
    value: str
    port: int | None = None
    context: str | None = None
    vt_hits: int | None = None


class PersistenceFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    persistence_type: str  # COM_CLSID, Registry_Run, Registry_Service, Registry_ScreenSave
    target_value: str
    offset: int | None = None
    is_malicious: bool = True


class APIHashingFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    offset: int
    pattern_type: str  # ROR13_RESOLVER, CALL_POP_DELTA, CRC32_RESOLVER
    disassembly_snippet: str
    hex_dump: str
    hashes_detected: list[str] = Field(default_factory=list)


class SQLiteCarvedFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    offset: int
    database_size: int
    tables_found: list[str] = Field(default_factory=list)
    extracted_records_count: int = 0
    records_preview: list[str] = Field(default_factory=list)


class DGAAlphabetFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    alphabet: str
    alphabet_type: str  # Custom_Base64, Char_Set, Permutation_Table
    offset: int


class FamilyAttribution(BaseModel):
    model_config = ConfigDict(frozen=True)

    family_name: str
    confidence: float
    attribution_reasons: list[str] = Field(default_factory=list)
    vt_family_reference: str | None = None


class MemoryAnalysisReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target_name: str
    file_size_bytes: int
    sha256: str
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    threat_score: int = Field(default=0, ge=0, le=100)
    threat_verdict: str = "BENIGN"
    family_attribution: FamilyAttribution | None = None
    mitre_techniques: list[dict[str, str]] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    modules_loaded: list[str] = Field(default_factory=list)
    c2_urls: list[str] = Field(default_factory=list)
    browser_profiles_targeted: list[str] = Field(default_factory=list)
    sample_context: dict[str, Any] = Field(default_factory=dict)
    crypto_primitives: list[CryptoPrimitiveFinding] = Field(default_factory=list)
    carved_pes: list[CarvedPEFinding] = Field(default_factory=list)
    carved_archives: list[CarvedArchiveFinding] = Field(default_factory=list)
    credentials: list[StealerCredentialFinding] = Field(default_factory=list)
    decrypted_regions: list[DecryptedRegionFinding] = Field(default_factory=list)
    mutexes: list[MutexFinding] = Field(default_factory=list)
    pdb_paths: list[PDBFinding] = Field(default_factory=list)
    anti_analysis: list[AntiAnalysisFinding] = Field(default_factory=list)
    network_c2: list[NetworkC2Finding] = Field(default_factory=list)
    persistence: list[PersistenceFinding] = Field(default_factory=list)
    api_hashing: list[APIHashingFinding] = Field(default_factory=list)
    sqlite_carved: list[SQLiteCarvedFinding] = Field(default_factory=list)
    dga_alphabets: list[DGAAlphabetFinding] = Field(default_factory=list)
    stealer_targets: list[str] = Field(default_factory=list)


class SampleAnalysisReport(BaseModel):
    """Aggregated multi-process memory intelligence for a complete malware sample."""
    model_config = ConfigDict(extra="ignore")

    sample_hash: str
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_processes_analyzed: int = 0
    process_names: list[str] = Field(default_factory=list)
    threat_verdict: str = "CONFIRMED_INFOSTEALER"
    threat_score: int = 95
    family_attribution: FamilyAttribution
    mitre_techniques: list[dict[str, str]] = Field(default_factory=list)
    all_mutexes: list[str] = Field(default_factory=list)
    all_pdbs: list[str] = Field(default_factory=list)
    all_c2_endpoints: list[str] = Field(default_factory=list)
    all_anti_analysis: list[str] = Field(default_factory=list)
    all_clsids: list[str] = Field(default_factory=list)
    all_persistence: list[str] = Field(default_factory=list)
    all_stealer_targets: list[str] = Field(default_factory=list)
    all_credentials: list[StealerCredentialFinding] = Field(default_factory=list)
    all_sqlite_databases: list[SQLiteCarvedFinding] = Field(default_factory=list)
    all_crypto_primitives: list[str] = Field(default_factory=list)
    all_api_hashing: list[str] = Field(default_factory=list)
    all_dga_alphabets: list[str] = Field(default_factory=list)
    process_reports: list[MemoryAnalysisReport] = Field(default_factory=list)
    benchmark_comparison: dict[str, Any] = Field(default_factory=dict)
