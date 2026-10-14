"""Kinetic MemHunter: Kinetic Memory & Cryptographic State Hunter for Infostealers."""

from .analyzer import MemoryAnalyzer
from .core.deobfuscator import StealerDeobfuscator
from .core.minidump_parser import MinidumpParser
from .models import (
    CarvedArchiveFinding,
    CarvedPEFinding,
    CredentialCategory,
    CryptoPrimitiveFinding,
    DecryptedRegionFinding,
    MemoryAnalysisReport,
    PrimitiveType,
    StealerCredentialFinding,
)
from .syncer import MemdumpSyncer

__version__ = "1.0.0"

__all__ = [
    "MemoryAnalyzer",
    "MemdumpSyncer",
    "MinidumpParser",
    "StealerDeobfuscator",
    "MemoryAnalysisReport",
    "CryptoPrimitiveFinding",
    "CarvedPEFinding",
    "CarvedArchiveFinding",
    "StealerCredentialFinding",
    "DecryptedRegionFinding",
    "PrimitiveType",
    "CredentialCategory",
]
