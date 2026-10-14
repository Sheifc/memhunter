"""Unit tests for kinetic-memhunter advanced forensic carvers and classifiers."""

import pytest
from kinetic_memhunter.core.mutex_carver import MutexCarver
from kinetic_memhunter.core.pdb_carver import PDBCarver
from kinetic_memhunter.core.anti_analysis_detector import AntiAnalysisDetector
from kinetic_memhunter.core.network_c2_carver import NetworkC2Carver
from kinetic_memhunter.core.persistence_carver import PersistenceCarver
from kinetic_memhunter.core.sqlite_carver import SQLiteCarver
from kinetic_memhunter.core.dga_detector import DGADetector
from kinetic_memhunter.core.family_classifier import FamilyClassifier


def test_mutex_carver():
    carver = MutexCarver()
    buf = b"junk junk Global\\FzYmEt5856\x00 and Local\\pptplsa.exe\x00 and BaseNamedObjects\\test_obj\x00"
    findings = carver.scan(buf)
    names = [f.name for f in findings]
    assert "Global\\FzYmEt5856" in names
    assert "Local\\pptplsa.exe" in names
    assert "BaseNamedObjects\\test_obj" in names
    fz = next(f for f in findings if "FzYmEt" in f.name)
    assert fz.associated_family == "QueenBee / BotGenStudio"


def test_pdb_carver():
    carver = PDBCarver()
    buf = (
        b"some junk RSDS\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        b"\x01\x00\x00\x00D:\\SVA\\NITRO\\BotGenStudio\\Interface\\Generations\\bin\\bot.pdb\x00 other junk"
    )
    findings = carver.scan(buf)
    assert len(findings) >= 1
    p = findings[0]
    assert "bot.pdb" in p.pdb_path
    assert p.project_name == "bot"
    assert p.guid is not None


def test_anti_analysis_detector():
    detector = AntiAnalysisDetector()
    buf = b"prefix IsDebuggerPresent middle VBOX suffix anticuckoo"
    findings = detector.scan(buf)
    assert len(findings) == 4
    categories = {f.category for f in findings}
    assert "anti_debug" in categories
    assert "anti_vm" in categories
    assert "anti_sandbox" in categories


def test_network_c2_carver():
    carver = NetworkC2Carver()
    buf = (
        b"connecting to ftp://199.231.188.109/ and https://github.com/therealdreg/anticuckoo "
        b"and http://malware.gate/upload.php and ip 46.246.120.178:21"
    )
    findings = carver.scan(buf)
    values = [f.value for f in findings]
    assert "ftp://199.231.188.109/" in values
    assert "https://github.com/therealdreg/anticuckoo" in values
    assert "http://malware.gate/upload.php" in values
    assert any(f.endpoint_type == "DDR" for f in findings)
    assert any(f.endpoint_type == "FTP" for f in findings)


def test_persistence_carver():
    carver = PersistenceCarver()
    buf = b"CLSID: {E429B25A-E5D3-4D1F-9BE3-0C608477E3A1} and CurrentVersion\\Run entry"
    findings = carver.scan(buf)
    assert len(findings) == 2
    types = {f.persistence_type for f in findings}
    assert "COM_CLSID" in types
    assert "Registry_Run" in types


def test_sqlite_carver():
    carver = SQLiteCarver()
    fake_db = (
        b"SQLite format 3\x00"
        + b"\x10\x00"  # page size 4096
        + b"\x00" * 84
        + b"CREATE TABLE logins (username TEXT, password TEXT);"
        + b" victim@corporate.com "
    )
    findings = carver.scan(fake_db)
    assert len(findings) == 1
    f = findings[0]
    assert "logins" in f.tables_found
    assert any("victim@corporate.com" in rec for rec in f.records_preview)


def test_dga_detector():
    detector = DGADetector()
    buf = b"Alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz and abcdefghijklmnopqrstuvwxyz012345"
    findings = detector.scan(buf)
    assert len(findings) >= 2


def test_family_classifier():
    classifier = FamilyClassifier()
    attribution = classifier.classify(
        mutexes=["Global\\FzYmEt5856"],
        pdbs=["D:\\SVA\\NITRO\\BotGenStudio\\Interface\\Generations\\bin\\bot.pdb"],
        c2_endpoints=["ftp://199.231.188.109/"],
        anti_analysis=["anticuckoo", "IsDebuggerPresent"],
        targets=["Google Chrome", "FileZilla FTP Client"],
        vt_reference_family="queenbee",
    )
    assert "QueenBee" in attribution.family_name
    assert attribution.confidence >= 0.80
