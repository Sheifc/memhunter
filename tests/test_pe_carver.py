"""Tests for PE carving and reflective loader detection."""

import struct
from kinetic_memhunter.core.pe_carver import PECarver


def create_minimal_pe_buffer() -> bytes:
    """Builds a minimal valid 32-bit PE image in memory."""
    buf = bytearray(4096)
    # MZ header
    buf[0:2] = b"MZ"
    # e_lfanew at 0x3C points to offset 0x80
    struct.pack_into("<I", buf, 0x3C, 0x80)

    # PE signature
    buf[0x80:0x84] = b"PE\x00\x00"

    # COFF Header: machine=0x14c (x86), num_sections=1, time=1700000000, opt_hdr_size=224
    struct.pack_into("<HHI", buf, 0x84, 0x014C, 1, 1700000000)
    struct.pack_into("<H", buf, 0x84 + 16, 224)

    # Optional Header
    opt_offset = 0x84 + 20
    # Magic=0x10b (PE32), EntryPoint=0x1000
    struct.pack_into("<H", buf, opt_offset, 0x010B)
    struct.pack_into("<I", buf, opt_offset + 16, 0x1000)
    # ImageSize=0x2000
    struct.pack_into("<I", buf, opt_offset + 56, 0x2000)

    # Section Header: .text, vsize=0x1000, va=0x1000, rsize=0x500, rptr=0x200
    sec_offset = opt_offset + 224
    buf[sec_offset : sec_offset + 5] = b".text"
    struct.pack_into("<IIII", buf, sec_offset + 8, 0x1000, 0x1000, 0x500, 0x200)

    # Inject a stealer API string
    buf[0x200:0x213] = b"CryptUnprotectData"
    return bytes(buf)


def test_pe_carving_minimal():
    pe_data = create_minimal_pe_buffer()
    memory_dump = b"\xcc" * 1024 + pe_data + b"\xcc" * 512

    carver = PECarver()
    findings = carver.scan(memory_dump)

    assert len(findings) == 1
    pe = findings[0]
    assert pe.offset == 1024
    assert not pe.is_64bit
    assert pe.machine_type == "x86"
    assert pe.entry_point == 0x1000
    assert len(pe.sections) == 1
    assert pe.sections[0].name == ".text"
    assert any("CryptUnprotectData" in s for s in pe.suspicious_imports)
