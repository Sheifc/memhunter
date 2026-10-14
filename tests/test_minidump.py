"""Tests for Windows Minidump stream parser."""

import struct
from kinetic_memhunter.core.minidump_parser import (
    MINIDUMP_SIGNATURE,
    STREAM_TYPE_MEMORY_LIST,
    STREAM_TYPE_MODULE_LIST,
    MinidumpParser,
)


def create_mock_minidump() -> bytes:
    """Builds a synthetic Windows Minidump buffer."""
    buf = bytearray(2048)
    # Header: sig, version, num_streams=2, dir_rva=32
    struct.pack_into("<IIII", buf, 0, MINIDUMP_SIGNATURE, 0xA793, 2, 32)

    # Stream Directory at offset 32:
    # Entry 0: MemoryListStream (type 5), size=20, rva=64
    struct.pack_into("<III", buf, 32, STREAM_TYPE_MEMORY_LIST, 20, 64)
    # Entry 1: ModuleListStream (type 4), size=112, rva=128
    struct.pack_into("<III", buf, 44, STREAM_TYPE_MODULE_LIST, 112, 128)

    # MemoryListStream at offset 64: num_ranges=1, start_addr=0x00400000, size=256, rva=500
    struct.pack_into("<I", buf, 64, 1)
    struct.pack_into("<QII", buf, 68, 0x00400000, 256, 500)
    buf[500:756] = b"\x90" * 256

    # ModuleListStream at offset 128: num_modules=1
    struct.pack_into("<I", buf, 128, 1)
    # Module descriptor: base=0x400000, size=0x10000, ..., name_rva=800
    struct.pack_into("<IIIII", buf, 132, 0x00400000, 0x10000, 0, 0, 800)
    # Module name string at 800: len=18 (9 chars * 2), "stealer.exe\0" in UTF-16LE
    mod_name_utf16 = "stealer.exe".encode("utf-16le")
    struct.pack_into("<I", buf, 800, len(mod_name_utf16))
    buf[804 : 804 + len(mod_name_utf16)] = mod_name_utf16

    return bytes(buf)


def test_minidump_parser_extraction():
    data = create_mock_minidump()
    parser = MinidumpParser(data)
    assert parser.is_minidump is True

    modules = parser.extract_modules()
    assert len(modules) == 1
    assert "stealer.exe" in modules[0].module_name
    assert modules[0].base_of_image == 0x00400000

    segments = list(parser.iter_memory_segments())
    assert len(segments) == 1
    assert segments[0].start_address == 0x00400000
    assert segments[0].size == 256
    assert len(segments[0].data) == 256
