"""Windows Minidump (.dmp / MDMP) Stream Parser and Memory Extractor."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

MINIDUMP_SIGNATURE = 0x504D444D  # b"MDMP"

STREAM_TYPE_UNUSED = 0
STREAM_TYPE_MODULE_LIST = 4
STREAM_TYPE_MEMORY_LIST = 5
STREAM_TYPE_SYSTEM_INFO = 7
STREAM_TYPE_THREAD_LIST = 8
STREAM_TYPE_MEMORY64_LIST = 9


@dataclass(frozen=True)
class MemorySegment:
    start_address: int
    size: int
    data: bytes


@dataclass(frozen=True)
class MinidumpModule:
    base_of_image: int
    size_of_image: int
    module_name: str


class MinidumpParser:
    """Extracts virtual memory ranges and modules from Windows Process Minidumps."""

    def __init__(self, raw_bytes: bytes):
        self.data = raw_bytes
        self.length = len(raw_bytes)
        self.is_minidump = False
        self._streams: dict[int, tuple[int, int]] = {}  # stream_type -> (size, rva)
        self._parse_header()

    def _parse_header(self) -> None:
        if self.length < 32:
            return
        sig, version, num_streams, dir_rva = struct.unpack_from("<IIII", self.data, 0)
        if sig != MINIDUMP_SIGNATURE:
            return

        self.is_minidump = True
        # Read stream directory
        for i in range(num_streams):
            entry_offset = dir_rva + (i * 12)
            if entry_offset + 12 > self.length:
                break
            stype, size, rva = struct.unpack_from("<III", self.data, entry_offset)
            self._streams[stype] = (size, rva)

    def extract_modules(self) -> list[MinidumpModule]:
        """Extracts loaded DLL and EXE modules from the minidump."""
        modules: list[MinidumpModule] = []
        if STREAM_TYPE_MODULE_LIST not in self._streams:
            return modules

        size, rva = self._streams[STREAM_TYPE_MODULE_LIST]
        if rva + 4 > self.length:
            return modules

        num_modules = struct.unpack_from("<I", self.data, rva)[0]
        cur = rva + 4
        for _ in range(min(num_modules, 512)):
            if cur + 108 > self.length:
                break
            base_of_img, size_of_img, _, _, mod_name_rva = struct.unpack_from("<IIIII", self.data, cur)

            # Read module name (UTF-16 string at mod_name_rva)
            mod_name = "unknown"
            if mod_name_rva + 4 <= self.length:
                str_len = struct.unpack_from("<I", self.data, mod_name_rva)[0]
                if mod_name_rva + 4 + str_len <= self.length:
                    raw_str = self.data[mod_name_rva + 4 : mod_name_rva + 4 + str_len]
                    mod_name = raw_str.decode("utf-16le", errors="ignore").rstrip("\x00")

            modules.append(
                MinidumpModule(
                    base_of_image=base_of_img,
                    size_of_image=size_of_img,
                    module_name=mod_name,
                )
            )
            cur += 108
        return modules

    def iter_memory_segments(self) -> Iterator[MemorySegment]:
        """Iterates through all virtual memory ranges contained in the dump."""
        if not self.is_minidump:
            # Fallback for raw memory dumps: yield entire buffer as single segment
            yield MemorySegment(start_address=0, size=self.length, data=self.data)
            return

        # 1. 32-bit MemoryListStream (Stream Type 5)
        if STREAM_TYPE_MEMORY_LIST in self._streams:
            size, rva = self._streams[STREAM_TYPE_MEMORY_LIST]
            if rva + 4 <= self.length:
                num_ranges = struct.unpack_from("<I", self.data, rva)[0]
                cur = rva + 4
                for _ in range(num_ranges):
                    if cur + 16 > self.length:
                        break
                    start_addr = struct.unpack_from("<Q", self.data, cur)[0]
                    data_size, data_rva = struct.unpack_from("<II", self.data, cur + 8)
                    if data_rva + data_size <= self.length:
                        yield MemorySegment(
                            start_address=start_addr,
                            size=data_size,
                            data=self.data[data_rva : data_rva + data_size],
                        )
                    cur += 16

        # 2. 64-bit Memory64ListStream (Stream Type 9)
        if STREAM_TYPE_MEMORY64_LIST in self._streams:
            size, rva = self._streams[STREAM_TYPE_MEMORY64_LIST]
            if rva + 16 <= self.length:
                num_ranges, base_rva = struct.unpack_from("<QQ", self.data, rva)
                cur = rva + 16
                cur_data_rva = base_rva
                for _ in range(num_ranges):
                    if cur + 16 > self.length:
                        break
                    start_addr, data_size = struct.unpack_from("<QQ", self.data, cur)
                    if cur_data_rva + data_size <= self.length:
                        yield MemorySegment(
                            start_address=start_addr,
                            size=data_size,
                            data=self.data[cur_data_rva : cur_data_rva + data_size],
                        )
                    cur_data_rva += data_size
                    cur += 16
