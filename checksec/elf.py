from enum import Enum
from typing import List
from functools import lru_cache
from pathlib import Path

import lief

from .errors import ErrorNotAnElf, ErrorParsingFailed


class RelroType(Enum):
    No = 1
    Partial = 2
    Full = 3


class PIEType(Enum):
    No = 1
    DSO = 2
    PIE = 3


class ELFSecurity:

    def __init__(self, elf_path: Path):
        # load with LIEF
        if not lief.is_elf(str(elf_path)):
            raise ErrorNotAnElf(elf_path)
        self.bin = lief.parse(str(elf_path))
        if not self.bin:
            raise ErrorParsingFailed(elf_path)

    @property
    def has_relro(self) -> RelroType:
        try:
            self.bin.get(lief.ELF.SEGMENT_TYPES.GNU_RELRO)
            if lief.ELF.DYNAMIC_FLAGS.BIND_NOW in self.bin.get(lief.ELF.DYNAMIC_TAGS.FLAGS):
                return RelroType.Full
            else:
                return RelroType.Partial
        except lief.not_found:
            return RelroType.No

    @property
    def has_canary(self) -> bool:
        canary_sections = ['__stack_chk_fail', '__intel_security_cookie']
        for section in canary_sections:
            try:
                if self.bin.get_symbol(section):
                    return True
            except lief.not_found:
                pass
        return False

    @property
    def has_nx(self) -> bool:
        return self.bin.has_nx

    @property
    def is_pie(self) -> PIEType:
        if self.bin.is_pie:
            if self.bin.has(lief.ELF.DYNAMIC_TAGS.DEBUG):
                return PIEType.PIE
            else:
                return PIEType.DSO
        return PIEType.No

    @property
    def has_rpath(self) -> bool:
        try:
            if self.bin.get(lief.ELF.DYNAMIC_TAGS.RPATH):
                return True
        except lief.not_found:
            pass
        return False

    @property
    def has_runpath(self):
        try:
            if self.bin.get(lief.ELF.DYNAMIC_TAGS.RUNPATH):
                return True
        except lief.not_found:
            pass
        return False

    @property
    @lru_cache()
    def symbols(self) -> List[str]:
        return [symbol.name for symbol in self.bin.static_symbols]

    @property
    def is_stripped(self):
        return True if not self.symbols else False

    @property
    @lru_cache()
    def fortified_functions(self) -> List[str]:
        return [func for func in self.bin.symbols if func.name.endswith('_chk')]

    @property
    def is_fortified(self) -> bool:
        return True if self.fortified_functions else False
