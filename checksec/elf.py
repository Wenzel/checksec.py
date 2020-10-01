from collections import namedtuple
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import List, FrozenSet

import lief

from .binary import BinarySecurity
from .errors import ErrorParsingFailed
from .utils import find_libc

FORTIFIED_END_MARKER = "_chk"
FORTFIED_START_MARKER = "__"
LIBC_OBJ = None
ELFChecksecData = namedtuple(
    "ELFChecksecData",
    [
        "relro",
        "canary",
        "nx",
        "pie",
        "rpath",
        "runpath",
        "symbols",
        "fortify_source",
        "fortified",
        "fortifiable",
        "fortify_score",
    ],
)


def set_libc(libc_path: Path):
    """Sets a new libc path to be used by future calls on ELFSecurity fortified functions"""
    global LIBC_OBJ
    LIBC_OBJ = Libc(libc_path)


def is_elf(filepath: Path) -> bool:
    return lief.is_elf(str(filepath))


class RelroType(Enum):
    No = 1
    Partial = 2
    Full = 3


class PIEType(Enum):
    No = 1
    DSO = 2
    PIE = 3


class Libc:
    def __init__(self, libpath: Path = None):
        if libpath is None:
            libpath = Path(find_libc())
        self.libc = lief.parse(str(libpath))
        if not self.libc:
            raise ErrorParsingFailed(libpath)

    @property
    @lru_cache()
    def fortified_symbols(self) -> FrozenSet[str]:
        """Get the list of libc symbols who have been fortified"""
        return frozenset({s.name for s in self.libc.symbols if s.name.endswith(FORTIFIED_END_MARKER)})

    @property
    @lru_cache()
    def fortified_symbols_base(self) -> FrozenSet[str]:
        """Get the list of fortified libc symbols, keeping only the function basename"""
        return frozenset(
            {sym[len(FORTFIED_START_MARKER) : -len(FORTIFIED_END_MARKER)] for sym in self.fortified_symbols}
        )


class ELFSecurity(BinarySecurity):
    def __init__(self, elf_path: Path):
        super().__init__(elf_path)

    @property
    @lru_cache()
    def set_dyn_syms(self) -> FrozenSet[str]:
        return frozenset(f.name for f in self.bin.dynamic_symbols)

    @property
    def relro(self) -> RelroType:
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
        canary_sections = ["__stack_chk_fail", "__intel_security_cookie"]
        for section in canary_sections:
            try:
                if self.bin.get_symbol(section):
                    return True
            except lief.not_found:
                pass
        return False

    @property
    def pie(self) -> PIEType:
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
    def has_runpath(self) -> bool:
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
    def is_stripped(self) -> bool:
        # TODO: hwo to reset static_symbols iterator for the next call to symbols() ?
        # consumes only the first symbol from iterator, saving CPU cycles
        try:
            next(self.bin.static_symbols)
        except StopIteration:
            return True
        else:
            return False

    @property
    def is_fortified(self) -> bool:
        return True if self.fortified else False

    @property
    @lru_cache()
    def __get_libc(self) -> Libc:
        global LIBC_OBJ
        if LIBC_OBJ is None:
            LIBC_OBJ = Libc()
        return LIBC_OBJ

    @property
    @lru_cache()
    def fortified(self) -> FrozenSet[str]:
        """Get the list of fortified symbols"""
        libc = self.__get_libc
        return self.set_dyn_syms & libc.fortified_symbols

    @property
    @lru_cache()
    def fortifiable(self) -> FrozenSet[str]:
        """Get the list of fortifiable symbols (fortified + unfortified)"""
        libc = self.__get_libc
        return self.set_dyn_syms & (self.fortified | libc.fortified_symbols_base)

    @property
    def checksec_state(self) -> ELFChecksecData:
        fortified_count = len(self.fortified)
        fortifiable_count = len(self.fortifiable)
        if not self.is_fortified:
            score = 0
        else:
            # fortified
            if fortified_count == 0:
                # all fortified !
                score = 100
            else:
                score = (fortified_count * 100) / fortifiable_count
                score = round(score)

        fortify_source = True if fortified_count != 0 else False
        return ELFChecksecData(
            self.relro,
            self.has_canary,
            self.has_nx,
            self.pie,
            self.has_rpath,
            self.has_runpath,
            not self.is_stripped,
            fortify_source,
            fortified_count,
            fortifiable_count,
            score,
        )
