import logging
from collections import namedtuple
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, List, Optional

import lief
from lief.ELF import E_TYPE

from .binary import BinarySecurity
from .errors import ErrorParsingFailed
from .utils import LibcNotFoundError, find_libc

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


__LIBC_OBJ = {}


def get_libc(libc_path: Optional[Path] = None) -> Optional["Libc"]:
    """This function initializes a Libc using LIEF

    :param libc_path: an optional Path to the libc library. if None, the Libc will be auto detected using various
    methods
    :return a Libc object
    """
    # Note: this weird function is designed as a poor singleton lru_cache wasn't possible, since get_libc(path) and
    # get_libc(None) should return the same data once the first call has been made we need to maintain a global
    # object as we can't pass the Libc object to ELFSecurity, as LIEF's objects are not picklable
    global __LIBC_OBJ
    try:
        __LIBC_OBJ["libc"]
    except KeyError:
        logging.debug("Libc object not set")
        try:
            libc = Libc(libc_path)
        except (LibcNotFoundError, ErrorParsingFailed) as e:
            logging.debug("Failed to init Libc object: %s", e)
            __LIBC_OBJ["libc"] = None
        else:
            logging.debug("Libc object initialized")
            __LIBC_OBJ["libc"] = libc
    logging.debug(__LIBC_OBJ)
    return __LIBC_OBJ["libc"]


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
    REL = 4


class Libc:
    def __init__(self, libpath: Path = None):
        if libpath is None:
            libpath = Path(find_libc())
            if not libpath:
                raise LibcNotFoundError
        logging.debug("Initializing Libc from %s", libpath)
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
        self._libc = get_libc()

    @property
    @lru_cache()
    def set_dyn_syms(self) -> FrozenSet[str]:
        return frozenset(f.name for f in self.bin.dynamic_symbols)

    @property
    def relro(self) -> RelroType:
        try:
            self.bin.get(lief.ELF.SEGMENT_TYPES.GNU_RELRO)
        except lief.not_found:
            return RelroType.No

        try:
            bind_now = lief.ELF.DYNAMIC_FLAGS.BIND_NOW in self.bin.get(lief.ELF.DYNAMIC_TAGS.FLAGS)
        except lief.not_found:
            bind_now = False

        try:
            now = lief.ELF.DYNAMIC_FLAGS_1.NOW in self.bin.get(lief.ELF.DYNAMIC_TAGS.FLAGS_1)
        except lief.not_found:
            now = False

        if bind_now or now:
            return RelroType.Full
        else:
            return RelroType.Partial

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
        if self.bin.header.file_type == E_TYPE.DYNAMIC:
            if self.bin.has(lief.ELF.DYNAMIC_TAGS.DEBUG):
                return PIEType.PIE
            else:
                return PIEType.DSO
        elif self.bin.header.file_type == E_TYPE.RELOCATABLE:
            return PIEType.REL
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
    def fortified(self) -> Optional[FrozenSet[str]]:
        """Get the list of fortified symbols"""
        if not self._libc:
            return None
        return self.set_dyn_syms & self._libc.fortified_symbols

    @property
    @lru_cache()
    def fortifiable(self) -> Optional[FrozenSet[str]]:
        """Get the list of fortifiable symbols (fortified + unfortified)"""
        if not self._libc:
            return None
        return self.set_dyn_syms & (self.fortified | self._libc.fortified_symbols_base)

    @property
    def checksec_state(self) -> ELFChecksecData:
        fortify_source = None
        fortified_count = None
        fortifiable_count = None
        score = None
        if self._libc:
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
            fortify_source = True if fortified_count != 0 or fortifiable_count == 0 else False
        return ELFChecksecData(
            relro=self.relro,
            canary=self.has_canary,
            nx=self.has_nx,
            pie=self.pie,
            rpath=self.has_rpath,
            runpath=self.has_runpath,
            symbols=not self.is_stripped,
            fortify_source=fortify_source,
            fortified=fortified_count,
            fortifiable=fortifiable_count,
            fortify_score=score,
        )
