from collections import namedtuple
from pathlib import Path

import lief
from lief.PE import DLL_CHARACTERISTICS

from .binary import BinarySecurity

PEChecksecData = namedtuple(
    "PEChecksecData",
    ["nx", "pie", "canary", "dynamic_base", "high_entropy_va", "guard_cf", "force_integrity"],
)


def is_pe(filepath: Path) -> bool:
    """Tests whether given file is a Portable Executable"""
    return lief.is_pe(str(filepath))


class PESecurity(BinarySecurity):
    """This class allows to get the security state of a PE from a Path object"""

    def __init__(self, pe_path: Path):
        super().__init__(pe_path)

    @property
    def has_pie(self) -> bool:
        """Whether PIE is enabled"""
        return self.bin.is_pie

    @property
    def has_canary(self) -> bool:
        """Whether Security Cookie (/GS) is enabled"""
        return True if self.bin.load_configuration.security_cookie != 0 else False

    @property
    def has_dynamic_base(self) -> bool:
        """Whether DYNAMIC_BASE is enabled"""
        return self.bin.optional_header.has(DLL_CHARACTERISTICS.DYNAMIC_BASE)

    @property
    def has_high_entropy_va(self) -> bool:
        """Whether HIGH_ENTROPY_VA is enabled"""
        return self.bin.optional_header.has(DLL_CHARACTERISTICS.HIGH_ENTROPY_VA)

    @property
    def has_guard_cf(self) -> bool:
        """Whether GUARD:CF is enabled"""
        return self.bin.optional_header.has(DLL_CHARACTERISTICS.GUARD_CF)

    @property
    def has_force_integrity(self) -> bool:
        """Whether FORCE_INTEGRITY is enabled"""
        return self.bin.optional_header.has(DLL_CHARACTERISTICS.FORCE_INTEGRITY)

    @property
    def checksec_state(self) -> PEChecksecData:
        return PEChecksecData(
            self.has_nx,
            self.has_pie,
            self.has_canary,
            self.has_dynamic_base,
            self.has_high_entropy_va,
            self.has_guard_cf,
            self.has_force_integrity,
        )