from collections import namedtuple
from pathlib import Path

import lief

from .binary import BinarySecurity

PEChecksecData = namedtuple(
    "PEChecksecData",
    [
        "nx",
        "pie",
        "canary",
    ],
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
    def checksec_state(self) -> PEChecksecData:
        return PEChecksecData(self.has_nx, self.has_pie, self.has_canary)
