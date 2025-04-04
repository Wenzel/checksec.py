from abc import ABC
from pathlib import Path
from typing import TYPE_CHECKING, Union

import lief

from .errors import ErrorParsingFailed

if TYPE_CHECKING:
    from .elf import ELFChecksecData
    from .pe import PEChecksecData


class BinarySecurity(ABC):
    def __init__(self, bin_path: Path):
        self.bin = lief.parse(str(bin_path))
        if not self.bin:
            raise ErrorParsingFailed(bin_path)

    @property
    def has_nx(self) -> bool:
        # Handle ELF binary with no program segments (e.g., Kernel modules)
        # In this case, return True
        if isinstance(self.bin, lief.ELF.Binary) and len(self.bin.segments) == 0:
            return True
        else:
            return self.bin.has_nx

    @property
    def checksec_state(self) -> Union["ELFChecksecData", "PEChecksecData"]:
        raise NotImplementedError
