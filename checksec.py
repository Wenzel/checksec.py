#!/usr/bin/env python3


import argparse
from typing import List
from functools import lru_cache
from pathlib import Path
from enum import Enum

import lief
from colorama import init, Fore, Style


class RelroType(Enum):
    No = 1
    Partial = 2
    Full = 3


class ELFSecurity:

    def __init__(self, elf_path: Path):
        # load with LIEF
        if not lief.is_elf(str(elf_path)):
            raise RuntimeError(f"File {elf_path} is not an ELF")
        self.bin = lief.parse(str(elf_path))

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
    def is_pie(self) -> bool:
        return self.bin.is_pie

    @property
    def has_rpath(self) -> bool:
        try:
            if self.bin.get(lief.ELF.DYNAMIC_TAGS.RPATH):
                return True
        except:
            pass
        return False

    @property
    def has_runpath(self):
        try:
            if self.bin.get(lief.ELF.DYNAMIC_TAGS.RUNPATH):
                return True
        except:
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


def parse_args() -> Path:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="file to be analyzed")
    args = parser.parse_args()
    filepath = Path(args.file)
    if not filepath.exists():
        raise RuntimeError(f"file {filepath} does not exists")
    return filepath


if __name__ == '__main__':
    filepath = parse_args()
    checksec = ELFSecurity(filepath)
    init()
    # display results
    relro = checksec.has_relro
    if relro == RelroType.No:
        print(f"RELRO: {Fore.RED}{checksec.has_relro.name}{Style.RESET_ALL}")
    else:
        print(f"RELRO: {Fore.GREEN}{checksec.has_relro.name}{Style.RESET_ALL}")

    if not checksec.has_canary:
        print(f"Canary: {Fore.RED}No{Style.RESET_ALL}")
    else:
        print(f"Canary: {Fore.GREEN}Yes{Style.RESET_ALL}")

    if not checksec.has_nx:
        print(f"NX: {Fore.RED}No{Style.RESET_ALL}")
    else:
        print(f"NX: {Fore.GREEN}Yes{Style.RESET_ALL}")

    if not checksec.is_pie:
        print(f"PIE: {Fore.RED}No{Style.RESET_ALL}")
    else:
        print(f"PIE: {Fore.GREEN}Yes{Style.RESET_ALL}")

    if checksec.has_rpath:
        print(f"RPATH: {Fore.RED}Yes{Style.RESET_ALL}")
    else:
        print(f"RPATH: {Fore.GREEN}No{Style.RESET_ALL}")

    if checksec.has_rpath:
        print(f"RUNPATH: {Fore.RED}Yes{Style.RESET_ALL}")
    else:
        print(f"RUNPATH: {Fore.GREEN}No{Style.RESET_ALL}")

    if not checksec.is_stripped:
        print(f"Symbols: {Fore.RED}Yes{Style.RESET_ALL}")
    else:
        print(f"Symbols: {Fore.GREEN}No{Style.RESET_ALL}")
