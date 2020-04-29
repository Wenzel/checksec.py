#!/usr/bin/env python3

import argparse
from pathlib import Path
from typing import List

from colorama import init, Fore, Style

from .elf import ELFSecurity, RelroType, PIEType
from .errors import ErrorNotAnElf, ErrorParsingFailed


def parse_args() -> List[Path]:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs='+', help="file to be analyzed")
    args = parser.parse_args()
    yield from [Path(f) for f in args.file]


def main():
    filepath_list = parse_args()
    init()
    for filepath in filepath_list:
        if not filepath.exists():
            print(f"File {filepath} does not exist")
            continue
        try:
            print(f"### {filepath} ###")
            checksec = ELFSecurity(filepath)
        except (ErrorNotAnElf, ErrorParsingFailed):
            print(f"Failed to process {filepath}")
            continue

        # display results
        relro = checksec.relro
        if relro == RelroType.No:
            print(f"RELRO: {Fore.RED}{relro.name}{Style.RESET_ALL}")
        elif relro == RelroType.Partial:
            print(f"RELRO: {Fore.YELLOW}{relro.name}{Style.RESET_ALL}")
        else:
            print(f"RELRO: {Fore.GREEN}{relro.name}{Style.RESET_ALL}")

        if not checksec.has_canary:
            print(f"Canary: {Fore.RED}No{Style.RESET_ALL}")
        else:
            print(f"Canary: {Fore.GREEN}Yes{Style.RESET_ALL}")

        if not checksec.has_nx:
            print(f"NX: {Fore.RED}No{Style.RESET_ALL}")
        else:
            print(f"NX: {Fore.GREEN}Yes{Style.RESET_ALL}")

        pie = checksec.pie
        if pie == PIEType.No:
            print(f"PIE: {Fore.RED}{pie.name}{Style.RESET_ALL}")
        elif pie == PIEType.DSO:
            print(f"PIE: {Fore.YELLOW}{pie.name}{Style.RESET_ALL}")
        else:
            print(f"PIE: {Fore.GREEN}Yes{Style.RESET_ALL}")

        if checksec.has_rpath:
            print(f"RPATH: {Fore.RED}Yes{Style.RESET_ALL}")
        else:
            print(f"RPATH: {Fore.GREEN}No{Style.RESET_ALL}")

        if checksec.has_runpath:
            print(f"RUNPATH: {Fore.RED}Yes{Style.RESET_ALL}")
        else:
            print(f"RUNPATH: {Fore.GREEN}No{Style.RESET_ALL}")

        if not checksec.is_stripped:
            print(f"Symbols: {Fore.RED}Yes{Style.RESET_ALL}")
        else:
            print(f"Symbols: {Fore.GREEN}No{Style.RESET_ALL}")

        fortified_funcs = checksec.fortified
        if not fortified_funcs:
            print(f"Fortified: {Fore.RED}No{Style.RESET_ALL}")
        else:
            print(f"Fortified: {Fore.GREEN}{len(fortified_funcs)}{Style.RESET_ALL}")

        fortifiable_funcs = checksec.fortifiable
        if not fortifiable_funcs:
            print(f"Fortifiable: {Fore.RED}No{Style.RESET_ALL}")
        else:
            print(f"Fortifiable: {Fore.GREEN}{len(fortifiable_funcs)}{Style.RESET_ALL}")

        if checksec.is_fortified and len(fortifiable_funcs) == 0:
            score = 100
            print(f"Fortify Score: {Fore.GREEN}{score}%{Style.RESET_ALL}")
        elif not checksec.is_fortified and len(fortifiable_funcs) == 0:
            score = 0
            print(f"Fortify Score: {Fore.RED}{score}%{Style.RESET_ALL}")
        else:
            score = (len(fortified_funcs) * 100) / (len(fortified_funcs) + len(fortifiable_funcs))
            score = round(score)
            color = Fore.YELLOW
            if score == 100:
                color = Fore.GREEN
            print(f"Fortify Score: {color}{score}%{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
