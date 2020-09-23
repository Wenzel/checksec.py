#!/usr/bin/env python3

"""
Usage: checksec.py [options] <file/directory>...

Options:
    -r --recursive                  Walk directories recursively
    -w WORKERS --workers=WORKERS    Specify the number of process pool workers [default: 4]
    -d --debug                      Enable debug output
    -h --help                       Display this message
"""

import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import List

from docopt import docopt
from rich import print
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from .elf import ELFSecurity, PIEType, RelroType, is_elf
from .errors import ErrorNotAnElf, ErrorParsingFailed


def walk_filepath_list(filepath_list: List[Path], recursive: bool = False):
    for path in filepath_list:
        if path.is_dir() and not path.is_symlink():
            if recursive:
                for f in os.scandir(path):
                    yield from walk_filepath_list([Path(f)], recursive)
            else:
                yield from (Path(f) for f in os.scandir(path))
        elif path.is_file():
            yield path


def checksec_file(filepath: Path):
    if not filepath.exists():
        raise FileNotFoundError()
    if not is_elf(filepath):
        raise ErrorNotAnElf(filepath)
    checksec = ELFSecurity(filepath)
    # display results
    relro = checksec.relro
    if relro == RelroType.No:
        relro_res = f"[red]{relro.name}"
    elif relro == RelroType.Partial:
        relro_res = f"[yellow]{relro.name}"
    else:
        relro_res = f"[green]{relro.name}"

    if not checksec.has_canary:
        canary_res = "[red]No"
    else:
        canary_res = "[green]Yes"

    if not checksec.has_nx:
        nx_res = "[red]No"
    else:
        nx_res = "[green]Yes"

    pie = checksec.pie
    if pie == PIEType.No:
        pie_res = f"[red]{pie.name}"
    elif pie == PIEType.DSO:
        pie_res = f"[yellow]{pie.name}"
    else:
        pie_res = "[green]Yes"

    if checksec.has_rpath:
        rpath_res = "[red]Yes"
    else:
        rpath_res = "[green]No"

    if checksec.has_runpath:
        runpath_res = "[red]Yes"
    else:
        runpath_res = "[green]No"

    if not checksec.is_stripped:
        symbols_res = "[red]Yes"
    else:
        symbols_res = "[green]No"

    fortified_funcs = checksec.fortified
    if not fortified_funcs:
        fortified_res = "[red]No"
    else:
        fortified_res = f"[green]{len(fortified_funcs)}"

    fortifiable_funcs = checksec.fortifiable
    if not fortifiable_funcs:
        fortifiable_res = "[red]No"
    else:
        fortifiable_res = f"[green]{len(fortifiable_funcs)}"

    if not checksec.is_fortified:
        score = 0
        fortified_score_res = f"[red]{score}"
    else:
        # fortified
        if len(fortified_funcs) == 0:
            # all fortified !
            score = 100
            fortified_score_res = f"[green]{score}"
        else:
            score = (len(fortified_funcs) * 100) / (len(fortified_funcs) + len(fortifiable_funcs))
            score = round(score)
            color_str = "yellow"
            if score == 100:
                color_str = "green"
            fortified_score_res = f"[{color_str}]{score}"

    return {
        "relro": relro_res,
        "canary": canary_res,
        "nx": nx_res,
        "pie": pie_res,
        "rpath": rpath_res,
        "runpath": runpath_res,
        "symbols": symbols_res,
        "fortified": fortified_res,
        "fortifiable": fortifiable_res,
        "fortified_score": fortified_score_res,
    }


def main(args):
    filepath_list = [Path(entry) for entry in args["<file/directory>"]]
    workers = int(args["--workers"])
    recursive = args["--recursive"]

    table = Table(title="Checksec Results", expand=True)
    table.add_column("File", justify="left", header_style="")
    table.add_column("Relro", justify="center")
    table.add_column("Canary", justify="center")
    table.add_column("NX", justify="center")
    table.add_column("PIE", justify="center")
    table.add_column("RPATH", justify="center")
    table.add_column("RUNPATH", justify="center")
    table.add_column("Symbols", justify="center")
    table.add_column("Fortified", justify="center")
    table.add_column("Fortifiable", justify="center")
    table.add_column("Fortify Score", justify="center")

    # build progress bar
    progress_bar = Progress(
        TextColumn("[bold blue]Processing...", justify="left"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
    )

    console = Console()

    # we need to consume the iterator once to get the total
    # for the progress bar
    count = sum(1 for i in walk_filepath_list(filepath_list, recursive))

    with progress_bar:
        task_id = progress_bar.add_task("Checking", total=count)
        with ProcessPoolExecutor(max_workers=workers) as pool:
            future_to_checksec = {
                pool.submit(checksec_file, filepath): filepath
                for filepath in walk_filepath_list(filepath_list, recursive)
            }
            for future in as_completed(future_to_checksec):
                filepath = future_to_checksec[future]
                try:
                    data = future.result()
                except FileNotFoundError:
                    print(f"{filepath} does not exist")
                except ErrorNotAnElf:
                    print(f"{filepath} is not a valid ELF")
                except ErrorParsingFailed:
                    print(f"{filepath} ELF parsing failed")
                else:
                    table.add_row(
                        str(filepath),
                        data["relro"],
                        data["canary"],
                        data["nx"],
                        data["pie"],
                        data["rpath"],
                        data["runpath"],
                        data["symbols"],
                        data["fortified"],
                        data["fortifiable"],
                        data["fortified_score"],
                    )
                finally:
                    progress_bar.update(task_id, advance=1)

    console.print(table)


def entrypoint():
    args = docopt(__doc__)
    main(args)


if __name__ == "__main__":
    entrypoint()
