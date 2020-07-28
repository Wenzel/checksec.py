#!/usr/bin/env python3

"""
Usage: capture.py [options] <file>...

Options:
    -h --help                       Display this message
    -d --debug                      Enable debug output
"""

import os
from pathlib import Path
from typing import List

from docopt import docopt
from rich import print
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from .elf import ELFSecurity, PIEType, RelroType, is_elf
from .errors import ErrorParsingFailed


def walk_filepath_list(filepath_list: List[Path]):
    for entry in filepath_list:
        if entry.is_file():
            yield entry
        else:
            yield from [Path(f) for f in os.scandir(entry)]


def main(args):
    filepath_list = [Path(entry) for entry in args['<file>']]

    table = Table(title='Checksec Results', expand=True)
    table.add_column('File', justify='left', header_style='')
    table.add_column('Relro', justify='center')
    table.add_column('Canary', justify='center')
    table.add_column('NX', justify='center')
    table.add_column('PIE', justify='center')
    table.add_column('RPATH', justify='center')
    table.add_column('RUNPATH', justify='center')
    table.add_column('Symbols', justify='center')
    table.add_column('Fortified', justify='center')
    table.add_column('Fortifiable', justify='center')
    table.add_column('Fortify Score', justify='center')

    # build progress bar
    progress_bar = Progress(
        TextColumn("[bold blue]Processing...", justify="left"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        TimeRemainingColumn()
    )

    console = Console()

    # we need to consume the iterator once to get the total
    # for the progress bar
    count = sum(1 for i in walk_filepath_list(filepath_list))

    with progress_bar:
        task_id = progress_bar.add_task("Checking", total=count)
        for index, filepath in enumerate(walk_filepath_list(filepath_list)):
            if not filepath.exists():
                progress_bar.update(task_id, advance=1)
                continue
            if not is_elf(filepath):
                progress_bar.update(task_id, advance=1)
                continue
            try:
                checksec = ELFSecurity(filepath)
            except ErrorParsingFailed:
                print(f"Failed to process {filepath}")
                progress_bar.update(task_id, advance=1)
                continue

            # display results
            relro = checksec.relro
            if relro == RelroType.No:
                relro_res = f'[red]{relro.name}'
            elif relro == RelroType.Partial:
                relro_res = f'[yellow]{relro.name}'
            else:
                relro_res = f'[green]{relro.name}'

            if not checksec.has_canary:
                canary_res = '[red]No'
            else:
                canary_res = '[green]Yes'

            if not checksec.has_nx:
                nx_res = '[red]No'
            else:
                nx_res = '[green]Yes'

            pie = checksec.pie
            if pie == PIEType.No:
                pie_res = f'[red]{pie.name}'
            elif pie == PIEType.DSO:
                pie_res = f'[yellow]{pie.name}'
            else:
                pie_res = '[green]Yes'

            if checksec.has_rpath:
                rpath_res = '[red]Yes'
            else:
                rpath_res = '[green]No'

            if checksec.has_runpath:
                runpath_res = '[red]Yes'
            else:
                runpath_res = '[green]No'

            if not checksec.is_stripped:
                symbols_res = '[red]Yes'
            else:
                symbols_res = '[green]No'

            fortified_funcs = checksec.fortified
            if not fortified_funcs:
                fortified_res = '[red]No'
            else:
                fortified_res = f'[green]{len(fortified_funcs)}'

            fortifiable_funcs = checksec.fortifiable
            if not fortifiable_funcs:
                fortifiable_res = '[red]No'
            else:
                fortifiable_res = f'[green]{len(fortifiable_funcs)}'

            if checksec.is_fortified and len(fortifiable_funcs) == 0:
                score = 100
                fortified_score_res = f'[green]{score}'
            elif not checksec.is_fortified and len(fortifiable_funcs) == 0:
                score = 0
                fortified_score_res = f'[red]{score}'
            else:
                score = (len(fortified_funcs) * 100) / (len(fortified_funcs) + len(fortifiable_funcs))
                score = round(score)
                color_str = 'yellow'
                if score == 100:
                    color_str = 'green'
                fortified_score_res = f'[{color_str}]{score}'

            progress_bar.update(task_id, advance=1)
            table.add_row(str(filepath), relro_res, canary_res, nx_res, pie_res, rpath_res, runpath_res, symbols_res,
                          fortified_res, fortifiable_res, fortified_score_res)

    console.print(table)


def entrypoint():
    args = docopt(__doc__)
    main(args)


if __name__ == "__main__":
    entrypoint()
