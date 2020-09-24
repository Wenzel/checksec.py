#!/usr/bin/env python3

"""
Usage: checksec.py [options] <file/directory>...

Options:
    -r --recursive                  Walk directories recursively
    -w WORKERS --workers=WORKERS    Specify the number of process pool workers [default: 4]
    -j --json                       Display results as JSON
    -d --debug                      Enable debug output
    -h --help                       Display this message
"""

import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import List

from docopt import docopt
from rich import print

from .elf import ELFChecksecData, ELFSecurity, is_elf
from .errors import ErrorNotAnElf, ErrorParsingFailed
from .output import JSONOutput, RichOutput


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


def checksec_file(filepath: Path) -> ELFChecksecData:
    if not filepath.exists():
        raise FileNotFoundError()
    if not is_elf(filepath):
        raise ErrorNotAnElf(filepath)
    checksec = ELFSecurity(filepath)

    fortified_count = len(checksec.fortified)
    fortifiable_count = len(checksec.fortifiable)
    if not checksec.is_fortified:
        score = 0
    else:
        # fortified
        if fortified_count == 0:
            # all fortified !
            score = 100
        else:
            score = (fortified_count * 100) / (fortified_count + fortifiable_count)
            score = round(score)

    fortify_source = True if fortified_count != 0 else False
    checksec_data = ELFChecksecData(
        checksec.relro,
        checksec.has_canary,
        checksec.has_nx,
        checksec.pie,
        checksec.has_rpath,
        checksec.has_runpath,
        not checksec.is_stripped,
        fortify_source,
        fortified_count,
        fortifiable_count,
        score,
    )
    return checksec_data


def main(args):
    filepath_list = [Path(entry) for entry in args["<file/directory>"]]
    debug = args["--debug"]
    workers = int(args["--workers"])
    json = args["--json"]
    recursive = args["--recursive"]

    # we need to consume the iterator once to get the total
    # for the progress bar
    count = sum(1 for i in walk_filepath_list(filepath_list, recursive))

    # default output: Rich console
    output_cls = RichOutput
    if json:
        output_cls = JSONOutput

    with output_cls(count) as check_output:
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
                    if debug:
                        print(f"{filepath} does not exist")
                except ErrorNotAnElf:
                    if debug:
                        print(f"{filepath} is not a valid ELF")
                except ErrorParsingFailed:
                    if debug:
                        print(f"{filepath} ELF parsing failed")
                else:
                    check_output.add_checksec_result(filepath, data)
                finally:
                    check_output.checksec_result_end()

        check_output.print()


def entrypoint():
    args = docopt(__doc__)
    main(args)


if __name__ == "__main__":
    entrypoint()
