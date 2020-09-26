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
from typing import List, Union

from docopt import docopt
from rich import print

from .elf import ELFChecksecData, ELFSecurity, is_elf
from .errors import ErrorNotAnElf, ErrorParsingFailed
from .output import JSONOutput, RichOutput
from .pe import PEChecksecData, PESecurity, is_pe


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


def checksec_file(filepath: Path) -> Union["ELFChecksecData", "PEChecksecData"]:
    if not filepath.exists():
        raise FileNotFoundError()
    if is_elf(filepath):
        binary = ELFSecurity(filepath)
    elif is_pe(filepath):
        binary = PESecurity(filepath)
    else:
        raise NotImplementedError
    return binary.checksec_state


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
                except NotImplementedError:
                    if debug:
                        print(f"{filepath} executable format is not supported. (Only ELF or PE)")
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
