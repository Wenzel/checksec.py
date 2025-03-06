#!/usr/bin/env python3

"""
Usage: checksec.py [options] <file/directory>...

Options:
    -r --recursive                  Walk directories recursively
    -w WORKERS --workers=WORKERS    Specify the number of process pool workers [default: 4]
    -j --json                       Display results as JSON
    -s LIBC --set-libc=LIBC         Specify LIBC library to use to check for fortify scores (ELF)
    -d --debug                      Enable debug output
    -h --help                       Display this message
"""

import logging
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator, List, Optional, Union

from docopt import docopt

from .elf import ELFChecksecData, ELFSecurity, get_libc, is_elf
from .errors import ErrorParsingFailed
from .output import JSONOutput, RichOutput
from .pe import PEChecksecData, PESecurity, is_pe
from .utils import lief_set_logging


def walk_filepath_list(filepath_list: List[Path], recursive: bool = False) -> Iterator[Path]:
    for path in filepath_list:
        if path.is_dir() and not path.is_symlink():
            try:
                if recursive:
                    for f in os.scandir(path):
                        yield from walk_filepath_list([Path(f)], recursive)
                else:
                    yield from (Path(f) for f in os.scandir(path))
            except OSError:
                continue
        elif path.is_file():
            yield path


def checksec_file(filepath: Path) -> Union["ELFChecksecData", "PEChecksecData"]:
    """Check the security of a given file. Workers main execution"""
    logging.debug("Worker %s: checking %s", os.getpid(), filepath)
    if not filepath.exists():
        raise FileNotFoundError()
    if is_elf(filepath):
        binary = ELFSecurity(filepath)
    elif is_pe(filepath):
        binary = PESecurity(filepath)
    else:
        raise NotImplementedError
    return binary.checksec_state


def worker_initializer(libc_path: Optional[Path] = None):
    """Routine to initialize some context in a worker process"""
    # this function is used to set global object in the worker's process context
    # multiprocessing has different behaviors on Windows and Linux
    # on Windows, the global object __LIBC_OBJ in elf.py is found to be uninitialized,
    # even after we explicitely initialized it in the main function.
    #
    # this function ensures that the object is initialized with the libc_path passed as cmdline argument
    logging.debug("Worker %s: initializer", os.getpid())
    get_libc(libc_path)


def main(args):
    filepath_list = [Path(entry) for entry in args["<file/directory>"]]
    debug = args["--debug"]
    workers = int(args["--workers"])
    json = args["--json"]
    recursive = args["--recursive"]
    libc_path = args["--set-libc"]

    # logging
    formatter = "%(asctime)s %(levelname)s:%(name)s:%(message)s"
    log_lvl = logging.INFO
    lief_logging = logging.CRITICAL  # silence lief warnings
    if debug:
        log_lvl = logging.DEBUG
        lief_logging = logging.DEBUG
    logging.basicConfig(level=log_lvl, format=formatter)
    lief_set_logging(lief_logging)

    libc_detected = False
    # init Libc LIEF object
    # we can't pass this object to ELFSecurity class as it isn't picklable
    libc = get_libc(libc_path)
    if not libc:
        # libc initialization failed
        if libc_path:
            # a libc path was specified, report error
            logging.critical("Could not find Libc at %s", libc_path)
            return 1
        logging.debug("Could not locate libc. Skipping fortify tests for ELF.")
    else:
        libc_detected = True

    # default output: Rich console
    output_cls = RichOutput
    if json:
        output_cls = JSONOutput

    with output_cls(libc_detected) as check_output:
        try:
            # we need to consume the iterator once to get the total
            # for the progress bar
            check_output.enumerating_tasks_start()
            count = sum(1 for i in walk_filepath_list(filepath_list, recursive))
            check_output.enumerating_tasks_stop(count)
            with ProcessPoolExecutor(
                max_workers=workers, initializer=worker_initializer, initargs=(libc_path,)
            ) as pool:
                try:
                    check_output.processing_tasks_start()
                    future_to_checksec = {
                        pool.submit(checksec_file, filepath): filepath
                        for filepath in walk_filepath_list(filepath_list, recursive)
                    }
                    for future in as_completed(future_to_checksec):
                        filepath = future_to_checksec[future]
                        try:
                            data = future.result()
                        except FileNotFoundError:
                            logging.debug("%s does not exist", filepath)
                        except ErrorParsingFailed:
                            logging.debug("%s LIEF parsing failed")
                        except NotImplementedError:
                            logging.debug("%s: Not an ELF/PE. Skipping", filepath)
                        else:
                            check_output.add_checksec_result(filepath, data)
                        finally:
                            check_output.checksec_result_end()
                except KeyboardInterrupt:
                    # remove progress bars before waiting for ProcessPoolExecutor to shutdown
                    check_output.__exit__(None, None, None)
                    logging.info("Shutdown Process Pool ...")
                    pool.shutdown(wait=True)
                    raise
        except KeyboardInterrupt:
            pass
        else:
            check_output.print()


def entrypoint():
    args = docopt(__doc__)
    try:
        main(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    entrypoint()
