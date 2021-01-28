import logging
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Dict

import lddwrap
# cannot use is_elf because of circular dependency
import lief
from lief.logging import LOGGING_LEVEL as lief_loglvl


class LibcNotFoundError(Exception):
    pass


LIBC_PATH_POSSIBILITIES = [
    "/lib/libc.so.6",
    "/lib/libc.so.7",
    "/lib/libc.so",
    "/lib64/libc.so.6",
    "/lib/i386-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/arm-linux-gnueabihf/libc.so.6",
    "/lib/aarch64-linux-gnu/libc.so.6",
    "/usr/x86_64-gentoo-linux-musl/bin/ld",
]
PY_LOG_TO_LIEF_LOG: Dict[int, lief_loglvl] = {
    0: lief_loglvl.TRACE,
    logging.DEBUG: lief_loglvl.DEBUG,
    logging.INFO: lief_loglvl.INFO,
    logging.WARNING: lief_loglvl.WARNING,
    logging.ERROR: lief_loglvl.ERROR,
    logging.CRITICAL: lief_loglvl.CRITICAL,
}


def find_libc():
    """Find the fullpath to the libc library with multiple methods"""
    libc_path = None
    try:
        libc_path = find_library_full("c")
    except (FileNotFoundError, AttributeError, RuntimeError):
        # ldconfig is not accessible as user
        # or running on Windows
        # or other errors
        try:
            libc_path = find_libc_ldd()
        except (FileNotFoundError, RuntimeError):
            # test hardcoded paths
            logging.debug("Finding libc path: hardcoded paths")
            for maybe_libc in LIBC_PATH_POSSIBILITIES:
                logging.debug("Testing libc at %s", maybe_libc)
                maybe_libc_path = Path(maybe_libc)
                if maybe_libc_path.exists():
                    # symlink
                    if maybe_libc_path.is_symlink():
                        dst = os.readlink(str(maybe_libc_path))
                        logging.debug("Resolve symlink %s -> %s", maybe_libc_path, dst)
                        maybe_libc_path = Path(dst)
                if lief.is_elf(str(maybe_libc_path)):
                    libc_path = maybe_libc
                    break
    if libc_path is None:
        raise LibcNotFoundError("Cannot find a suitable libc path on your system")
    logging.debug("Found libc: %s", libc_path)
    return libc_path


def find_libc_ldd():
    """Find libc path with ldd utility"""
    logging.debug("Finding libc path: ldd")
    # first get ld path
    ld_path = shutil.which("ld")
    if not ld_path:
        raise FileNotFoundError("Failed to locate ld executable")
    # find libc
    libc_possibles = [
        dep.path
        for dep in lddwrap.list_dependencies(Path(ld_path))
        if dep.soname is not None and dep.soname.startswith("libc.so")
    ]
    if not libc_possibles:
        raise FileNotFoundError("Failed to find libc")
    if len(libc_possibles) > 1:
        raise FileNotFoundError("Found multiple libc")
    return libc_possibles[0]


def find_library_full(name):
    """https://stackoverflow.com/a/29227195/3017219

    :raise:
        AttributeError: if an attribute is not found on OS module
        RuntimeError"""
    logging.debug("Finding libc path: ldconfig")
    # see ctypes.find_library code
    # Note: os.uname is OS dependant, will raise AttributeError
    uname = os.uname()[4]
    if uname.startswith("arm"):
        uname = "arm"
    if struct.calcsize("l") == 4:
        machine = uname + "-32"
    else:
        machine = uname + "-64"
    mach_map = {
        "x86_64-64": "libc6,x86-64",
        "ppc64-64": "libc6,64bit",
        "sparc64-64": "libc6,64bit",
        "s390x-64": "libc6,64bit",
        "ia64-64": "libc6,IA-64",
        "arm-32": "libc6(,hard-float)?",
    }
    abi_type = mach_map.get(machine, "libc6")
    # Note, we search libXXX.so.XXX, not just libXXX.so (!)
    expr = re.compile(r"^\s+lib%s\.so.[^\s]+\s+\(%s.*=>\s+(.*)$" % (re.escape(name), abi_type))
    p = subprocess.Popen(["ldconfig", "-N", "-p"], stdout=subprocess.PIPE)
    result = None
    for line in p.stdout:
        res = expr.match(line.decode())
        if res is None:
            continue
        if result is not None:
            raise RuntimeError("Duplicate library found for %s" % name)
        result = res.group(1)
    if p.wait():
        raise RuntimeError('"ldconfig -p" failed')
    if result is None:
        raise RuntimeError("Library %s not found" % name)
    return result


def lief_set_logging(lvl: int):
    """Configures LIEF logging level

    lvl: Python numeric logging level, corresponding to the logging module level values


    example:
        import logging
        lief_set_logging(logging.WARNING)
    """
    try:
        lief_log = PY_LOG_TO_LIEF_LOG[lvl]
    except KeyError as e:
        raise RuntimeError(f"Failed to find LIEF logging level for {lvl}") from e
    else:
        lief.logging.set_level(lief_log)
