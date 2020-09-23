import os
import re
import struct
import subprocess


def find_library_full(name):
    """https://stackoverflow.com/a/29227195/3017219"""
    # see ctypes.find_library code
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
