import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict

CHECKSEC_BIN = shutil.which("checksec")


def run_checksec(bin_path: Path, libc_path: Path = None) -> Dict:
    """Runs checksec from command line, returns json output as dict"""
    cmd = [CHECKSEC_BIN, str(bin_path), "-j"]
    if libc_path:
        cmd.extend(["-s", str(libc_path)])
    output = subprocess.check_output(cmd)
    return json.loads(output.decode())
