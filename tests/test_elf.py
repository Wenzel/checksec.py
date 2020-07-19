from tempfile import NamedTemporaryFile
from pathlib import Path
from subprocess import check_call

from checksec.elf import ELFSecurity, PIEType, RelroType


MAIN_PATH = Path(__file__).parent / 'main.c'


def test_nx_enabled():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert elf.has_nx


def test_nx_disabled():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', '-z', 'execstack', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert not elf.has_nx


def test_canary_enabled():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', '-fstack-protector', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert elf.has_canary


def test_canary_disabled():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', '-fno-stack-protector', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert not elf.has_canary


def test_relro_disabled():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', '-Wl,-z,norelro', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert elf.relro == RelroType.No


def test_relro_full():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', '-Wl,-z,relro,-z,now', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert elf.relro == RelroType.Full


# TODO: DSO and PIE
def test_pie_disabled():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', '-no-pie', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert elf.pie == PIEType.No


def test_rpath_disabled():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert not elf.has_rpath


def test_rpath_enabled():
    with NamedTemporaryFile() as tmp_f:
        rpath = '/opt/lib'
        cmdline = ['gcc', '-Wl,--disable-new-dtags', f'-Wl,-rpath,{rpath}', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert elf.has_rpath


def test_runpath_disabled():
    with NamedTemporaryFile() as tmp_f:
        cmdline = ['gcc', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert not elf.has_runpath


def test_runpath_enabled():
    with NamedTemporaryFile() as tmp_f:
        rpath = '/opt/lib'
        cmdline = ['gcc', '-Wl,--enable-new-dtags', f'-Wl,-rpath,{rpath}', str(MAIN_PATH), '-o', tmp_f.name]
        check_call(cmdline)
        elf = ELFSecurity(Path(tmp_f.name))
        assert elf.has_runpath
