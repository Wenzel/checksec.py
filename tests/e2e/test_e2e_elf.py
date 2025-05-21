"""E2E tests for ELF"""

from pathlib import Path

import pytest

from checksec.elf import PIEType, RelroType
from tests.conftest import run_checksec

ELF_BINARIES = Path(__file__).parent.parent / "binaries" / "elf"


@pytest.mark.parametrize("is_enabled", [False, True])
@pytest.mark.parametrize("prop", ["nx", "canary", "rpath", "runpath", "symbols", "fortify_source"])
def test_bool_prop(prop: str, is_enabled: bool):
    """Test that boolean prop is disabled/enabled"""
    libc_path = ELF_BINARIES / "libc-2.27.so"
    bin_path = ELF_BINARIES / f"{prop}_{'enabled' if is_enabled else 'disabled'}"
    chk_data = run_checksec(bin_path, libc_path)
    assert chk_data[str(bin_path)][prop] == is_enabled


@pytest.mark.parametrize("relro_type", list(RelroType))
def test_relro(relro_type: RelroType):
    """Test that relro type is No/Partial/Full/NA"""
    bin_path = ELF_BINARIES / f"relro_{relro_type.name.lower()}"
    chk_data = run_checksec(bin_path)
    assert chk_data[str(bin_path)]["relro"] == relro_type.name


def test_relro_full_df1():
    """Test that relro type is full via dynamic flags 1"""
    bin_path = ELF_BINARIES / "relro_full_FLAGS_1"
    chk_data = run_checksec(bin_path)
    assert chk_data[str(bin_path)]["relro"] == RelroType.Full.name


@pytest.mark.parametrize("pie_type", list(PIEType))
def test_pie(pie_type):
    """Test that PIE is No/Partial/Full/NA"""
    bin_path = ELF_BINARIES / f"pie_{pie_type.name.lower()}"
    chk_data = run_checksec(bin_path)
    assert chk_data[str(bin_path)]["pie"] == pie_type.name


def test_fortified():
    """Test the fortified functions"""
    libc_path = ELF_BINARIES / "libc-2.27.so"
    bin_path = ELF_BINARIES / "fortify_funcs"
    chk_data = run_checksec(bin_path, libc_path)
    fortified_funcs = ["__fprintf_chk@@GLIBC_2.3.4", "__printf_chk@@GLIBC_2.3.4"]
    assert chk_data[str(bin_path)]["fortified"] == len(fortified_funcs)


def test_fortifiable():
    """Test the fortifiable functions"""
    libc_path = ELF_BINARIES / "libc-2.27.so"
    bin_path = ELF_BINARIES / "fortify_funcs"
    chk_data = run_checksec(bin_path, libc_path)
    fortified_funcs = ["__fprintf_chk@@GLIBC_2.3.4", "__printf_chk@@GLIBC_2.3.4"]
    non_fortified_funcs = ["fgets"]
    assert chk_data[str(bin_path)]["fortify-able"] == len(fortified_funcs) + len(non_fortified_funcs)


def test_fortify_score():
    """Test the fortify score"""
    libc_path = ELF_BINARIES / "libc-2.27.so"
    bin_path = ELF_BINARIES / "fortify_funcs"
    chk_data = run_checksec(bin_path, libc_path)
    fortified_funcs = ["__fprintf_chk@@GLIBC_2.3.4", "__printf_chk@@GLIBC_2.3.4"]
    non_fortified_funcs = ["fgets"]
    total = len(fortified_funcs) + len(non_fortified_funcs)
    assert chk_data[str(bin_path)]["fortify_score"] == round((2 * 100) / total, 0)
