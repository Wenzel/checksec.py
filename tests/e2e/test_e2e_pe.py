"""E2E tests for PE"""

from pathlib import Path

import pytest

from checksec.binary import NX
from tests.conftest import run_checksec

PE_BINARIES = Path(__file__).parent.parent / "binaries" / "pe"


@pytest.mark.parametrize("is_enabled", [False, True])
@pytest.mark.parametrize(
    "prop",
    [
        "canary",
        "dynamic_base",
        "aslr",
        "high_entropy_va",
        "safe_seh",
        "force_integrity",
        "guard_cf",
        "isolation",
        "authenticode",
    ],
)
def test_bool_prop(prop: str, is_enabled: bool):
    """Test that boolean prop is disabled/enabled"""
    bin_path = PE_BINARIES / f"{prop}_{'enabled' if is_enabled else 'disabled'}.exe"
    chk_data = run_checksec(bin_path)
    assert chk_data[str(bin_path)][prop] == is_enabled


@pytest.mark.parametrize("nx", list(NX))
def test_nx(nx: NX):
    """Test that nx is No/Yes"""
    # NA not possible for PE (only for ELF)
    if nx != NX.NA:
        bin_path = PE_BINARIES / f"nx_{'enabled' if nx == NX.Yes else 'disabled'}.exe"
        chk_data = run_checksec(bin_path)
        assert chk_data[str(bin_path)]["nx"] == nx.name
