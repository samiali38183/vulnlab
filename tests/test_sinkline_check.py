"""tools/sinkline_check.py must run the active interpreter's sinkline and refuse a version mismatch."""

from __future__ import annotations

import sys
from importlib import metadata

import pytest

from vulnlab_common.loader import REPO, load

check = load(REPO / "tools" / "sinkline_check.py", "sinkline_check_tool")


def test_pinned_version_comes_from_pyproject():
    assert check.pinned_version() == metadata.version("sinkline")


def test_matching_version_passes():
    assert check.check_version() == check.pinned_version()


def test_a_different_installed_version_fails_loudly(monkeypatch):
    monkeypatch.setattr(check.metadata, "version", lambda name: "0.3.0")
    with pytest.raises(check.VersionMismatch, match=r"0\.3\.0.*pins"):
        check.check_version()


def test_a_missing_install_fails_loudly(monkeypatch):
    def missing(name):
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(check.metadata, "version", missing)
    with pytest.raises(check.VersionMismatch, match="not installed"):
        check.check_version()


def test_scans_run_through_the_active_interpreter_not_path():
    assert check.SINKLINE[:2] == [sys.executable, "-m"]


def test_main_exits_2_on_mismatch(monkeypatch, capsys):
    monkeypatch.setattr(check.metadata, "version", lambda name: "0.3.0")
    monkeypatch.setattr(sys, "argv", ["sinkline_check.py"])
    assert check.main() == 2
    assert "ERROR" in capsys.readouterr().err
