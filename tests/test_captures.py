"""The recorded sinkline outputs must be readable UTF-8, not double-encoded text."""

from __future__ import annotations

from pathlib import Path

import pytest

CAPTURES = sorted(Path(__file__).resolve().parents[1].glob("labs/*/sinkline/*.txt"))
MOJIBAKE_MARKERS = ("â", "Ã", "�")


def test_captures_exist():
    assert len(CAPTURES) == 6


@pytest.mark.parametrize("path", CAPTURES, ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_capture_is_not_double_encoded(path):
    text = path.read_text(encoding="utf-8")
    for marker in MOJIBAKE_MARKERS:
        assert marker not in text, f"{path} contains {marker!r}: re-run tools/sinkline_check.py capture"


@pytest.mark.parametrize("path", CAPTURES, ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_finding_captures_keep_their_path_glyphs(path):
    text = path.read_text(encoding="utf-8")
    if "[HIGH]" in text or "[CRITICAL]" in text:
        assert "┌" in text and "└" in text
