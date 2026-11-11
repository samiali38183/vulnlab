"""Load a lab's modules by path (lab directory names are not valid package names)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parent.parent
LABS = REPO / "labs"


def load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def lab_dirs() -> list[Path]:
    return sorted(p for p in LABS.iterdir() if p.is_dir() and (p / "lab.py").exists())
