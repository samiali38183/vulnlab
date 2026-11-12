"""Capture or verify the documented sinkline results for each lab.

python tools/sinkline_check.py --capture   write labs/*/sinkline/{vulnerable,fixed}.txt and
                                           expected.json from a real run
python tools/sinkline_check.py             re-scan and fail if findings differ from expected.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

from vulnlab_common.loader import REPO, lab_dirs

VARIANTS = ("vulnerable", "fixed")
SINKLINE = [sys.executable, "-m", "sinkline"]  # the active interpreter's sinkline, never one found on PATH


class VersionMismatch(RuntimeError):
    pass


def pinned_version() -> str:
    """The sinkline release pyproject.toml pins (the git tag, without the leading v)."""
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"sinkline @ git\+\S+@v(\d+\.\d+\.\d+\S*?)\"", text)
    if not match:
        raise VersionMismatch("could not find the sinkline pin in pyproject.toml")
    return match.group(1)


def check_version() -> str:
    """Fail loudly unless the interpreter running this tool has the pinned sinkline installed."""
    expected = pinned_version()
    try:
        installed = metadata.version("sinkline")
    except metadata.PackageNotFoundError:
        raise VersionMismatch(
            f"sinkline is not installed in {sys.executable}; install requirements.lock"
        ) from None
    if installed != expected:
        raise VersionMismatch(
            f"sinkline {installed} is installed in {sys.executable} but pyproject.toml pins {expected}; "
            "run: pip install -r requirements.lock"
        )
    return installed


def scan(lab: Path, variant: str, fmt: str) -> str:
    args = [*SINKLINE, "scan", variant, "--no-color", "--format", fmt]
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    run = subprocess.run(args, cwd=lab, capture_output=True, text=True, encoding="utf-8", check=True, env=env)
    return run.stdout


def summarize(report_json: str) -> dict:
    report = json.loads(report_json)
    findings = sorted((f["rule_id"], f["file"], f["line"]) for f in report["findings"])
    return {
        "count": len(findings),
        "findings": [{"rule_id": r, "file": f, "line": n} for r, f, n in findings],
        "version": report["version"],
    }


def capture(lab: Path) -> None:
    out = lab / "sinkline"
    expected = {"command": "sinkline scan <variant> --no-color (run from the lab directory)"}
    for variant in VARIANTS:
        text = scan(lab, variant, "text")
        (out / f"{variant}.txt").write_text(f"$ sinkline scan {variant} --no-color\n{text}", encoding="utf-8")
        expected[variant] = summarize(scan(lab, variant, "json"))
    (out / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")


def verify(lab: Path) -> list[str]:
    expected = json.loads((lab / "sinkline" / "expected.json").read_text(encoding="utf-8"))
    problems = []
    for variant in VARIANTS:
        actual = summarize(scan(lab, variant, "json"))
        if actual != expected[variant]:
            problems.append(f"{lab.name}/{variant}: expected {expected[variant]}, got {actual}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", action="store_true")
    args = parser.parse_args()
    try:
        print(f"sinkline {check_version()} ({sys.executable})")
    except VersionMismatch as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    problems: list[str] = []
    for lab in lab_dirs():
        if args.capture:
            capture(lab)
            print(f"captured {lab.name}")
        else:
            problems += verify(lab)
            print(f"checked {lab.name}")
    for problem in problems:
        print("MISMATCH", problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
