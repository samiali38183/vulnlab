"""Capture or verify the documented sinkline results for each lab.

python tools/sinkline_check.py --capture   write labs/*/sinkline/{vulnerable,fixed}.txt and
                                           expected.json from a real run
python tools/sinkline_check.py             re-scan and fail if findings differ from expected.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from vulnlab_common.loader import lab_dirs

VARIANTS = ("vulnerable", "fixed")


def scan(lab: Path, variant: str, fmt: str) -> str:
    args = ["sinkline", "scan", variant, "--no-color", "--format", fmt]
    return subprocess.run(args, cwd=lab, capture_output=True, text=True, check=True).stdout


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
