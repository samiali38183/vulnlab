"""Render docs/img/hero.png from a real test run and the saved lab artifacts.

Numbers come from: a fresh `pytest` run (JUnit XML), each lab's sinkline/expected.json, and a replay
of each lab's Sigma rule over its recorded sample logs. Nothing is typed in except labels.

Run from the repo root:  python tools/make_hero.py            (runs the whole suite, about 2 minutes)
                         python tools/make_hero.py junit.xml  (reuse an existing JUnit file)
Needs matplotlib and Pillow in addition to the dev install.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from PIL import Image

from vulnlab_common.replay import read_ndjson, replay

ROOT = Path(__file__).resolve().parent.parent

# Shared look across samiali38183 repos: light background, dark text, large type.
TEXT, MUTED, LINE, PANEL = "#111827", "#4b5563", "#d1d5db", "#f3f4f6"
GOOD, WARN, GREY = "#15803d", "#b45309", "#4b5563"
GOOD_BG, WARN_BG, GREY_BG = "#dcfce7", "#fef3c7", "#e5e7eb"
plt.rcParams["font.family"] = "DejaVu Sans"

LABS = [
    ("01-ssrf-redirect", "SSRF via redirect", "CWE-918"),
    ("02-sqli-order-by", "SQL injection", "CWE-89, ORDER BY"),
    ("03-idor-bola", "IDOR (BOLA)", "CWE-639"),
]


def run_suite(junit: Path) -> None:
    subprocess.run([sys.executable, "-m", "pytest", "-q", f"--junitxml={junit}"], cwd=ROOT, check=False)


def count_tests(junit: Path) -> tuple[Counter[str], int, int]:
    per_lab: Counter[str] = Counter()
    passed = total = 0
    for tc in ET.parse(junit).getroot().iter("testcase"):
        total += 1
        bad = any(child.tag in ("failure", "error", "skipped") for child in tc)
        if bad:
            continue
        passed += 1
        parts = tc.get("classname", "").split(".")
        if parts[0] == "labs":
            per_lab[parts[1]] += 1
    return per_lab, passed, total


def rule_for(lab: str) -> Path | None:
    found = sorted((ROOT / "labs" / lab / "detection").glob("*.yml"))
    return found[0] if found else None


def alerts(lab: str, sample: str) -> int:
    rule = rule_for(lab)
    events = read_ndjson(ROOT / "labs" / lab / "detection" / sample)
    return len(replay(rule, events)) if rule else -1


def box(ax, x, y, w, h, fc, ec=LINE, lw=1.5, r=1.2) -> None:
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}", fc=fc, ec=ec, lw=lw))


def main() -> None:
    if len(sys.argv) > 1:
        junit = Path(sys.argv[1])
    else:
        junit = Path(tempfile.mkdtemp()) / "junit.xml"
        run_suite(junit)
    per_lab, passed, total = count_tests(junit)

    fig = plt.figure(figsize=(9, 5.5), dpi=200, facecolor="white")
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 180)
    ax.set_ylim(0, 110)
    ax.axis("off")

    ax.text(
        6,
        101,
        "Three web bugs: exploited, fixed, checked twice",
        fontsize=20,
        fontweight="bold",
        color=TEXT,
        va="center",
    )
    ax.text(
        6,
        92,
        "Each lab is a small service that runs only on localhost, with a proof of impact, a fix, "
        "a static scan and a log rule.",
        fontsize=10.6,
        color=MUTED,
        va="center",
    )

    box(ax, 6, 19, 168, 66, PANEL)
    cols = [
        (50, "Proof and fix", "lab tests"),
        (88, "sinkline scan", "vulnerable / fixed"),
        (130, "Sigma log rule", "attack log / benign log"),
    ]
    ax.text(10, 78, "Lab", fontsize=10.5, fontweight="bold", color=TEXT, va="center")
    for x, head, sub in cols:
        ax.text(x, 79.5, head, fontsize=10.5, fontweight="bold", color=TEXT, va="center")
        ax.text(x, 75.3, sub, fontsize=8.3, color=MUTED, va="center")

    for i, (lab, name, cwe) in enumerate(LABS):
        y = 57 - i * 16  # row bottom
        exp = json.loads((ROOT / "labs" / lab / "sinkline" / "expected.json").read_text("utf-8"))
        sv, sf = exp["vulnerable"]["count"], exp["fixed"]["count"]
        att, ben = alerts(lab, "sample_attack.ndjson"), alerts(lab, "sample_benign.ndjson")
        ax.text(10, y + 8, name, fontsize=10.5, fontweight="bold", color=TEXT, va="center")
        ax.text(10, y + 3.5, f"lab {lab[:2]}, {cwe}", fontsize=8.3, color=MUTED, va="center")

        cells = [
            (50, 34, f"{per_lab[lab]} tests pass", "exploit works, fix blocks it", GOOD, GOOD_BG),
            (
                88,
                38,
                f"{sv} / {sf} findings",
                "right, then a false alarm" if sv and sf else "no taint flow to follow",
                WARN if sv and sf else GREY,
                WARN_BG if sv and sf else GREY_BG,
            ),
            (
                130,
                41,
                f"{att} alert / {ben} alerts",
                "fires on attack log, not benign",
                GOOD,
                GOOD_BG,
            ),
        ]
        for x, w, big, small, fg, bg in cells:
            box(ax, x, y, w, 12, bg, ec=fg, lw=1.4, r=1)
            ax.text(x + 2, y + 8, big, fontsize=10.5, fontweight="bold", color=fg, va="center")
            ax.text(x + 2, y + 3.5, small, fontsize=8.3, color=TEXT, va="center")

    ax.text(
        6,
        14,
        "sinkline reports the fixed code too because it does not treat a custom allow-list as a "
        "sanitizer. Lab 03 is not a taint flow.",
        fontsize=9.6,
        color=TEXT,
        va="center",
    )
    ax.text(
        6,
        9,
        "Those misses are left in and written up, not hidden. Not vulnerability research: "
        "textbook bug classes, no CVEs.",
        fontsize=8.8,
        color=MUTED,
        va="center",
    )
    ax.text(
        6,
        4,
        f"{passed} of {total} tests pass. Run {datetime.date.today()}.  Source: pytest run, "
        "labs/*/sinkline/expected.json, Sigma replay.  Reproduce: python tools/make_hero.py",
        fontsize=8,
        color=MUTED,
        va="center",
    )

    out = ROOT / "docs" / "img" / "hero.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=200, facecolor="white")
    Image.open(out).convert("RGB").quantize(colors=64, dither=Image.Dither.NONE).save(out, optimize=True)
    print(f"wrote {out}  ({passed}/{total} tests)")


if __name__ == "__main__":
    main()
