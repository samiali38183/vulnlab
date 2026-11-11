#!/usr/bin/env bash
# End-to-end run of lab 01. Every step prints real output from this machine.
set -euo pipefail
cd "$(dirname "$0")/.."
LAB=labs/01-ssrf-redirect
RULE=$LAB/detection/web_ssrf_preview_internal_address.yml

step() { printf '\n=== %s ===\n' "$1"; }

step "1. vulnerable service: the preview endpoint returns the internal service's canary via an allowed redirect"
python -m pytest -v -s -p no:cacheprovider "$LAB/test_lab.py" -k vulnerable_service

step "2. what sinkline reports on the vulnerable version"
(cd "$LAB" && sinkline scan vulnerable --no-color)

step "3. fixed service: the same request is refused and the internal service is never contacted"
python -m pytest -v -s -p no:cacheprovider "$LAB/test_lab.py" -k "fixed_service"

step "4. what sinkline reports on the fixed version (a documented false positive)"
(cd "$LAB" && sinkline scan fixed --no-color)

step "5. replay the Sigma rule over the recorded logs"
python -m vulnlab_common.replay "$RULE" "$LAB/detection/sample_attack.ndjson"
python -m vulnlab_common.replay "$RULE" "$LAB/detection/sample_benign.ndjson"
