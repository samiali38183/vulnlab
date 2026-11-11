"""Lab 01 tests: impact on the vulnerable service, same check on the fixed one, detection replay.

Every request goes through the loopback-only client to services started by this test.
Set VULNLAB_RECORD=1 to refresh the recorded detection samples from a real run.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from vulnlab_common.loader import load
from vulnlab_common.replay import read_ndjson, replay

HERE = Path(__file__).resolve().parent
lab = load(HERE / "lab.py", "lab01_lab")
DETECTION = HERE / "detection"
RULE = DETECTION / "web_ssrf_preview_internal_address.yml"
RECORD = os.environ.get("VULNLAB_RECORD") == "1"


def test_vulnerable_service_returns_internal_marker_via_allowed_redirect(tmp_path):
    with lab.start("vulnerable", tmp_path) as running:
        direct = running.preview(running.internal_url)
        assert direct.status_code == 403, "the host allow-list must block the direct request"

        chained = running.preview(running.via_partner_redirect(running.internal_url))
        assert chained.status_code == 200
        assert running.canary in chained.text

        hits = read_ndjson(running.internal_log)
        assert [h["cs-uri-stem"] for h in hits] == ["/latest/meta-data/credentials"]
        if RECORD:
            shutil.copy(running.log_path, DETECTION / "sample_attack.ndjson")


def test_fixed_service_does_not_return_internal_marker(tmp_path):
    with lab.start("fixed", tmp_path) as running:
        direct = running.preview(running.internal_url)
        chained = running.preview(running.via_partner_redirect(running.internal_url))
        assert direct.status_code == 403
        assert chained.status_code == 403
        assert running.canary not in chained.text
        assert not running.internal_log.exists(), "the internal service must never be contacted"


def test_fixed_service_still_previews_pages_and_follows_allowed_redirects(tmp_path):
    with lab.start("fixed", tmp_path) as running:
        plain = running.preview(running.partner + "/page")
        followed = running.preview(running.via_partner_redirect(running.partner + "/page"))
        assert plain.status_code == followed.status_code == 200
        assert "Partner page" in followed.text
        if RECORD:
            shutil.copy(running.log_path, DETECTION / "sample_benign.ndjson")


def test_detection_rule_fires_on_recorded_attack_not_on_benign_traffic():
    attack = replay(RULE, read_ndjson(DETECTION / "sample_attack.ndjson"))
    benign = replay(RULE, read_ndjson(DETECTION / "sample_benign.ndjson"))
    assert len(attack) == 1 and len(attack[0].events) == 2
    assert benign == []
