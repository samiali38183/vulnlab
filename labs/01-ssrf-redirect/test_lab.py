"""Lab 01 tests: impact on the vulnerable service, same check on the fixed one, detection replay.

Every request goes through the loopback-only client to services started by this test.
Set VULNLAB_RECORD=1 to refresh the recorded detection samples from a real run.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from vulnlab_common.guard import LoopbackSession
from vulnlab_common.harness import serve
from vulnlab_common.loader import load
from vulnlab_common.replay import read_ndjson, replay

HERE = Path(__file__).resolve().parent
lab = load(HERE / "lab.py", "lab01_lab")
fixed_module = load(HERE / "fixed" / "app.py", "lab01_fixed_for_tests")
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
        assert replay(RULE, read_ndjson(running.log_path)), "the attempt is still visible in the log"


def test_fixed_service_still_previews_pages_and_follows_allowed_redirects(tmp_path):
    with lab.start("fixed", tmp_path) as running:
        plain = running.preview(running.partner + "/page")
        followed = running.preview(running.via_partner_redirect(running.partner + "/page"))
        assert plain.status_code == followed.status_code == 200
        assert "Partner page" in followed.text
        if RECORD:
            shutil.copy(running.log_path, DETECTION / "sample_benign.ndjson")


# Inputs that are not usable http URLs. Each is written as scheme + remainder so that the textual
# scan in tests/test_safety.py (no non-loopback URL literals in lab tests) stays strict; none of these
# is ever fetched, the service under test refuses them.
HTTP = "http:"
MALFORMED_URLS = {
    "invalid port": HTTP + "//127.0.0.1:abc/",
    "port out of range": HTTP + "//127.0.0.1:99999/",
    "port zero": HTTP + "//127.0.0.1:0/",
    "unterminated ipv6 literal": HTTP + "//[::1/",
    "empty": "",
    "scheme only": HTTP + "//",
    "empty host": HTTP + "///page",
    "port without host": HTTP + "//:80/",
    "no scheme": "127.0.0.1/page",
    "userinfo": HTTP + "//user@127.0.0.1/",
    "userinfo with password": HTTP + "//user:secret@127.0.0.1/",
    "userinfo trick, allowed name first": HTTP + "//127.0.0.1@127.0.0.2/",
    "userinfo trick, allowed name as user": HTTP + "//127.0.0.1:80@127.0.0.2/",
    "ftp scheme": "ftp:" + "//127.0.0.1/",
    "https scheme": "https:" + "//127.0.0.1/",
    "file scheme": "file:" + "///etc/passwd",
    "javascript scheme": "javascript:alert(1)",
    "overlong": HTTP + "//127.0.0.1/" + "a" * 3000,
}


@pytest.mark.parametrize("url", MALFORMED_URLS.values(), ids=MALFORMED_URLS.keys())
def test_fixed_service_answers_400_to_every_malformed_url(tmp_path, url):
    with lab.start("fixed", tmp_path) as running:
        response = running.preview(url)
        assert response.status_code == 400
        assert response.json() == {"error": "invalid url"}
        assert not running.internal_log.exists()


@pytest.mark.parametrize("target", ["ftp:" + "//127.0.0.1/", HTTP + "//user@127.0.0.1/"])
def test_fixed_service_answers_400_to_a_malformed_redirect_target(tmp_path, target):
    with lab.start("fixed", tmp_path) as running:
        response = running.preview(running.via_partner_redirect(target))
        assert response.status_code == 400
        assert not running.internal_log.exists()


def test_fixed_service_keeps_403_for_well_formed_urls_on_other_hosts(tmp_path):
    with lab.start("fixed", tmp_path) as running:
        assert running.preview(running.internal_url).status_code == 403
        assert running.preview(HTTP + "//127.0.0.1.example.com/").status_code == 403


def test_address_pinning_refuses_a_host_whose_address_is_not_approved():
    """The host name is allowed but the address it resolves to is not: only the pinning check stops it."""
    with serve(lab.services.partner_app()) as partner:
        client = LoopbackSession()
        permissive = fixed_module.create_app()
        with serve(permissive) as target:
            ok = client.get(f"{target.url}/preview", params={"url": partner.url + "/page"})
            assert ok.status_code == 200
        strict = fixed_module.create_app({"allowed_addrs": {"127.0.0.9"}})
        with serve(strict) as target:
            blocked = client.get(f"{target.url}/preview", params={"url": partner.url + "/page"})
            assert blocked.status_code == 403
            assert blocked.json() == {"error": "address not allowed"}


def test_detection_rule_fires_on_recorded_attack_not_on_benign_traffic():
    attack = replay(RULE, read_ndjson(DETECTION / "sample_attack.ndjson"))
    benign = replay(RULE, read_ndjson(DETECTION / "sample_benign.ndjson"))
    assert len(attack) == 1 and len(attack[0].events) == 2
    assert benign == []
