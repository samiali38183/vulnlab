"""Lab 03 tests: reading another user's record by id, then the same check on the fixed API.

Set VULNLAB_RECORD=1 to refresh the recorded detection samples from a real run.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from vulnlab_common.loader import load
from vulnlab_common.replay import read_ndjson, replay

HERE = Path(__file__).resolve().parent
lab = load(HERE / "lab.py", "lab03_lab")
DETECTION = HERE / "detection"
RULE = DETECTION / "web_idor_object_id_enumeration.yml"
RECORD = os.environ.get("VULNLAB_RECORD") == "1"


def sweep(running, headers) -> dict[int, int]:
    return {i: running.get(f"/api/invoices/{i}", headers).status_code for i in lab.OWNERS}


def test_vulnerable_api_returns_another_users_record(tmp_path):
    with lab.start("vulnerable", tmp_path) as running:
        mallory = running.login("mallory")
        own = running.get("/api/invoices", mallory).json()
        assert {i["owner"] for i in own} == {"mallory"}, "the list route is scoped correctly"

        record = running.get(f"/api/invoices/{lab.VICTIM_ID}", mallory)
        assert record.status_code == 200
        assert record.json()["owner"] == "bob"
        assert record.json()["memo"] == running.canary

        assert set(sweep(running, mallory).values()) == {200}
        if RECORD:
            shutil.copy(running.log_path, DETECTION / "sample_attack.ndjson")


def test_vulnerable_patch_route_already_checks_ownership(tmp_path):
    with lab.start("vulnerable", tmp_path) as running:
        mallory = running.login("mallory")
        assert running.patch(f"/api/invoices/{lab.VICTIM_ID}", "x", mallory).status_code == 404
        assert running.patch("/api/invoices/2", "mine", mallory).status_code == 200


def test_fixed_api_hides_other_users_records_on_every_route(tmp_path):
    with lab.start("fixed", tmp_path) as running:
        mallory = running.login("mallory")
        statuses = sweep(running, mallory)
        others = [i for i, owner in lab.OWNERS.items() if owner != "mallory"]
        assert all(statuses[i] == 404 for i in others)
        assert all(statuses[i] == 200 for i in lab.OWNERS if i not in others)
        victim = running.get(f"/api/invoices/{lab.VICTIM_ID}", mallory)
        assert running.canary not in victim.text
        assert running.patch(f"/api/invoices/{lab.VICTIM_ID}", "x", mallory).status_code == 404
        assert replay(RULE, read_ndjson(running.log_path)), "the sweep is still visible in the log"


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_requests_without_a_login_are_rejected(tmp_path, variant):
    with lab.start(variant, tmp_path) as running:
        assert running.get(f"/api/invoices/{lab.VICTIM_ID}").status_code == 401
        assert running.get("/api/invoices").status_code == 401


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_anonymous_callers_cannot_tell_existing_ids_from_missing_ones(tmp_path, variant):
    with lab.start(variant, tmp_path) as running:
        missing = max(lab.OWNERS) + 991
        for method in ("get", "patch"):
            call = getattr(running.client, method)
            kwargs = {"json": {"memo": "x"}} if method == "patch" else {}
            existing = call(f"{running.target}/api/invoices/{lab.VICTIM_ID}", **kwargs)
            absent = call(f"{running.target}/api/invoices/{missing}", **kwargs)
            assert existing.status_code == absent.status_code == 401
            assert existing.json() == absent.json()


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
@pytest.mark.parametrize(
    "body",
    [
        {"user": "nobody", "password": None},
        {"user": "nobody"},
        {"user": "nobody", "password": ""},
        {"user": None, "password": None},
        {},
        [],
        "text",
        {"user": ["alice"], "password": "x"},
        {"user": {"a": 1}, "password": "x"},
    ],
    ids=repr,
)
def test_login_rejects_unknown_users_and_malformed_bodies(tmp_path, variant, body):
    with lab.start(variant, tmp_path) as running:
        response = running.raw_login(body)
        assert response.status_code == 401
        assert "token" not in response.text


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
@pytest.mark.parametrize("password", [None, 0, 123, ["x"], "wrong"], ids=repr)
def test_login_rejects_known_user_with_missing_or_non_string_password(tmp_path, variant, password):
    with lab.start(variant, tmp_path) as running:
        body = {"user": "alice"} if password is None else {"user": "alice", "password": password}
        assert running.raw_login(body).status_code == 401
        assert running.raw_login({"user": "alice", "password": None}).status_code == 401
        assert running.raw_login({"user": "alice", "password": running.passwords["alice"]}).status_code == 200


def test_fixed_api_still_serves_owners_their_own_records(tmp_path):
    with lab.start("fixed", tmp_path) as running:
        bob = running.login("bob")
        assert running.get(f"/api/invoices/{lab.VICTIM_ID}", bob).json()["memo"] == running.canary
        assert running.patch("/api/invoices/7", "updated", bob).json()["memo"] == "updated"
        assert [i["id"] for i in running.get("/api/invoices", bob).json()] == [4, 7]
        if RECORD:
            shutil.copy(running.log_path, DETECTION / "sample_benign.ndjson")


def test_detection_rule_fires_on_recorded_enumeration_not_on_benign_traffic():
    attack = replay(RULE, read_ndjson(DETECTION / "sample_attack.ndjson"))
    benign = replay(RULE, read_ndjson(DETECTION / "sample_benign.ndjson"))
    assert len(attack) == 1 and attack[0].rule.startswith("One session reads many")
    assert benign == []
