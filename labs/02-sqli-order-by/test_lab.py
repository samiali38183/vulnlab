"""Lab 02 tests: an ORDER BY value that reads another table, then the same check on the fixed app.

The oracle used as proof: the order of the rows depends on a condition evaluated against the
lab's second table, so data the endpoint should never expose influences what it returns.
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
lab = load(HERE / "lab.py", "lab02_lab")
DETECTION = HERE / "detection"
RULE = DETECTION / "web_sqli_order_by_injection.yml"
RECORD = os.environ.get("VULNLAB_RECORD") == "1"


def oracle(first_char: str) -> str:
    return (
        "(CASE WHEN substr((SELECT value FROM api_keys LIMIT 1),1,1)='" + first_char + "' "
        "THEN price ELSE name END)"
    )


def test_vulnerable_sort_parameter_lets_another_table_decide_the_order(tmp_path):
    with lab.start("vulnerable", tmp_path) as running:
        assert running.product_ids(sort="name") == lab.NAME_ORDER
        assert running.product_ids(sort="price") == lab.PRICE_ORDER

        right = running.product_ids(sort=oracle(running.canary[0]))
        wrong = running.product_ids(sort=oracle("!"))
        assert right == lab.PRICE_ORDER
        assert wrong == lab.NAME_ORDER
        if RECORD:
            shutil.copy(running.log_path, DETECTION / "sample_attack.ndjson")


@pytest.mark.parametrize("make_value", [oracle, lambda c: f"{c}", lambda c: f"price,{oracle(c)}"])
def test_fixed_endpoint_rejects_non_column_sort_values(tmp_path, make_value):
    with lab.start("fixed", tmp_path) as running:
        value = make_value(running.canary[0])
        response = running.get(sort=value)
        assert response.status_code == 400
        assert running.canary not in response.text
        if not value.isidentifier():
            alerts = replay(RULE, read_ndjson(running.log_path))
            assert alerts, "the attempt is still visible in the log"


@pytest.mark.parametrize("sort", ["Name", "1", "name,price"])
def test_fixed_endpoint_is_stricter_than_the_vulnerable_one_on_legitimate_looking_values(tmp_path, sort):
    """Documented behavior change: the allow-list is exact, so these ORDER BY forms are refused."""
    with lab.start("vulnerable", tmp_path / "v") as running:
        assert running.get(sort=sort).status_code == 200
    with lab.start("fixed", tmp_path / "f") as running:
        assert running.get(sort=sort).status_code == 400


def test_fixed_endpoint_keeps_normal_sorting_and_filtering(tmp_path):
    with lab.start("fixed", tmp_path) as running:
        assert running.product_ids(sort="name") == lab.NAME_ORDER
        assert running.product_ids(sort="price") == lab.PRICE_ORDER
        assert running.product_ids(sort="price", order="desc") == lab.PRICE_ORDER[::-1]
        assert running.product_ids(sort="name", q="an") == [2]
        if RECORD:
            shutil.copy(running.log_path, DETECTION / "sample_benign.ndjson")


def test_detection_rule_fires_on_recorded_attack_not_on_benign_traffic():
    attack = replay(RULE, read_ndjson(DETECTION / "sample_attack.ndjson"))
    benign = replay(RULE, read_ndjson(DETECTION / "sample_benign.ndjson"))
    assert len(attack) == 1 and len(attack[0].events) == 2
    assert benign == []
