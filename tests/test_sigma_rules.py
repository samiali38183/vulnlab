"""Each Sigma rule file parses, compiles, fires on its attack sample and not on its benign one."""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from tripline.engine.compiler import compile_rule

from vulnlab_common.replay import read_ndjson, replay

RULES = sorted(Path(__file__).resolve().parents[1].glob("labs/*/detection/*.yml"))


def test_every_lab_has_a_rule():
    assert len(RULES) == 3


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.parent.parent.name)
def test_rule_parses_and_every_base_rule_compiles(path):
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    assert collection.errors == []
    base_rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
    assert base_rules, "no detection rule in the file"
    for rule in base_rules:
        assert rule.id is not None
        compile_rule(rule)


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.parent.parent.name)
def test_rule_has_a_positive_and_a_negative_sample(path):
    detection = path.parent
    attack = read_ndjson(detection / "sample_attack.ndjson")
    benign = read_ndjson(detection / "sample_benign.ndjson")
    assert attack, "positive sample is empty"
    assert benign, "negative sample is empty"
    assert replay(path, attack), f"{path.name} does not fire on its attack sample"
    assert replay(path, benign) == [], f"{path.name} fires on its benign sample"
