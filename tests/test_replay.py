"""Unit tests for the correlation windowing in vulnlab_common.replay, on synthetic events."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnlab_common.replay import replay

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

RULE = """\
title: base
name: base_rule
id: 11111111-2222-4333-8444-555555555555
logsource:
  category: webserver
detection:
  selection:
    cs-method: GET
  condition: selection
level: low
---
title: correlated
correlation:
  type: {type}
  rules:
    - base_rule
  group-by:
{group_by}
  timespan: {timespan}
  condition:
    gte: {gte}
{field}
level: medium
"""


def make_rule(
    tmp_path: Path,
    *,
    type: str = "value_count",
    gte: int = 5,
    timespan: str = "60s",
    group_by: tuple[str, ...] = ("session",),
    field: str | None = "object_id",
) -> Path:
    path = tmp_path / "rule.yml"
    path.write_text(
        RULE.format(
            type=type,
            gte=gte,
            timespan=timespan,
            group_by="\n".join(f"    - {g}" for g in group_by),
            field=f"    field: {field}" if field and type == "value_count" else "",
        ),
        encoding="utf-8",
    )
    return path


def event(seconds: float, object_id: int | None = 1, session: str = "s1", method: str = "GET") -> dict:
    record = {
        "timestamp": (T0 + timedelta(seconds=seconds)).isoformat(timespec="milliseconds"),
        "cs-method": method,
        "session": session,
    }
    if object_id is not None:
        record["object_id"] = object_id
    return record


def test_empty_log_gives_no_alerts(tmp_path):
    assert replay(make_rule(tmp_path), []) == []


def test_events_the_base_rule_does_not_match_are_ignored(tmp_path):
    events = [event(i, object_id=i, method="POST") for i in range(10)]
    assert replay(make_rule(tmp_path), events) == []


def test_exactly_at_threshold_alerts_and_one_below_does_not(tmp_path):
    rule = make_rule(tmp_path, gte=5)
    assert len(replay(rule, [event(i, object_id=i) for i in range(5)])) == 1
    assert replay(rule, [event(i, object_id=i) for i in range(4)]) == []


def test_alert_carries_the_first_satisfying_window_and_its_group(tmp_path):
    alerts = replay(make_rule(tmp_path, gte=3), [event(i, object_id=i) for i in range(8)])
    assert len(alerts) == 1
    assert alerts[0].group == ("s1",)
    assert [e["object_id"] for e in alerts[0].events] == [0, 1, 2]


def test_window_boundary_is_inclusive_of_exactly_the_timespan(tmp_path):
    rule = make_rule(tmp_path, gte=5, timespan="60s")
    inside = [event(s, object_id=i) for i, s in enumerate([0, 15, 30, 45, 60])]
    outside = [event(s, object_id=i) for i, s in enumerate([0, 15, 30, 45, 60.001])]
    assert len(replay(rule, inside)) == 1
    assert replay(rule, outside) == []


def test_window_slides_so_a_late_burst_is_found_after_early_noise(tmp_path):
    rule = make_rule(tmp_path, gte=5, timespan="60s")
    early = [event(0, object_id=100), event(1, object_id=101)]
    burst = [event(500 + i, object_id=i) for i in range(5)]
    alerts = replay(rule, early + burst)
    assert len(alerts) == 1
    assert {e["object_id"] for e in alerts[0].events} == {0, 1, 2, 3, 4}


def test_value_count_counts_distinct_values_not_events(tmp_path):
    rule = make_rule(tmp_path, gte=3)
    assert replay(rule, [event(i, object_id=7) for i in range(20)]) == []
    repeated = [event(i, object_id=i % 2) for i in range(20)]
    assert replay(rule, repeated) == []
    assert len(replay(rule, repeated + [event(21, object_id=2)])) == 1


def test_event_count_counts_events_including_repeats(tmp_path):
    rule = make_rule(tmp_path, type="event_count", gte=5)
    assert len(replay(rule, [event(i, object_id=7) for i in range(5)])) == 1
    assert replay(rule, [event(i, object_id=7) for i in range(4)]) == []


def test_out_of_order_timestamps_give_the_same_result_as_sorted_ones(tmp_path):
    rule = make_rule(tmp_path, gte=5)
    ordered = [event(i * 10, object_id=i) for i in range(5)]
    shuffled = ordered[:]
    random.Random(1).shuffle(shuffled)
    assert shuffled != ordered
    assert len(replay(rule, shuffled)) == len(replay(rule, ordered)) == 1
    spread = [event(i * 20, object_id=i) for i in range(5)]
    random.Random(2).shuffle(spread)
    assert replay(rule, spread) == []


def test_groups_are_counted_separately(tmp_path):
    rule = make_rule(tmp_path, gte=5)
    mixed = [event(i, object_id=i, session="a" if i % 2 else "b") for i in range(8)]
    assert replay(rule, mixed) == []
    alerts = replay(rule, mixed + [event(9 + i, object_id=20 + i, session="a") for i in range(5)])
    assert [a.group for a in alerts] == [("a",)]


def test_multiple_group_by_fields_form_one_group_only_when_all_match(tmp_path):
    rule = make_rule(tmp_path, gte=3, group_by=("session", "cs-method"))
    events = [event(i, object_id=i) for i in range(3)]
    assert len(replay(rule, events)) == 1
    split = [{**e, "cs-method": "GET"} if i < 2 else {**e, "session": "other"} for i, e in enumerate(events)]
    assert replay(rule, split) == []


def test_event_missing_the_counted_field_is_not_a_distinct_value(tmp_path):
    rule = make_rule(tmp_path, gte=2)
    assert replay(rule, [event(0, object_id=None), event(1, object_id=1)]) == []
    assert replay(rule, [event(i, object_id=None) for i in range(10)]) == []
    assert len(replay(rule, [event(0, object_id=None), event(1, object_id=1), event(2, object_id=2)])) == 1


def test_unsupported_correlation_types_are_refused_not_silently_ignored(tmp_path):
    rule = make_rule(tmp_path, type="temporal")
    with pytest.raises(NotImplementedError):
        replay(rule, [event(0)])
