"""Replay recorded NDJSON access logs through a Sigma rule file.

Single-event rules are compiled with tripline's engine (pySigma parses, tripline walks the
condition tree). tripline's logsource router only knows Windows, Linux auditd and CloudTrail
shapes, so it is bypassed here: the lab applies the rule to every event in the file it is given.

event_count and value_count correlation rules are evaluated by the small windowing code below,
because tripline's engine does not implement correlation.
"""

from __future__ import annotations

import json
import operator
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from tripline.engine.compiler import compile_rule

_OPS = {
    "gte": operator.ge,
    "gt": operator.gt,
    "lte": operator.le,
    "lt": operator.lt,
    "eq": operator.eq,
}


@dataclass
class Alert:
    rule: str
    group: tuple[Any, ...] = ()
    events: list[dict[str, Any]] = field(default_factory=list)


def read_ndjson(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def replay(rule_path: Path, events: list[dict[str, Any]]) -> list[Alert]:
    collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    base = {r.name or str(r.id): r for r in collection.rules if isinstance(r, SigmaRule)}
    referenced = {
        ref.reference
        for rule in collection.rules
        if isinstance(rule, SigmaCorrelationRule)
        for ref in rule.rules
    }
    alerts: list[Alert] = []
    for rule in collection.rules:
        if isinstance(rule, SigmaRule):
            if (rule.name or str(rule.id)) in referenced:
                continue
            compiled = compile_rule(rule)
            hits = [e for e in events if compiled.matches(e)]
            if hits:
                alerts.append(Alert(rule.title, events=hits))
        elif isinstance(rule, SigmaCorrelationRule):
            alerts.extend(_correlate(rule, base, events))
    return alerts


def _correlate(
    rule: SigmaCorrelationRule, base: dict[str, SigmaRule], events: list[dict[str, Any]]
) -> list[Alert]:
    if rule.type.name.lower() not in {"event_count", "value_count"}:
        raise NotImplementedError(f"correlation type {rule.type} is not supported")
    matched: list[dict[str, Any]] = []
    for ref in rule.rules:
        compiled = compile_rule(base[ref.reference])
        matched.extend(e for e in events if compiled.matches(e))
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for event in matched:
        groups[tuple(event.get(k) for k in rule.group_by)].append(event)
    op = _OPS[rule.condition.op.name.lower()]
    alerts = []
    for key, items in groups.items():
        items.sort(key=lambda e: datetime.fromisoformat(e["timestamp"]))
        times = [datetime.fromisoformat(e["timestamp"]) for e in items]
        start = 0
        for end in range(len(items)):
            while (times[end] - times[start]).total_seconds() > rule.timespan.seconds:
                start += 1
            window = items[start : end + 1]
            if rule.type.name.lower() == "event_count":
                measure = len(window)
            else:
                values = (e.get(rule.condition.fieldref) for e in window)
                measure = len({v for v in values if v is not None})  # a missing field is not a value
            if op(measure, rule.condition.count):
                alerts.append(Alert(str(rule.title), key, window))
                break
    return alerts


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Replay a recorded access log through a Sigma rule")
    parser.add_argument("rule", type=Path)
    parser.add_argument("log", type=Path)
    args = parser.parse_args(argv)
    events = read_ndjson(args.log)
    alerts = replay(args.rule, events)
    print(f"{args.log.name}: {len(events)} events, {len(alerts)} alert(s)")
    for alert in alerts:
        print(f"  ALERT {alert.rule!r}: {len(alert.events)} matching event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
