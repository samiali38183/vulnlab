# vulnlab

[![ci](https://github.com/samiali38183/vulnlab/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/vulnlab/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.12-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Three small vulnerable web services that only run on localhost: SSRF, SQL injection and IDOR. Each
one has a minimal proof of impact, a fix with regression tests, a write-up of the bug class, a Sigma
rule that matches the attempt in the service's access log, and a record of what my static analyzer
([sinkline](https://github.com/samiali38183/sinkline)) does and does not report on it.

I built it to compare the three tools on the same bugs: the exploit, the fix, the taint scan and
the log rule. The places where sinkline or the rule gets it wrong are left in and written up. The
suite has 137 tests and all of them pass.

## What it is and is not

- It is a training lab. The bugs are textbook classes, written small enough to read on one screen.
- It is not vulnerability research. There are no CVEs, no disclosures and no findings against
  real software.
- It is not a scanner, an exploit kit or a target for anything else. Everything runs on 127.0.0.1
  against services this repo starts itself. See `docs/SAFETY.md`.

## Quick start

Python 3.12. There is no Docker: the tests start the services as plain Python processes.

```
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

`make setup`, `make test` and `make demo` wrap these. `make demo` runs lab 01 from start to finish:
the proof test against the vulnerable service, the sinkline scan, the same check against the fixed
service, and the Sigma replay over the recorded logs. `requirements.lock` lists the exact versions
of a working install. `pyproject.toml` pins the direct dependencies and installs sinkline and
tripline from their GitHub tags.

## Labs

Results below are from runs on 2026-11-13 (Windows 11, Python 3.12.2, pytest 9.2.0, sinkline
0.5.0, tripline 0.2.1, pySigma 2.1.0). CI runs the same checks on Linux, plus `ruff check` and
`ruff format --check`.

| Lab | Bug class | CWE | Proof (vulnerable) | Fix verified | sinkline vulnerable / fixed | Detection rule |
|---|---|---|---|---|---|---|
| [01-ssrf-redirect](labs/01-ssrf-redirect) | SSRF through a redirect on an allowed host | 918 | preview endpoint returned the internal service's canary | yes, 26 tests | 1 finding (correct) / 1 finding (false positive) | Sigma rule, replays: 1 alert on attack log, 0 on benign |
| [02-sqli-order-by](labs/02-sqli-order-by) | SQL injection in ORDER BY (dynamic identifier) | 89 | sort value made another table decide the row order | yes, 9 tests | 1 finding (correct) / 1 finding (false positive) | Sigma rule, replays: 1 alert on attack log, 0 on benign |
| [03-idor-bola](labs/03-idor-bola) | Missing object-level authorization | 639 | another user's invoice returned with the canary | yes, 37 tests | 0 / 0 (expected: not a taint flow) | Sigma correlation rule (distinct ids per session), replays: 1 / 0 |

65 more tests in `tests/` cover the loopback guard and harness (26), the recorded sinkline captures
(13), the Sigma replay's correlation logic (13), the rule files (7) and the sinkline check tool (6).
The lab rows count every test in each lab directory. That makes 137 in total.

What the results show:

- sinkline finds the two injection-style bugs and traces the flow correctly. It also flags the fixed
  versions, because it does not treat a custom allow-list or address check as a sanitizer. I count
  those as sinkline limitations and did not change the labs to hide them.
- sinkline reports nothing on lab 03, vulnerable or fixed. A missing authorization check is not a
  taint flow, so a taint analyzer has nothing to follow. The write-up says so.
- The detection rules see attempts, not outcomes, so they fire on the fixed services too. Lab 03's
  rule only sees behavior around the bug (many ids in a short time), not the bug itself.

## Layout

```
labs/NN-name/
  vulnerable/app.py   the bug
  fixed/app.py        the fix
  lab.py              starts the services for a variant on loopback ports
  test_lab.py         proof on vulnerable, same check on fixed, regression, detection replay
  README.md           write-up
  sinkline/           captured scan output and the expected result CI checks
  detection/          Sigma rule, recorded sample logs
vulnlab_common/       loopback guard, test harness and access log, Sigma replay
tools/                sinkline capture/verify, demo script
docs/                 METHOD.md, SAFETY.md
```

## License

MIT. See `LICENSE`.
