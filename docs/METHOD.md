# How a lab is built and verified

## Shape

Each lab is a directory under `labs/` with the same files:

- `vulnerable/app.py` and `fixed/app.py`: a Flask app with a `create_app(settings)` function,
  under about 120 lines, with no comments pointing at the bug. The two files differ only where
  the fix is.
- `lab.py`: `start(variant, workdir)` is a context manager that creates the lab's data (a canary
  value, a SQLite file, seeded users), starts the services on free loopback ports through the
  harness, and yields a small object with the URLs and a loopback-only HTTP client.
- `test_lab.py`: the proof, the fix check, the regression check, and the detection replay.
- `detection/`: a Sigma rule over the lab's own access log, plus two recorded logs.
- `sinkline/`: the captured scan output and `expected.json`.
- `README.md`: root cause with the vulnerable line, what the proof shows, the fix and why it
  works, detection and its limits, what sinkline reports, and references.

## What each test must establish

1. Proof on the vulnerable service: a control first (the intended protection works for the
   direct case), then the observable impact (the canary or another user's record comes back).
   The proof only touches data the lab created for the test.
2. The same request against the fixed service does not produce the impact.
3. The fixed service still does its job (a legitimate redirect, a normal sort, an owner reading
   their own record). A fix that breaks the feature is not accepted.
4. The detection rule fires on the recorded attack log and not on the recorded benign log, and
   the attempt against the fixed service is still visible to the rule.

## Access log and detection

The harness wraps every service with an after-request hook that appends one JSON object per
request to a file: timestamp, client address, method, path, raw query string, status, a hash of
the Authorization header as `session`, and the route's `object_id`. Field names follow W3C-style
web-server logs (`cs-uri-stem`, `cs-uri-query`, `sc-status`) so the rules read like web-server
rules.

Single-event rules are compiled by tripline's engine (pySigma parses, tripline walks the
condition tree). Tripline's logsource router only knows Windows, Linux auditd and CloudTrail, so
it is bypassed: the rule is applied to every event in the file. Correlation rules are evaluated
by `vulnlab_common/replay.py` (event_count and value_count over a time window), because tripline
does not implement correlation.

Recorded logs are real output of the tests. To refresh them: `VULNLAB_RECORD=1 pytest labs`.

## sinkline

`python tools/sinkline_check.py --capture` runs `sinkline scan` on each variant, writes the text
output and `expected.json` (rule ids, files, lines, tool version). CI runs
`python tools/sinkline_check.py` and fails if any scan differs. It runs `python -m sinkline` of the
active interpreter (never a `sinkline` found on PATH) and exits 2 before scanning if the installed
version differs from the one pinned in `pyproject.toml`. If sinkline reports something
unflattering, I leave the lab alone and the README records it as a sinkline limitation.

## Adding a lab

Copy a lab, keep the layout, write the bug small, and turn each of the four statements above into a
test before writing the README. Every number in a README has to come from a run you can repeat.
