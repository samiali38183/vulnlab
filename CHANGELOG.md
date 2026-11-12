# Changelog

## 0.1.1

Fixes from a review of 0.1.0. Training-lab scope only; no new attack content.

- Lab 03 (both variants): login no longer issues a token to an unknown user with a missing or `null`
  password (`None != None`), and malformed login bodies (non-object, non-string fields) get 401
  instead of an unhandled error.
- Lab 03 (fixed): authentication is checked before the object lookup, so callers with no token get
  the same 401 for existing and missing ids. The README now states exactly this.
- Lab 01 (fixed): malformed URLs (invalid or zero port, unterminated IPv6 literal, missing host,
  credentials in the URL, non-http scheme, longer than 2048 characters) get a clean 400 instead of an
  unhandled 500 or a 403. Well-formed URLs for unapproved hosts still get 403. The lab 01 sinkline
  capture was regenerated because `fixed/app.py` line numbers moved; findings are unchanged.
- Lab 01 tests: a new test fails if the resolved-address (pinning) check is removed; before, all
  tests stayed green without it.
- Replay: a missing `value_count` field is no longer counted as a distinct value. Found by the new
  unit tests for window boundaries, distinct counting, thresholds, ordering, empty logs and missing fields.
- New tests: every Sigma rule parses, compiles and has a positive and a negative sample; lab 02's
  stricter fixed behavior (`Name`, `1`, `name,price` rejected) is pinned down and documented.
- `tools/sinkline_check.py` runs the active interpreter's sinkline and exits 2 on a version mismatch
  with `pyproject.toml`; `tools/demo.sh` does the same via `python -m sinkline`.
- CI also runs `ruff format --check`.
- The recorded sinkline captures had been regenerated as UTF-8 after 0.1.0 (PR #1, double-encoded
  glyphs); that was not in the 0.1.0 notes. `tests/test_captures.py` guards it.
- Docs: test counts corrected from real runs (137 passing; the README said 43), lab 01 line
  reference, lab 02 wording about the oracle.

## 0.1.0

- Lab 01: SSRF through a redirect on an allowed host (CWE-918).
- Lab 02: SQL injection in ORDER BY (CWE-89).
- Lab 03: IDOR / broken object-level authorization (CWE-639).
- Per lab: vulnerable and fixed service, proof and regression tests, write-up, captured sinkline
  results, Sigma rule with recorded logs.
- Shared harness with a loopback-only guard, safety tests, `make demo` for lab 01, CI.
