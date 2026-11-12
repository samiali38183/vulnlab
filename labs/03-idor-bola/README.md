# Lab 03: IDOR / broken object-level authorization (CWE-639, OWASP API1:2023)

A training lab. The bug is a textbook one, written for this repo. It is not vulnerability research
and nothing here is a disclosure or a CVE.

## The service

`vulnerable/app.py` is a small JSON invoice API with token login. Invoices have small sequential
integer ids and an owner. Routes:

- `POST /api/login` returns a bearer token for a known user with the right password. An unknown user,
  a missing or non-string field, or a body that is not a JSON object gets 401.
- `GET /api/invoices` lists the caller's own invoices. It filters by owner.
- `GET /api/invoices/<id>` returns one invoice.
- `PATCH /api/invoices/<id>` updates the memo. It checks the owner and returns 404 otherwise.

The test seeds three users and eight invoices. One invoice owned by bob carries a canary string in
its memo. The lab's data is held in memory by the app; nothing touches the filesystem.

## Root cause

Authentication is checked on the read-by-id route but authorization is not:

```python
def get_invoice(object_id: int):
    if current_user() is None:  # who are you
        return jsonify(error="login required"), 401
    ...
    return jsonify(invoices[object_id])  # line 41: no check that it is yours
```

The same file does the ownership check correctly in the list route and in `PATCH`, which is what
makes this bug realistic: each route re-implements the rule by hand, and one of them forgot. Sequential
ids make the other users' records easy to find, but they are not the bug. Random ids would only
make a missing check harder to exploit, not correct.

## What the proof shows

`test_vulnerable_api_returns_another_users_record` logs in as mallory. The list route returns only
mallory's invoices, as designed. A request for the id of bob's invoice then returns 200 with bob as
owner and the canary in the memo. A pass over all eight ids returns 200 for every one. In the same
file `test_vulnerable_patch_route_already_checks_ownership` shows the update route refusing mallory
with 404 on the same record, so the inconsistency is part of the evidence.

The fixed API gives 404 for every record mallory does not own, on both read and update
(`test_fixed_api_hides_other_users_records_on_every_route`).

## Fix

One helper decides, and every by-id route goes through it:

```python
def owned_invoice(object_id: int) -> dict:
    invoice = invoices.get(object_id)
    if invoice is None or invoice["owner"] != current_user():
        abort(404)
    return invoice
```

It authenticates first, then answers 404 both for "does not exist" and "exists but is not yours".
So a caller with no valid token gets the same 401 for every id, and a logged-in caller gets the same
404 for a missing id and for someone else's id: the responses do not confirm which ids are in use to
either kind of caller. (Before 0.1.1 the ownership comparison ran first and skipped authentication
for missing ids, so a caller with no token got 401 for an existing id and 404 for a missing one.) Because the check lives in one place, a new route that calls it
inherits the rule, and the tests assert the behavior per route so a route that skips it fails.
Regression tests also confirm owners can still read and update their own records and that
unauthenticated requests get 401
(`test_anonymous_callers_cannot_tell_existing_ids_from_missing_ones` compares an existing and a
missing id on read and update). Login is covered by
`test_login_rejects_unknown_users_and_malformed_bodies` for both variants: before 0.1.1 an unknown
user with a missing or `null` password was issued a token (`None != None` is false) and a malformed
body could crash the handler. That was incidental to the lab's bug and is fixed in both variants.

## Detection

`detection/web_idor_object_id_enumeration.yml` is a Sigma correlation rule (type `value_count`)
over the lab's access log. The base rule matches `GET /api/invoices/<digits>`. The correlation
alerts when one session, identified by a hash of the Authorization header, requests 5 or more
distinct ids within one minute. `sample_attack.ndjson` is the id pass from the vulnerable run and
`sample_benign.ndjson` is normal owner traffic from the fixed run. Tests expect 1 alert and 0
alerts respectively, and also that the pass against the fixed API still alerts (it returns 404s).

Limits: it counts distinct ids, not sequential ones, and the threshold would need tuning against
real traffic. A single targeted read of one other user's id produces no alert at all, which is the
real gap: this class has no request-level signature. Replay uses tripline's compiler (v0.2.1) for
the base rule and this repo's own windowing code (`vulnlab_common/replay.py`) for the correlation,
because tripline's engine does not implement correlation and its logsource router does not cover
web-server logs.

## What sinkline sees

Command: `sinkline scan <dir> --no-color` from this directory, sinkline 0.5.0. Captured output is
in `sinkline/`.

| Version | Result |
|---|---|
| vulnerable | 0 findings |
| fixed | 0 findings |

Nothing is reported on the vulnerable version, and that is the expected outcome. A missing
authorization check is not a taint flow: no attacker-controlled value reaches a dangerous sink.
The path parameter is used only as a dictionary key. Whether the caller is allowed to see the
record is a property of the application's rules, which a source-to-sink analyzer has no model of.
This is the honest boundary of static taint analysis, not a bug in sinkline. Finding this class
takes authorization tests, a policy layer that fails closed, or review against an access matrix.

## References

- OWASP API Security Top 10 2023, API1: Broken Object Level Authorization: check authorization on
  every function that takes an object id from the client; random ids help but do not replace the
  check. https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization
- MITRE, CWE-639: Authorization Bypass Through User-Controlled Key.
  https://cwe.mitre.org/data/definitions/639.html

Run: `pytest -q labs/03-idor-bola`
