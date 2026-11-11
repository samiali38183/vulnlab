# Lab 02: SQL injection in ORDER BY (CWE-89)

A training lab. The bug is a textbook one, written for this repo. It is not vulnerability research
and nothing here is a disclosure or a CVE.

## The service

`vulnerable/app.py` is a product list API: `GET /api/products?sort=<column>&order=asc|desc&q=<text>`.
The data is a SQLite file the test creates in its own temp directory. It has a `products` table
and a second `api_keys` table that holds a canary value. The endpoint is only meant to read
`products`.

## Root cause

The search text is bound as a query parameter, so the author did the right thing for values. But
placeholders cannot stand in for identifiers, so the sort column is pasted into the SQL string:

```python
query = f"SELECT id, name, price FROM products WHERE name LIKE ? ORDER BY {sort} {direction}"  # line 16
rows = conn.execute(query, (needle,)).fetchall()                                               # line 19
```

`sort` comes straight from the query string. The `LIKE ?` parameter gives a false sense that the
query is safe; the placeholder protects one position and the f-string opens another. `direction` is
safe only because it is reduced to the literals `ASC` or `DESC` before use.

## What the proof shows

ORDER BY accepts an expression, not just a column. The test passes an expression whose result
depends on a condition about the `api_keys` table. The response is still a normal product list, but
its row order switches depending on whether the condition holds: with a correct guess about the
first character of the canary the rows come back in price order, with a wrong guess in name order.
That is the whole point of the proof: data from a table the endpoint never returns changes what the
endpoint returns, so it can be read one yes/no answer at a time. The test stops at demonstrating the
oracle; it does not recover the full canary.

The same inputs against the fixed service get a 400 and no change in the output
(`test_fixed_endpoint_rejects_non_column_sort_values`).

## Fix

`fixed/app.py` maps the caller's `sort` value through an allow-list of columns the application owns:

```python
SORT_COLUMNS = {"id": "id", "name": "name", "price": "price"}
column = SORT_COLUMNS.get(request.args.get("sort", "name"))
if column is None:
    return jsonify(error="unsupported sort column"), 400
```

The string interpolated into the SQL is the dictionary's value, which the application wrote, never
the caller's text. This is the approach OWASP recommends for identifiers that cannot be
parameterized.

Regression tests: injected sort values are rejected with 400 and nothing from `api_keys` appears;
sorting by each allowed column in both directions and filtering with `q` still work.

## Detection

`detection/web_sqli_order_by_injection.yml` is a Sigma rule over the lab's access log. It flags
`/api/products` requests whose `sort` value contains anything other than letters, digits and
underscore. `sample_attack.ndjson` and `sample_benign.ndjson` were recorded from real runs of the
tests; the test replays the rule over both and expects 1 alert on the first and none on the second.

Limits: it matches the raw query string, so percent-encoded characters (which any special
character becomes) are what trigger it. It sees the attempt and fires on the fixed service as well.
A client that legitimately sends a multi-column sort would be a false positive. Replay uses
tripline's compiler (v0.2.1) with its logsource router bypassed, because that router does not
cover web-server logs.

## What sinkline sees

Command: `sinkline scan <dir> --no-color` from this directory, sinkline 0.5.0. Captured output is
in `sinkline/`.

| Version | Result |
|---|---|
| vulnerable | 1 finding, SL-SQLI-001 (CWE-89, critical), source `request.args` at `app.py:13` to `conn.execute` at `app.py:19`, through the f-string |
| fixed | 1 finding, SL-SQLI-001, same flow; the path shows `SORT_COLUMNS.get()` as "unknown; assumed passthrough" |

The vulnerable finding is correct and the flow is traced accurately. The fixed one is a false
positive: sinkline treats a dictionary lookup against a constant allow-list as a passthrough, so it
cannot tell the fix from the bug. Documented as a sinkline limitation (allow-list lookups are not
recognized as sanitizers); the lab was not changed to avoid it.

## References

- OWASP, SQL Injection Prevention Cheat Sheet: identifiers and sort order cannot be bound as
  parameters, so map the caller's choice to application-owned values.
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- MITRE, CWE-89: Improper Neutralization of Special Elements used in an SQL Command.
  https://cwe.mitre.org/data/definitions/89.html

Run: `pytest -q labs/02-sqli-order-by`
