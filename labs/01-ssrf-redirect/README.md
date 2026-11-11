# Lab 01: SSRF through an allowed host's redirect (CWE-918)

A training lab. The bug is a textbook one, written for this repo. It is not vulnerability research
and nothing here is a disclosure or a CVE.

## The service

`vulnerable/app.py` is a link-preview endpoint: `GET /preview?url=...` fetches the page server-side
and returns a status and an excerpt. It only accepts URLs whose host is on an allow-list.

Lab layout, all on loopback, started by the tests:

- the preview service (127.0.0.1)
- a "partner" site on an allowed host with an open redirect (`/go?to=...`) (127.0.0.1)
- an "internal" service on 127.0.0.2 that serves a canary value, standing in for a cloud
  metadata address. 127.0.0.2 is not on the allow-list.

## Root cause

The check runs once, on the URL the user supplied:

```python
if not host_allowed(url):          # checked here
    ...
upstream = requests.get(url, timeout=3)   # app.py:23, follows redirects by default
```

`requests.get` follows redirects on its own. The allow-list never sees the second URL. Any allowed
host that redirects to a caller-chosen location (an open redirect, which is a common minor finding
on its own) turns the allow-list into a pass for anything that host can be made to point at.

## What the proof shows

`test_vulnerable_service_returns_internal_marker_via_allowed_redirect` first confirms the control:
asking the preview endpoint for the internal address directly gets a 403. It then asks for the
partner's redirect URL, which points at the internal service. The preview endpoint returns 200 and
the body contains the internal service's canary, and the internal service's access log shows one
request it should never have received. The same test run against the fixed service is
`test_fixed_service_does_not_return_internal_marker`: both requests get 403 and the internal service
is never contacted.

## Fix

`fixed/app.py` changes three things:

1. Redirects are not followed by the HTTP client (`allow_redirects=False`). The app follows
   them itself, at most 3 hops, and runs the full check on every hop's URL.
2. The hostname is resolved once, the result is checked against the allowed addresses, and the
   request connects to that exact address with the original `Host` header. A name that resolves
   differently between the check and the connection (DNS rebinding) cannot change the target.
3. Only `http` is accepted in this lab. Pinning an address for `https` needs a custom adapter that
   keeps SNI and certificate checks on the original hostname; that is not done here.

Why it works: the property being enforced is "every address this server connects to was approved",
and that is checked at the point of connection for each hop instead of once at the front.

`test_fixed_service_still_previews_pages_and_follows_allowed_redirects` guards against fixing it by
breaking the feature: a redirect to an allowed page still works.

## Detection

`detection/web_ssrf_preview_internal_address.yml` is a Sigma rule over the lab's own access log
(NDJSON, W3C-style field names; the format is in `vulnlab_common/harness.py`). It flags
`/preview` requests whose `url` parameter contains a literal internal or metadata address, directly
or inside a redirect URL. `sample_attack.ndjson` and `sample_benign.ndjson` are recorded from real
runs of the tests (`VULNLAB_RECORD=1 pytest labs/01-ssrf-redirect`), and the test replays the rule
over both.

Limits:

- It sees the attempt, not the result. It fires on the fixed service too.
- It misses internal targets named by hostname, and any address form not in the list (decimal,
  IPv6-mapped).
- A first draft matched "nested redirect parameter in the url" in general. It also fired on the
  benign redirect sample, so it was narrowed to internal-address literals.
- The rule is replayed with tripline's compiler (`tripline` v0.2.1). Tripline's logsource router
  does not cover web-server logs, so it is bypassed and the rule is applied to the whole file.

## What sinkline sees

Command: `sinkline scan <dir> --no-color` from this directory, sinkline 0.5.0. Captured output is
in `sinkline/`.

| Version | Result |
|---|---|
| vulnerable | 1 finding, SL-SSRF-001 (CWE-918), `requests.get` at `app.py:23`, source `request.args` |
| fixed | 1 finding, SL-SSRF-001, same flow reported through `fetch()` at `app.py:33` |

The vulnerable finding is correct. The fixed one is a false positive: sinkline does not model a
project-specific validator, so it reports the flow as unsanitized. This is documented as a sinkline
limitation (no recognition of custom allow-list and pinning logic) and the lab was not changed to
avoid it. Also note that on the vulnerable version sinkline does not say that the bug is the
redirect; it reports "tainted URL reaches `requests.get`", which would also be true of an app with
no allow-list.

## References

- OWASP, Server Side Request Forgery Prevention Cheat Sheet: advises disabling redirect following,
  preferring allow-lists, and validating resolved addresses and connecting to the validated one.
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy, "What is SSRF": describes bypassing an allow-list through an open
  redirect on a trusted domain. https://portswigger.net/web-security/ssrf
- MITRE, CWE-918: Server-Side Request Forgery. https://cwe.mitre.org/data/definitions/918.html

Run: `pytest -q labs/01-ssrf-redirect`
