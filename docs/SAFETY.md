# Safety scope

vulnlab contains intentionally vulnerable code. Read it, run it and test it on your own machine
only.

## Rules the repo enforces

- Everything binds to loopback. `vulnlab_common/harness.py` refuses to start a service on any
  host that is not a loopback address, and the services use random free ports.
- Every request the tests make goes through `LoopbackSession` (`vulnlab_common/guard.py`), which
  checks the URL before sending anything. A host is accepted only if it is `localhost` or a
  literal loopback IP. No DNS lookup is done, so a hostname cannot resolve past the check.
- The lab's own redirects are checked too: the client does not follow redirects itself, and
  the services involved are all started by the test.
- `tests/test_safety.py` asserts that non-loopback URLs (private ranges, the link-local metadata
  address, public names, look-alike names such as `127.0.0.1.example.com`, `0.0.0.0`, IPv6
  documentation addresses) are refused by the guard and by the client before a request is made,
  that the harness will not bind to them, and that no lab test imports `requests` directly or
  names a non-loopback URL.
- The only data touched is created by the lab test in a temporary directory or in memory: a
  canary string, a SQLite file, seeded records. There is no shell, persistence, evasion, scanning
  or code that works against anything other than the lab's own services.
- The stand-in "internal" address in lab 01 is 127.0.0.2, which is still loopback.

## Not in scope

- No real products, vendors or exploited CVEs are reproduced. The bugs are small, self-written
  examples of common classes.
- This is not vulnerability research, and there are no disclosures or CVEs.
- The vulnerable apps have no hardening. Do not deploy them, expose them on a network, or reuse
  their code outside the lab.
