"""Loopback guard used by every proof script.

A target is accepted only if its host is a literal loopback IP address or the name
"localhost". No DNS lookup is performed, so a hostname cannot resolve its way past the check.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

import requests


class NonLoopbackTarget(ValueError):
    """Raised when a proof script is pointed at anything other than loopback."""


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_loopback_url(url: str) -> str:
    try:
        host = urlsplit(url).hostname
    except ValueError as exc:
        raise NonLoopbackTarget(f"unparseable URL: {url!r}") from exc
    if not is_loopback_host(host):
        raise NonLoopbackTarget(f"refusing non-loopback target: {url!r}")
    return url


class LoopbackSession(requests.Session):
    """requests.Session that checks every request URL, and never follows redirects itself."""

    def request(self, method, url, **kwargs):  # type: ignore[override]
        assert_loopback_url(url)
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("timeout", 5)
        return super().request(method, url, **kwargs)
