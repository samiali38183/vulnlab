from __future__ import annotations

import socket
from urllib.parse import urljoin, urlsplit

import requests
from flask import Flask, jsonify, request

MAX_HOPS = 3
MAX_URL_LENGTH = 2048


class Blocked(Exception):
    """A well-formed URL that policy refuses (403)."""


class InvalidUrl(Exception):
    """Input that is not a usable http URL at all (400)."""


def create_app(settings: dict | None = None) -> Flask:
    config = {"allowed_hosts": {"127.0.0.1"}, "allowed_addrs": {"127.0.0.1"}, **(settings or {})}
    app = Flask(__name__)

    def resolve_allowed(url: str) -> tuple[str, str]:
        if len(url) > MAX_URL_LENGTH:
            raise InvalidUrl("too long")
        try:
            parts = urlsplit(url)
            hostname = parts.hostname
            port = parts.port
        except ValueError:  # unterminated IPv6 literal, non-numeric or out-of-range port
            raise InvalidUrl("unparseable") from None
        if parts.scheme != "http":
            raise InvalidUrl("only http is supported")
        if not hostname:
            raise InvalidUrl("missing host")
        if "@" in parts.netloc:
            raise InvalidUrl("credentials in the URL are not accepted")
        if port == 0:
            raise InvalidUrl("invalid port")
        if hostname not in config["allowed_hosts"]:
            raise Blocked("host not allowed")
        port = port or 80
        addr = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)[0][4][0]
        if addr not in config["allowed_addrs"]:
            raise Blocked("address not allowed")
        return parts.netloc, parts._replace(netloc=f"{addr}:{port}").geturl()

    def fetch(url: str) -> requests.Response:
        for _ in range(MAX_HOPS + 1):
            host_header, pinned = resolve_allowed(url)
            upstream = requests.get(pinned, headers={"Host": host_header}, allow_redirects=False, timeout=3)
            if not upstream.is_redirect:
                return upstream
            url = urljoin(url, upstream.headers["Location"])
        raise Blocked("too many redirects")

    @app.get("/preview")
    def preview():
        try:
            upstream = fetch(request.args.get("url", ""))
        except InvalidUrl:
            return jsonify(error="invalid url"), 400
        except Blocked as exc:
            return jsonify(error=str(exc)), 403
        except requests.RequestException:
            return jsonify(error="fetch failed"), 502
        return jsonify(status=upstream.status_code, excerpt=upstream.text[:300])

    return app
