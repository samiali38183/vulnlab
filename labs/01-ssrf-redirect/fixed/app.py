from __future__ import annotations

import socket
from urllib.parse import urljoin, urlsplit

import requests
from flask import Flask, jsonify, request

MAX_HOPS = 3


class Blocked(Exception):
    pass


def create_app(settings: dict | None = None) -> Flask:
    config = {"allowed_hosts": {"127.0.0.1"}, "allowed_addrs": {"127.0.0.1"}, **(settings or {})}
    app = Flask(__name__)

    def resolve_allowed(url: str) -> tuple[str, str]:
        parts = urlsplit(url)
        if parts.scheme != "http" or parts.hostname not in config["allowed_hosts"]:
            raise Blocked("host not allowed")
        port = parts.port or 80
        addr = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)[0][4][0]
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
        except Blocked as exc:
            return jsonify(error=str(exc)), 403
        except requests.RequestException:
            return jsonify(error="fetch failed"), 502
        return jsonify(status=upstream.status_code, excerpt=upstream.text[:300])

    return app
