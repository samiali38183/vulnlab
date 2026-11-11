from __future__ import annotations

from urllib.parse import urlsplit

import requests
from flask import Flask, jsonify, request


def create_app(settings: dict | None = None) -> Flask:
    config = {"allowed_hosts": {"127.0.0.1"}, **(settings or {})}
    app = Flask(__name__)

    def host_allowed(url: str) -> bool:
        parts = urlsplit(url)
        return parts.scheme in ("http", "https") and parts.hostname in config["allowed_hosts"]

    @app.get("/preview")
    def preview():
        url = request.args.get("url", "")
        if not host_allowed(url):
            return jsonify(error="host not allowed"), 403
        try:
            upstream = requests.get(url, timeout=3)
        except requests.RequestException:
            return jsonify(error="fetch failed"), 502
        return jsonify(status=upstream.status_code, excerpt=upstream.text[:300])

    return app
