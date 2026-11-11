"""Lab-side stand-ins: an internal metadata service and a partner site with an open redirect."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, redirect, request


def internal_app(canary_file: Path) -> Flask:
    app = Flask("internal")

    @app.get("/latest/meta-data/credentials")
    def credentials():
        return jsonify(role="lab-internal", secret_token=canary_file.read_text().strip())

    return app


def partner_app() -> Flask:
    app = Flask("partner")

    @app.get("/page")
    def page():
        return "<html><title>Partner page</title><body>hello</body></html>"

    @app.get("/go")
    def go():
        return redirect(request.args["to"], code=302)

    return app
