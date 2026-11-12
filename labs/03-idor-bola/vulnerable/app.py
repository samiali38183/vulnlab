from __future__ import annotations

import secrets

from flask import Flask, jsonify, request


def create_app(settings: dict) -> Flask:
    app = Flask(__name__)
    invoices = {item["id"]: item for item in settings["invoices"]}
    sessions: dict[str, str] = {}

    def current_user() -> str | None:
        return sessions.get(request.headers.get("Authorization", "").removeprefix("Bearer "))

    @app.post("/api/login")
    def login():
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        user, password = body.get("user"), body.get("password")
        expected = settings["users"].get(user) if isinstance(user, str) else None
        if expected is None or not isinstance(password, str) or password != expected:
            return jsonify(error="bad credentials"), 401
        token = secrets.token_hex(16)
        sessions[token] = user
        return jsonify(token=token)

    @app.get("/api/invoices")
    def list_invoices():
        user = current_user()
        if user is None:
            return jsonify(error="login required"), 401
        return jsonify([i for i in invoices.values() if i["owner"] == user])

    @app.get("/api/invoices/<int:object_id>")
    def get_invoice(object_id: int):
        if current_user() is None:
            return jsonify(error="login required"), 401
        if object_id not in invoices:
            return jsonify(error="not found"), 404
        return jsonify(invoices[object_id])

    @app.patch("/api/invoices/<int:object_id>")
    def update_invoice(object_id: int):
        user = current_user()
        if user is None:
            return jsonify(error="login required"), 401
        invoice = invoices.get(object_id)
        if invoice is None or invoice["owner"] != user:
            return jsonify(error="not found"), 404
        invoice["memo"] = (request.get_json(silent=True) or {}).get("memo", invoice["memo"])
        return jsonify(invoice)

    return app
