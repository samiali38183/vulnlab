from __future__ import annotations

import secrets

from flask import Flask, abort, jsonify, request


def create_app(settings: dict) -> Flask:
    app = Flask(__name__)
    invoices = {item["id"]: item for item in settings["invoices"]}
    sessions: dict[str, str] = {}

    def current_user() -> str:
        user = sessions.get(request.headers.get("Authorization", "").removeprefix("Bearer "))
        if user is None:
            abort(401)
        return user

    def owned_invoice(object_id: int) -> dict:
        invoice = invoices.get(object_id)
        if invoice is None or invoice["owner"] != current_user():
            abort(404)
        return invoice

    @app.errorhandler(401)
    @app.errorhandler(404)
    def error(exc):
        return jsonify(error=exc.name.lower()), exc.code

    @app.post("/api/login")
    def login():
        body = request.get_json(silent=True) or {}
        if settings["users"].get(body.get("user")) != body.get("password"):
            return jsonify(error="bad credentials"), 401
        token = secrets.token_hex(16)
        sessions[token] = body["user"]
        return jsonify(token=token)

    @app.get("/api/invoices")
    def list_invoices():
        user = current_user()
        return jsonify([i for i in invoices.values() if i["owner"] == user])

    @app.get("/api/invoices/<int:object_id>")
    def get_invoice(object_id: int):
        return jsonify(owned_invoice(object_id))

    @app.patch("/api/invoices/<int:object_id>")
    def update_invoice(object_id: int):
        invoice = owned_invoice(object_id)
        invoice["memo"] = (request.get_json(silent=True) or {}).get("memo", invoice["memo"])
        return jsonify(invoice)

    return app
