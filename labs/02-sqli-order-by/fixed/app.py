from __future__ import annotations

import sqlite3

from flask import Flask, jsonify, request

SORT_COLUMNS = {"id": "id", "name": "name", "price": "price"}


def create_app(settings: dict) -> Flask:
    app = Flask(__name__)

    @app.get("/api/products")
    def products():
        column = SORT_COLUMNS.get(request.args.get("sort", "name"))
        if column is None:
            return jsonify(error="unsupported sort column"), 400
        direction = "DESC" if request.args.get("order") == "desc" else "ASC"
        needle = f"%{request.args.get('q', '')}%"
        query = f"SELECT id, name, price FROM products WHERE name LIKE ? ORDER BY {column} {direction}"
        with sqlite3.connect(settings["db_path"]) as conn:
            rows = conn.execute(query, (needle,)).fetchall()
        return jsonify([{"id": i, "name": n, "price": p} for i, n, p in rows])

    return app
