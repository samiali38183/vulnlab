from __future__ import annotations

import sqlite3

from flask import Flask, jsonify, request


def create_app(settings: dict) -> Flask:
    app = Flask(__name__)

    @app.get("/api/products")
    def products():
        sort = request.args.get("sort", "name")
        direction = "DESC" if request.args.get("order") == "desc" else "ASC"
        needle = f"%{request.args.get('q', '')}%"
        query = f"SELECT id, name, price FROM products WHERE name LIKE ? ORDER BY {sort} {direction}"
        with sqlite3.connect(settings["db_path"]) as conn:
            try:
                rows = conn.execute(query, (needle,)).fetchall()
            except sqlite3.Error:
                return jsonify(error="bad query"), 400
        return jsonify([{"id": i, "name": n, "price": p} for i, n, p in rows])

    return app
