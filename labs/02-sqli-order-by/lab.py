"""Start the lab-02 product API on loopback with a lab-owned SQLite database."""

from __future__ import annotations

import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from vulnlab_common.guard import LoopbackSession
from vulnlab_common.harness import serve
from vulnlab_common.loader import load

HERE = Path(__file__).resolve().parent
PRODUCTS = [(1, "apple", 3.0), (2, "banana", 1.0), (3, "cherry", 2.0)]
NAME_ORDER = [1, 2, 3]
PRICE_ORDER = [2, 3, 1]


@dataclass
class Running:
    target: str
    canary: str
    log_path: Path
    client: LoopbackSession = field(default_factory=LoopbackSession)

    def product_ids(self, **params: str) -> list[int]:
        response = self.client.get(f"{self.target}/api/products", params=params)
        response.raise_for_status()
        return [row["id"] for row in response.json()]

    def get(self, **params: str):
        return self.client.get(f"{self.target}/api/products", params=params)


def init_db(path: Path, canary: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
        conn.executemany("INSERT INTO products VALUES (?, ?, ?)", PRODUCTS)
        conn.execute("CREATE TABLE api_keys (label TEXT, value TEXT)")
        conn.execute("INSERT INTO api_keys VALUES ('lab-canary', ?)", (canary,))


@contextmanager
def start(variant: str, workdir: Path) -> Iterator[Running]:
    workdir.mkdir(parents=True, exist_ok=True)
    canary = "canary-" + secrets.token_hex(6)
    db_path = workdir / "lab.sqlite3"
    db_path.unlink(missing_ok=True)
    init_db(db_path, canary)
    app = load(HERE / variant / "app.py", f"lab02_{variant}").create_app({"db_path": str(db_path)})
    log_path = workdir / f"{variant}.access.ndjson"
    with serve(app, log_path) as server:
        yield Running(server.url, canary, log_path)
