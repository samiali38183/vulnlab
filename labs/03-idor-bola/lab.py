"""Start the lab-03 invoice API on loopback with seeded users and records."""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from vulnlab_common.guard import LoopbackSession
from vulnlab_common.harness import serve
from vulnlab_common.loader import load

HERE = Path(__file__).resolve().parent
OWNERS = {1: "alice", 2: "mallory", 3: "alice", 4: "bob", 5: "mallory", 6: "alice", 7: "bob", 8: "alice"}
VICTIM_ID = 4


@dataclass
class Running:
    target: str
    canary: str
    passwords: dict[str, str]
    log_path: Path
    client: LoopbackSession = field(default_factory=LoopbackSession)

    def login(self, user: str) -> dict[str, str]:
        body = {"user": user, "password": self.passwords[user]}
        token = self.client.post(f"{self.target}/api/login", json=body).json()["token"]
        return {"Authorization": f"Bearer {token}"}

    def raw_login(self, body):
        return self.client.post(f"{self.target}/api/login", json=body)

    def get(self, path: str, headers: dict[str, str] | None = None):
        return self.client.get(f"{self.target}{path}", headers=headers)

    def patch(self, path: str, memo: str, headers: dict[str, str] | None = None):
        return self.client.patch(f"{self.target}{path}", json={"memo": memo}, headers=headers)


@contextmanager
def start(variant: str, workdir: Path) -> Iterator[Running]:
    workdir.mkdir(parents=True, exist_ok=True)
    canary = "canary-" + secrets.token_hex(6)
    passwords = {name: secrets.token_hex(8) for name in ("alice", "mallory", "bob")}
    invoices = [
        {"id": i, "owner": owner, "memo": canary if i == VICTIM_ID else f"routine invoice {i}"}
        for i, owner in OWNERS.items()
    ]
    settings = {"users": passwords, "invoices": invoices}
    app = load(HERE / variant / "app.py", f"lab03_{variant}").create_app(settings)
    log_path = workdir / f"{variant}.access.ndjson"
    with serve(app, log_path) as server:
        yield Running(server.url, canary, passwords, log_path)
