"""Start the lab-01 service set (preview app, partner site, internal service) on loopback."""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode

from vulnlab_common.guard import LoopbackSession
from vulnlab_common.harness import serve
from vulnlab_common.loader import load

HERE = Path(__file__).resolve().parent
services = load(HERE / "services.py", "lab01_services")


@dataclass
class Running:
    target: str
    partner: str
    internal: str
    canary: str
    log_path: Path
    internal_log: Path
    client: LoopbackSession = field(default_factory=LoopbackSession)

    def preview(self, url: str):
        return self.client.get(f"{self.target}/preview?{urlencode({'url': url})}")

    @property
    def internal_url(self) -> str:
        return f"{self.internal}/latest/meta-data/credentials"

    def via_partner_redirect(self, destination: str) -> str:
        return f"{self.partner}/go?{urlencode({'to': destination})}"


@contextmanager
def start(variant: str, workdir: Path) -> Iterator[Running]:
    workdir.mkdir(parents=True, exist_ok=True)
    canary = "canary-" + secrets.token_hex(6)
    canary_file = workdir / "canary.txt"
    canary_file.write_text(canary)
    app_module = load(HERE / variant / "app.py", f"lab01_{variant}")
    log_path = workdir / f"{variant}.access.ndjson"
    internal_log = workdir / "internal.access.ndjson"
    with ExitStack() as stack:
        internal = stack.enter_context(
            serve(services.internal_app(canary_file), internal_log, host="127.0.0.2")
        )
        partner = stack.enter_context(serve(services.partner_app()))
        target = stack.enter_context(serve(app_module.create_app(), log_path))
        yield Running(target.url, partner.url, internal.url, canary, log_path, internal_log)
