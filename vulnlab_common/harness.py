"""Start a lab Flask app on a free loopback port, with an NDJSON access log."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, request
from werkzeug.serving import BaseWSGIServer, make_server

from vulnlab_common.guard import is_loopback_host

logging.getLogger("werkzeug").setLevel(logging.ERROR)


class Server:
    def __init__(self, app: Flask, host: str, log_path: Path | None) -> None:
        if not is_loopback_host(host):
            raise ValueError(f"lab services bind to loopback only, got {host!r}")
        if log_path is not None:
            _add_access_log(app, log_path)
        self._server: BaseWSGIServer = make_server(host, 0, app, threaded=True)
        self.url = f"http://{host}:{self._server.server_port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> Server:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


def serve(app: Flask, log_path: Path | None = None, host: str = "127.0.0.1") -> Server:
    return Server(app, host, log_path)


def _add_access_log(app: Flask, log_path: Path) -> None:
    lock = threading.Lock()

    @app.after_request
    def log(response):
        auth = request.headers.get("Authorization", "")
        record = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "c-ip": request.remote_addr,
            "cs-method": request.method,
            "cs-uri-stem": request.path,
            "cs-uri-query": request.query_string.decode("latin-1"),
            "sc-status": response.status_code,
            "session": hashlib.sha256(auth.encode()).hexdigest()[:12] if auth else "-",
            "object_id": (request.view_args or {}).get("object_id", "-"),
        }
        with lock, log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        return response
