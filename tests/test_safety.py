"""Safety tests: the harness and client refuse anything that is not loopback."""

from __future__ import annotations

import ast
import re

import pytest
from flask import Flask

from vulnlab_common.guard import (
    LoopbackSession,
    NonLoopbackTarget,
    assert_loopback_url,
    is_loopback_host,
)
from vulnlab_common.harness import serve
from vulnlab_common.loader import LABS

NON_LOOPBACK = [
    "http://192.0.2.10/",
    "http://10.0.0.5:8080/x",
    "http://169.254.169.254/latest",
    "http://example.com/",
    "http://0.0.0.0:80/",
    "http://127.0.0.1.example.com/",
    "http://localhost.example.com/",
    "http://[2001:db8::1]/",
]
LOOPBACK = ["http://127.0.0.1:1/", "http://127.0.0.2:9/x", "http://localhost/", "http://[::1]:5/"]


@pytest.mark.parametrize("url", NON_LOOPBACK)
def test_guard_refuses_non_loopback_urls(url):
    with pytest.raises(NonLoopbackTarget):
        assert_loopback_url(url)


@pytest.mark.parametrize("url", NON_LOOPBACK)
def test_client_refuses_non_loopback_before_sending(url):
    with pytest.raises(NonLoopbackTarget):
        LoopbackSession().get(url)


@pytest.mark.parametrize("url", LOOPBACK)
def test_guard_accepts_loopback_urls(url):
    assert assert_loopback_url(url) == url


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.10", "example.com", "", "::"])
def test_harness_refuses_to_bind_non_loopback(host):
    assert not is_loopback_host(host)
    with pytest.raises(ValueError):
        serve(Flask("x"), host=host)


def test_lab_tests_use_only_the_loopback_client():
    for test_file in LABS.glob("*/test_lab.py"):
        tree = ast.parse(test_file.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        assert "requests" not in imported, f"{test_file} must use the harness client"
        assert not re.search(r"https?://(?!127\.|localhost|\[::1\])", test_file.read_text())
