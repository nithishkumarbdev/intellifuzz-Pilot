"""
Shared fixtures for the runner test suite.

Three ways of reaching the vulnerable-api target, used for different
purposes:

- `asgi_client` / `vulnerable_api_app`: a FRESH vulnerable-api app
  instance per test, wired via httpx.ASGITransport. No real socket, no
  background process — fast and deterministic. Freshness matters: many
  tests perform state-changing requests (POST/PUT/PATCH/DELETE against
  the in-memory USERS/ORDERS "database"), and sharing one instance
  across tests caused real cross-test pollution — a DELETE in one test
  file silently broke an unrelated test elsewhere in the suite because
  both happened to reference the same default user id. Loading a fresh
  module instance per test is cheap (in-process exec, not a server
  boot) and gives every test proper isolation.

- `live_vulnerable_api_url`: a SEPARATE, dedicated vulnerable-api
  instance actually bound to a real local port, running in a background
  thread for the whole test session. Only used where real network-level
  behavior is required — specifically timeouts, since httpx does not
  enforce its timeout against an in-process ASGI transport (there's no
  real I/O for it to interrupt). Session-scoped deliberately: booting a
  real server per test is slow, and most tests that use this fixture
  either don't care about specific resource state or only need "alice
  still exists at the very start" — true for the first user of the
  fixture in a session, but NOT guaranteed for every test, since a
  full-spec capture_baselines() call also captures DELETE
  /users/{user_id}'s baseline as a side effect, which really deletes
  user 1 on the shared server. A test file that ran a full-spec
  baseline+fuzz pass and then later needed user 1 to still exist hit
  exactly this — see test_rules_pipeline.py's own history.

- `isolated_live_vulnerable_api_url`: a dedicated, function-scoped real
  server — for tests that specifically need guaranteed-fresh seed data
  regardless of what any other test in the same file already did.
  Slower (boots a real server per test), used only where that
  guarantee genuinely matters.
"""

from __future__ import annotations

import importlib.util
import socket
import threading
import time
from pathlib import Path
from typing import Iterator

import httpx
import pytest
import uvicorn

VULN_API_MAIN = Path(__file__).parent.parent / "vulnerable-api" / "app" / "main.py"


def _load_vulnerable_api_app():
    # Loaded via importlib with an explicit module name (rather than a
    # normal sys.path import) because vulnerable-api's package is also
    # named `app` — same as our own top-level package. A regular import
    # would collide with it. Each call execs a brand-new module object
    # (never registered into sys.modules), so its module-level state
    # (USERS, ORDERS, ...) is always fresh.
    spec = importlib.util.spec_from_file_location("vulnerable_api_main", VULN_API_MAIN)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.app


@pytest.fixture
def vulnerable_api_app():
    """A fresh vulnerable-api app instance, isolated to this one test."""
    return _load_vulnerable_api_app()


@pytest.fixture
async def asgi_client(vulnerable_api_app) -> Iterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=vulnerable_api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://vulnerable-api-test") as client:
        yield client


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _boot_live_server(app) -> Iterator[str]:
    """Shared boot/teardown logic for both live-server fixtures below."""
    port = _find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(f"{base_url}/health", timeout=0.2)
            break
        except httpx.TransportError:
            time.sleep(0.1)
    else:
        raise RuntimeError("vulnerable-api did not start in time for live tests")

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def live_vulnerable_api_url() -> Iterator[str]:
    # Deliberately its own app instance, not shared with the
    # function-scoped `vulnerable_api_app` above.
    yield from _boot_live_server(_load_vulnerable_api_app())


@pytest.fixture
def isolated_live_vulnerable_api_url() -> Iterator[str]:
    """Function-scoped: a brand-new server + fresh seed data for this
    one test only, unaffected by what any other test did to the shared
    session-scoped server above."""
    yield from _boot_live_server(_load_vulnerable_api_app())


@pytest.fixture
def unused_port_url() -> str:
    """A base_url pointing at a real (unused) local port — nothing is
    listening, so any request against it should fail with a connection
    error. Used to test the runner's connection-error handling without
    depending on anything external."""
    return f"http://127.0.0.1:{_find_free_port()}"
