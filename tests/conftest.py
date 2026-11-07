"""Shared test setup.

Network guard: every test runs with socket connections and DNS lookups blocked, so an
accidental network request fails loudly instead of contacting a real host. Never
disable or bypass this; stub the network code instead (see CLAUDE.md).
"""

import socket

import pytest


class NetworkAccessBlocked(RuntimeError):
    """Raised when a test tries to use the network.

    Deliberately not an OSError, so code that handles connection errors
    (e.g. turning them into {"error": ...}) can't silently swallow it.
    """


def _blocked(*args, **kwargs):
    raise NetworkAccessBlocked("Tests must not use the network; stub the fetch function instead.")


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    monkeypatch.setattr(socket.socket, "sendto", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
