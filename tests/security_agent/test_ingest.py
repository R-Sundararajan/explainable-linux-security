from __future__ import annotations

import json
import os
from pathlib import Path
import socket

import pytest

from security_agent.contracts import MAX_PACKET_BYTES
from security_agent.ingest import EvidenceSocketServer

from helpers import evidence_dict


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SOCK_SEQPACKET"),
    reason="Unix SOCK_SEQPACKET is required",
)


def packet(**kwargs: object) -> bytes:
    return json.dumps(evidence_dict(**kwargs), separators=(",", ":")).encode()


def connect(path: Path) -> socket.socket:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.connect(str(path))
    return client


def pump(server: EvidenceSocketServer, count: int = 3) -> None:
    for _ in range(count):
        server.poll_once(0.1)


def test_seqpacket_server_preserves_and_validates_packets(tmp_path: Path) -> None:
    path = tmp_path / "evidence.sock"
    with EvidenceSocketServer(path, queue_capacity=2) as server:
        client = connect(path)
        client.sendall(packet())
        pump(server)
        accepted = server.drain()
        assert len(accepted) == 1
        assert accepted[0].evidence_id == "evidence-1"

        client.sendall(b"{bad")
        unknown = evidence_dict(evidence_id="unknown")
        unknown["schema_version"] = "unknown"
        client.sendall(json.dumps(unknown).encode())
        client.sendall(b"x" * MAX_PACKET_BYTES)
        pump(server, 6)
        assert server.stats.malformed_packets == 1
        assert server.stats.unknown_schema_packets == 1
        assert server.stats.oversized_packets == 1
        client.close()
    assert not path.exists()


def test_queue_and_connection_bounds(tmp_path: Path) -> None:
    path = tmp_path / "bounded.sock"
    with EvidenceSocketServer(path, queue_capacity=1) as server:
        client = connect(path)
        client.sendall(packet(evidence_id="one"))
        client.sendall(packet(evidence_id="two"))
        pump(server, 5)
        assert len(server.drain()) == 1
        assert server.stats.queue_drops == 1
        client.close()


def test_peer_uid_is_enforced(tmp_path: Path) -> None:
    path = tmp_path / "uid.sock"
    with EvidenceSocketServer(path, allowed_uid=os.getuid() + 1) as server:
        client = connect(path)
        pump(server)
        assert server.stats.unauthorized_connections == 1
        client.close()
