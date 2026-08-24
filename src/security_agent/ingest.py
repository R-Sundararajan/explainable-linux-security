from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct

from pydantic import ValidationError

from .contracts import (
    MAX_PACKET_BYTES,
    PROCESS_EVIDENCE_SCHEMA_VERSION,
    ProcessEvidence,
)


DEFAULT_EVIDENCE_SOCKET = Path("/run/linux-security-agent/evidence.sock")
DEFAULT_QUEUE_CAPACITY = 128
MAX_CONNECTIONS = 4


class EvidencePacketError(ValueError):
    pass


class OversizedEvidencePacket(EvidencePacketError):
    pass


class MalformedEvidencePacket(EvidencePacketError):
    pass


class UnknownEvidenceSchema(EvidencePacketError):
    pass


def decode_evidence_packet(
    packet: bytes,
    *,
    max_packet_bytes: int = MAX_PACKET_BYTES,
) -> ProcessEvidence:
    if not packet:
        raise MalformedEvidencePacket("empty evidence packet")
    if len(packet) >= max_packet_bytes:
        raise OversizedEvidencePacket(
            f"evidence packet is {len(packet)} bytes; limit is {max_packet_bytes - 1}"
        )
    try:
        untyped = json.loads(packet)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MalformedEvidencePacket("evidence packet is not valid UTF-8 JSON") from error
    if not isinstance(untyped, dict):
        raise MalformedEvidencePacket("evidence packet root must be an object")
    version = untyped.get("schema_version")
    if version != PROCESS_EVIDENCE_SCHEMA_VERSION:
        raise UnknownEvidenceSchema(str(version))
    try:
        return ProcessEvidence.model_validate_json(packet, strict=True)
    except ValidationError as error:
        raise MalformedEvidencePacket(str(error)) from error


@dataclass(slots=True)
class IngestStats:
    accepted_connections: int = 0
    unauthorized_connections: int = 0
    rejected_connections: int = 0
    packets_received: int = 0
    packets_accepted: int = 0
    malformed_packets: int = 0
    unknown_schema_packets: int = 0
    oversized_packets: int = 0
    queue_drops: int = 0


class EvidenceSocketServer:
    def __init__(
        self,
        socket_path: str | Path = DEFAULT_EVIDENCE_SOCKET,
        *,
        queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
        allowed_uid: int | None = None,
    ) -> None:
        if not 1 <= queue_capacity <= 4_096:
            raise ValueError("queue_capacity outside safe bounds")
        self.socket_path = Path(socket_path)
        if len(os.fsencode(self.socket_path)) >= 108:
            raise ValueError("Unix socket path is too long")
        self.allowed_uid = os.getuid() if allowed_uid is None else allowed_uid
        self._queue_capacity = queue_capacity
        self._queue: deque[ProcessEvidence] = deque()
        self._listener: socket.socket | None = None
        self._connections: set[socket.socket] = set()
        self._owns_socket_path = False
        self.stats = IngestStats()

    @staticmethod
    def _peer_uid(connection: socket.socket) -> int:
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _, uid, _ = struct.unpack("3i", credentials)
        return uid

    def _remove_stale_socket(self) -> None:
        try:
            state = os.lstat(self.socket_path)
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(state.st_mode):
            raise RuntimeError(f"refusing to replace non-socket path: {self.socket_path}")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            probe.connect(str(self.socket_path))
        except OSError as error:
            if error.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
                raise
        else:
            raise RuntimeError(f"evidence socket is already active: {self.socket_path}")
        finally:
            probe.close()
        self.socket_path.unlink()

    def start(self) -> None:
        if self._listener is not None:
            return
        parent = self.socket_path.parent
        if not parent.is_dir():
            raise RuntimeError(f"evidence runtime directory is missing: {parent}")
        self._remove_stale_socket()
        listener = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC,
        )
        try:
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o660)
            listener.listen(MAX_CONNECTIONS)
        except Exception:
            listener.close()
            raise
        self._listener = listener
        self._owns_socket_path = True

    def _close_connection(self, connection: socket.socket) -> None:
        self._connections.discard(connection)
        connection.close()

    def _accept_ready(self) -> None:
        assert self._listener is not None
        while True:
            try:
                connection, _ = self._listener.accept()
            except BlockingIOError:
                return
            connection.setblocking(False)
            if len(self._connections) >= MAX_CONNECTIONS:
                self.stats.rejected_connections += 1
                connection.close()
                continue
            if self._peer_uid(connection) != self.allowed_uid:
                self.stats.unauthorized_connections += 1
                connection.close()
                continue
            self._connections.add(connection)
            self.stats.accepted_connections += 1

    def _receive_ready(self, connection: socket.socket) -> None:
        try:
            packet, _, flags, _ = connection.recvmsg(MAX_PACKET_BYTES, 0)
        except BlockingIOError:
            return
        except ConnectionError:
            self._close_connection(connection)
            return
        if not packet:
            self._close_connection(connection)
            return
        self.stats.packets_received += 1
        if flags & socket.MSG_TRUNC or len(packet) >= MAX_PACKET_BYTES:
            self.stats.oversized_packets += 1
            return
        try:
            evidence = decode_evidence_packet(packet)
        except UnknownEvidenceSchema:
            self.stats.unknown_schema_packets += 1
            return
        except OversizedEvidencePacket:
            self.stats.oversized_packets += 1
            return
        except MalformedEvidencePacket:
            self.stats.malformed_packets += 1
            return
        if len(self._queue) >= self._queue_capacity:
            self.stats.queue_drops += 1
            return
        self._queue.append(evidence)
        self.stats.packets_accepted += 1

    def poll_once(self, timeout: float = 0.0) -> int:
        if self._listener is None:
            raise RuntimeError("evidence socket server is not started")
        readers = [self._listener, *self._connections]
        ready, _, _ = select.select(readers, [], [], timeout)
        for item in ready:
            if item is self._listener:
                self._accept_ready()
            elif item in self._connections:
                self._receive_ready(item)
        return len(ready)

    def drain(self, limit: int | None = None) -> tuple[ProcessEvidence, ...]:
        if limit is None:
            limit = len(self._queue)
        if limit < 0:
            raise ValueError("drain limit cannot be negative")
        drained: list[ProcessEvidence] = []
        while self._queue and len(drained) < limit:
            drained.append(self._queue.popleft())
        return tuple(drained)

    def close(self) -> None:
        for connection in tuple(self._connections):
            self._close_connection(connection)
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._owns_socket_path:
            try:
                state = os.lstat(self.socket_path)
            except FileNotFoundError:
                pass
            else:
                if stat.S_ISSOCK(state.st_mode):
                    self.socket_path.unlink()
            self._owns_socket_path = False

    def __enter__(self) -> "EvidenceSocketServer":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
