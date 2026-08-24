from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import sys
import threading

from .audit import AuditWriter, SecurityAuditEvent
from .config import AgentConfig, load_agent_config
from .coordinator import SecurityAgentCoordinator
from .explain import render_explanation
from .ingest import EvidenceSocketServer
from .local_runner import LocalSubprocessRunner
from .reasoner import LocalSubprocessReasoner


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local Linux security/XAI agent")
    parser.add_argument("--config", type=Path, help="strict JSON configuration")
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and configured local model, then exit",
    )
    return parser.parse_args()


def _provider(config: AgentConfig) -> LocalSubprocessReasoner | None:
    if config.model is None:
        return None
    return LocalSubprocessReasoner(LocalSubprocessRunner(config.model))


def main() -> int:
    arguments = _arguments()
    if os.name != "posix" or not hasattr(os, "geteuid"):
        print("security agent requires Linux", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("refusing to run the Python security agent as root", file=sys.stderr)
        return 2
    try:
        config = load_agent_config(arguments.config)
        provider = _provider(config)
        if arguments.check_config:
            if provider is None:
                print("configuration valid; local model: not configured")
                return 0
            error = provider.runner.availability_error()
            if error:
                print(f"configuration invalid: local reasoner {error}", file=sys.stderr)
                return 1
            print("configuration valid; local model artifact and checksum verified")
            return 0

        stopping = threading.Event()

        def request_stop(_signum: int, _frame: object) -> None:
            stopping.set()

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        with AuditWriter(config.audit_path) as audit:
            def emit(event: SecurityAuditEvent) -> None:
                audit.write(event)
                print(event.model_dump_json(), flush=True)
                print(render_explanation(event.explanation), flush=True)

            coordinator = SecurityAgentCoordinator(config, emit, provider)
            try:
                with EvidenceSocketServer(
                    config.evidence_socket,
                    queue_capacity=config.ingest_queue_capacity,
                    allowed_uid=config.allowed_uid,
                ) as server:
                    print(
                        f"security agent listening on {config.evidence_socket}; "
                        f"model={'configured' if provider else 'not configured'}",
                        flush=True,
                    )
                    while not stopping.is_set():
                        coordinator.run_once(server)
            finally:
                coordinator.close()
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"security agent failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
