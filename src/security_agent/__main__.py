from __future__ import annotations

import argparse
from contextlib import ExitStack
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
from .ml.predict import MLThreatModel


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local Linux security/XAI agent",
        epilog=(
            "Start with this command after setup. Stop with Ctrl+C, or use "
            "'./scripts/security-agent.sh stop' when started by the lifecycle script."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="strict JSON configuration (see config/security-agent.example.json)",
    )
    parser.add_argument(
        "--explanation-file",
        type=Path,
        metavar="PATH",
        help="append each human-readable XAI explanation to a .txt file",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and configured local model, then exit",
    )
    return parser.parse_args()


def _provider(config: AgentConfig) -> MLThreatModel | None:
    if config.model is None:
        return None
    return MLThreatModel(config.model)


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
            print("configuration valid; local ML artifact and checksum verified")
            return 0

        stopping = threading.Event()

        def request_stop(_signum: int, _frame: object) -> None:
            stopping.set()

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        explanation_path = arguments.explanation_file
        if explanation_path is not None:
            explanation_path = explanation_path.resolve()
            if explanation_path.suffix.lower() != ".txt":
                raise ValueError("--explanation-file must use a .txt suffix")
            if explanation_path == config.audit_path.resolve():
                raise ValueError("explanation file must differ from the JSONL audit path")
            if not explanation_path.parent.is_dir():
                raise ValueError(
                    f"explanation directory is missing: {explanation_path.parent}"
                )

        with ExitStack() as resources:
            audit = resources.enter_context(AuditWriter(config.audit_path))
            explanation_file = (
                None
                if explanation_path is None
                else resources.enter_context(
                    explanation_path.open("a", encoding="utf-8", newline="\n")
                )
            )

            def emit(event: SecurityAuditEvent) -> None:
                audit.write(event)
                print(event.model_dump_json(), flush=True)
                rendered = render_explanation(event.explanation)
                print(rendered, flush=True)
                if explanation_file is not None:
                    print(rendered, file=explanation_file)
                    print(file=explanation_file, flush=True)

            coordinator = SecurityAgentCoordinator(config, emit, provider)
            try:
                with EvidenceSocketServer(
                    config.evidence_socket,
                    queue_capacity=config.ingest_queue_capacity,
                    allowed_uid=config.allowed_uid,
                ) as server:
                    print(
                        f"security agent listening on {config.evidence_socket}; "
                        f"ml_model={'configured' if provider else 'not configured'}; "
                        f"explanations={explanation_path or 'terminal only'}; "
                        "stop with Ctrl+C",
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
