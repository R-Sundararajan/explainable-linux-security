from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess


def _run(*arguments: str) -> None:
    subprocess.run(
        list(arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=5,
    )


def run_safe_workload(scenario: str, sandbox: Path) -> None:
    """Perform bounded real activity only inside the supplied temporary root."""

    sandbox.mkdir(mode=0o700)
    if scenario == "simple_activity":
        note = sandbox / "note.txt"
        note.write_text("ordinary activity\n", encoding="utf-8")
        _run("/usr/bin/pwd")
        _run("/usr/bin/ls", str(sandbox))
        _run("/usr/bin/cat", str(note))
        _run("/usr/bin/sleep", "0.01")
        return

    if scenario == "file_activity":
        for index in range(8):
            item = sandbox / f"item-{index}.txt"
            item.write_text("created\n", encoding="utf-8")
            item.write_text("modified\n", encoding="utf-8")
            renamed = sandbox / f"renamed-{index}.txt"
            item.rename(renamed)
            renamed.unlink()
        return

    if scenario == "benign_activity":
        checksum = 0
        for index in range(500):
            item = sandbox / f"bounded-{index:04d}.txt"
            content = f"legitimate-data-{index}\n"
            item.write_text(content, encoding="utf-8")
            checksum += len(item.read_bytes())
        if checksum <= 0:
            raise AssertionError("benign workload did not read its data")
        for _ in range(8):
            _run("/usr/bin/true")
        for item in sandbox.iterdir():
            item.unlink()
        return

    if scenario == "suspicious_activity":
        credentials = sandbox / "credential-like"
        credentials.mkdir()
        (credentials / "synthetic-token").write_text(
            "not-a-real-secret\n",
            encoding="utf-8",
        )
        staged = sandbox / "staged-executable"
        staged.write_text("test fixture only\n", encoding="utf-8")
        staged.chmod(0o700)
        for index in range(20):
            (sandbox / f"rapid-{index}").write_text("stage\n", encoding="utf-8")
        left, right = socket.socketpair()
        try:
            left.sendall(b"local-only")
            if right.recv(32) != b"local-only":
                raise AssertionError("local socket fixture failed")
        finally:
            left.close()
            right.close()
        _run("/usr/bin/true")
        return

    if scenario == "malicious_simulation":
        fake_credentials = sandbox / "fake-credentials"
        fake_persistence = sandbox / "fake-persistence"
        fake_credentials.mkdir()
        fake_persistence.mkdir()
        (fake_credentials / "shadow.test").write_text(
            "synthetic-only\n",
            encoding="utf-8",
        )
        (fake_persistence / "autostart.test").write_text(
            "synthetic-only\n",
            encoding="utf-8",
        )
        destructive = sandbox / "destructive-only-here"
        destructive.mkdir()
        for index in range(30):
            target = destructive / f"target-{index}"
            target.write_bytes(os.urandom(32))
            target.unlink()
        for _ in range(3):
            _run("/usr/bin/true")
        return

    raise ValueError(f"unsupported safe workload: {scenario}")
