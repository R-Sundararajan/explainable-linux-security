from __future__ import annotations

from dataclasses import dataclass, replace
import errno
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import selectors
import signal
import stat
import subprocess
import threading
import time
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator, model_validator

from .contracts import StrictFrozenModel


MIB = 1024 * 1024
DEFAULT_MEMORY_LIMIT_BYTES = 500 * MIB
PREFERRED_MEMORY_LIMIT_BYTES = 350 * MIB
_GLOBAL_REASONER_SLOT = threading.BoundedSemaphore(1)
_DENIED_EXECUTABLE_NAMES = frozenset(
    {"sh", "bash", "dash", "zsh", "fish", "cmd", "powershell", "pwsh"}
)


class LocalRunnerConfig(StrictFrozenModel):
    backend_executable: Path
    backend_arguments: tuple[
        Annotated[str, StringConstraints(max_length=4_095)], ...
    ] = Field(default=(), max_length=32)
    model_path: Path | None = None
    expected_model_sha256: Annotated[
        str, StringConstraints(pattern=r"^[0-9a-f]{64}$")
    ] | None = None
    backend_id: Annotated[str, StringConstraints(min_length=1, max_length=127)] = (
        "local-subprocess-backend"
    )
    model_id: Annotated[str, StringConstraints(min_length=1, max_length=255)] = (
        "embedded-or-test-backend"
    )
    library_paths: tuple[Path, ...] = Field(default=(), max_length=4)
    ggml_backend_library: Path | None = None
    sandbox_executable: Path = Path("/usr/bin/bwrap")
    resource_limiter_executable: Path = Path("/usr/bin/prlimit")
    timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 60.0
    cpu_seconds: Annotated[int, Field(ge=1, le=300)] = 120
    memory_limit_bytes: Annotated[
        int, Field(ge=64 * MIB, le=DEFAULT_MEMORY_LIMIT_BYTES)
    ] = DEFAULT_MEMORY_LIMIT_BYTES
    max_processes: Annotated[int, Field(ge=1, le=4)] = 3
    max_input_bytes: Annotated[int, Field(ge=1_024, le=128 * 1_024)] = 64 * 1_024
    max_output_bytes: Annotated[int, Field(ge=1_024, le=64 * 1_024)] = 32 * 1_024
    max_stderr_bytes: Annotated[int, Field(ge=512, le=16 * 1_024)] = 8 * 1_024

    @field_validator(
        "backend_executable",
        "sandbox_executable",
        "resource_limiter_executable",
        "model_path",
    )
    @classmethod
    def absolute_paths(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("local runner paths must be absolute")
        return value

    @field_validator("library_paths")
    @classmethod
    def absolute_library_paths(cls, value: tuple[Path, ...]) -> tuple[Path, ...]:
        if any(not path.is_absolute() for path in value):
            raise ValueError("local library paths must be absolute")
        return value

    @field_validator("ggml_backend_library")
    @classmethod
    def absolute_ggml_backend(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("GGML backend path must be absolute")
        return value

    @model_validator(mode="after")
    def safe_command(self) -> "LocalRunnerConfig":
        if self.backend_executable.name.lower() in _DENIED_EXECUTABLE_NAMES:
            raise ValueError("shell executables are forbidden as reasoner backends")
        model_token_used = any("{model}" in value for value in self.backend_arguments)
        if model_token_used != (self.model_path is not None):
            raise ValueError("{model} argument and model_path must be configured together")
        if (self.model_path is None) != (self.expected_model_sha256 is None):
            raise ValueError("model path and expected SHA-256 must be configured together")
        if self.model_path is not None and self.model_id == "embedded-or-test-backend":
            raise ValueError("configured model artifacts require an explicit model ID")
        if len(set(self.library_paths)) != len(self.library_paths):
            raise ValueError("duplicate local library path")
        if self.ggml_backend_library is not None and not self.library_paths:
            raise ValueError("GGML backend requires a configured local library path")
        if self.ggml_backend_library is not None and not any(
            self.ggml_backend_library.is_relative_to(path)
            for path in self.library_paths
        ):
            raise ValueError("GGML backend must be inside a configured library path")
        if any("\x00" in value for value in self.backend_arguments):
            raise ValueError("backend arguments cannot contain NUL")
        return self


@dataclass(frozen=True, slots=True)
class LocalRunResult:
    output: bytes
    stderr: bytes
    error_code: str | None
    timed_out: bool
    resource_limited: bool
    input_bytes: int
    output_bytes: int
    elapsed_ms: float
    time_to_first_output_ms: float | None
    peak_incremental_rss_bytes: int
    peak_processes: int


def _empty_result(error_code: str, input_bytes: int = 0) -> LocalRunResult:
    return LocalRunResult(
        output=b"",
        stderr=b"",
        error_code=error_code,
        timed_out=False,
        resource_limited=False,
        input_bytes=input_bytes,
        output_bytes=0,
        elapsed_ms=0.0,
        time_to_first_output_ms=None,
        peak_incremental_rss_bytes=0,
        peak_processes=0,
    )


def _validate_host_file(path: Path, *, executable: bool) -> str | None:
    try:
        resolved = path.resolve(strict=True)
        state = resolved.stat()
    except (FileNotFoundError, OSError):
        return "FILE_UNAVAILABLE"
    if not stat.S_ISREG(state.st_mode):
        return "NOT_A_REGULAR_FILE"
    if state.st_mode & stat.S_IWOTH:
        return "WORLD_WRITABLE_FILE"
    if executable and not os.access(resolved, os.X_OK):
        return "BACKEND_NOT_EXECUTABLE"
    return None


def _validate_host_directory(path: Path) -> str | None:
    try:
        resolved = path.resolve(strict=True)
        state = resolved.stat()
    except (FileNotFoundError, OSError):
        return "DIRECTORY_UNAVAILABLE"
    if not stat.S_ISDIR(state.st_mode):
        return "NOT_A_DIRECTORY"
    if state.st_mode & stat.S_IWOTH:
        return "WORLD_WRITABLE_DIRECTORY"
    return None


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sandbox_command(config: LocalRunnerConfig) -> list[str]:
    backend = config.backend_executable.resolve(strict=True)
    command = [
        str(config.sandbox_executable),
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
    ]
    for library_path in ("/usr/lib", "/usr/local/lib", "/lib", "/lib64"):
        if Path(library_path).exists():
            command.extend(("--ro-bind", library_path, library_path))
    if Path("/etc/ld.so.cache").is_file():
        command.extend(("--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"))
    sandbox_libraries: list[str] = []
    resolved_libraries = tuple(path.resolve(strict=True) for path in config.library_paths)
    for index, library_path in enumerate(resolved_libraries):
        sandbox_path = f"/runtime/lib{index}"
        command.extend(("--ro-bind", str(library_path), sandbox_path))
        sandbox_libraries.extend((sandbox_path, f"{sandbox_path}/llama"))
    command.extend(
        (
            "--dir",
            "/runtime",
            "--ro-bind",
            str(backend),
            "/runtime/backend",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "PATH",
            "/runtime",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--chdir",
            "/tmp",
            "--uid",
            "65534",
            "--gid",
            "65534",
        )
    )
    if sandbox_libraries:
        command.extend(("--setenv", "LD_LIBRARY_PATH", ":".join(sandbox_libraries)))
    if config.ggml_backend_library is not None:
        resolved_backend = config.ggml_backend_library.resolve(strict=True)
        mapped_backend = None
        for index, library_path in enumerate(resolved_libraries):
            try:
                relative = resolved_backend.relative_to(library_path)
            except ValueError:
                continue
            mapped_backend = str(PurePosixPath(f"/runtime/lib{index}") / relative)
            break
        if mapped_backend is None:
            raise ValueError("GGML backend must be inside a configured library path")
        command.extend(("--setenv", "GGML_BACKEND_PATH", mapped_backend))
    sandbox_model = None
    if config.model_path is not None:
        model = config.model_path.resolve(strict=True)
        sandbox_model = "/runtime/model.gguf"
        command.extend(("--ro-bind", str(model), sandbox_model))
    arguments = tuple(
        value.replace("{model}", sandbox_model or "")
        for value in config.backend_arguments
    )
    command.extend(("--", "/runtime/backend", *arguments))
    return command


def _launch_command(config: LocalRunnerConfig) -> list[str]:
    return [
        str(config.resource_limiter_executable),
        f"--core=0:0",
        f"--cpu={config.cpu_seconds}:{config.cpu_seconds}",
        f"--as={config.memory_limit_bytes}:{config.memory_limit_bytes}",
        f"--fsize={config.max_output_bytes}:{config.max_output_bytes}",
        "--nofile=32:32",
        "--",
        *_sandbox_command(config),
    ]


def _process_tree(root_pid: int) -> set[int]:
    found: set[int] = set()
    pending = [root_pid]
    while pending:
        pid = pending.pop()
        if pid in found or not Path(f"/proc/{pid}").exists():
            continue
        found.add(pid)
        task_root = Path(f"/proc/{pid}/task")
        try:
            task_dirs = tuple(task_root.iterdir())
        except OSError:
            continue
        for task_dir in task_dirs:
            try:
                children = (task_dir / "children").read_text().split()
            except OSError:
                continue
            pending.extend(int(child) for child in children)
    return found


def _rss_bytes(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class LocalSubprocessRunner:
    def __init__(self, config: LocalRunnerConfig) -> None:
        self.config = config

    def availability_error(self) -> str | None:
        if os.name != "posix" or not Path("/proc").is_dir():
            return "LINUX_REQUIRED"
        if os.geteuid() == 0:
            return "REFUSING_ROOT_EXECUTION"
        error = _validate_host_file(self.config.sandbox_executable, executable=True)
        if error:
            return f"SANDBOX_{error}"
        error = _validate_host_file(
            self.config.resource_limiter_executable,
            executable=True,
        )
        if error:
            return f"RESOURCE_LIMITER_{error}"
        error = _validate_host_file(self.config.backend_executable, executable=True)
        if error:
            return f"BACKEND_{error}"
        if self.config.model_path is not None:
            error = _validate_host_file(self.config.model_path, executable=False)
            if error:
                return f"MODEL_{error}"
            try:
                actual_model_sha256 = _file_sha256(self.config.model_path)
            except OSError:
                return "MODEL_HASH_ERROR"
            if actual_model_sha256 != self.config.expected_model_sha256:
                return "MODEL_SHA256_MISMATCH"
        for path in self.config.library_paths:
            error = _validate_host_directory(path)
            if error:
                return f"LIBRARY_{error}"
        if self.config.ggml_backend_library is not None:
            error = _validate_host_file(
                self.config.ggml_backend_library,
                executable=False,
            )
            if error:
                return f"GGML_BACKEND_{error}"
        return None

    def run(self, payload: bytes) -> LocalRunResult:
        input_bytes = len(payload)
        if input_bytes > self.config.max_input_bytes:
            result = _empty_result("INPUT_LIMIT", input_bytes)
            return replace(result, resource_limited=True)
        availability = self.availability_error()
        if availability:
            return _empty_result(availability, input_bytes)
        if not _GLOBAL_REASONER_SLOT.acquire(blocking=False):
            return _empty_result("CONCURRENCY_LIMIT", input_bytes)

        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        output = bytearray()
        stderr = bytearray()
        first_output: float | None = None
        peak_rss = 0
        peak_processes = 0
        error_code: str | None = None
        timed_out = False
        resource_limited = False
        selector = selectors.DefaultSelector()
        try:
            process = subprocess.Popen(
                _launch_command(self.config),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            process.stdin.write(payload)
            process.stdin.close()
            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")

            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if now - started > self.config.timeout_seconds:
                    timed_out = True
                    error_code = "TIMEOUT"
                    _kill_process_group(process)
                    break
                processes = _process_tree(process.pid)
                peak_processes = max(peak_processes, len(processes))
                current_rss = sum(_rss_bytes(pid) for pid in processes)
                peak_rss = max(peak_rss, current_rss)
                if len(processes) > self.config.max_processes:
                    error_code = "PROCESS_LIMIT"
                    resource_limited = True
                    _kill_process_group(process)
                    break
                if current_rss > self.config.memory_limit_bytes:
                    error_code = "MEMORY_LIMIT"
                    resource_limited = True
                    _kill_process_group(process)
                    break

                for key, _ in selector.select(timeout=0.02):
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    if key.data == "stdout":
                        if first_output is None:
                            first_output = time.monotonic()
                        output.extend(chunk)
                        if len(output) > self.config.max_output_bytes:
                            error_code = "OUTPUT_LIMIT"
                            resource_limited = True
                            _kill_process_group(process)
                            break
                    elif len(stderr) < self.config.max_stderr_bytes:
                        remaining = self.config.max_stderr_bytes - len(stderr)
                        stderr.extend(chunk[:remaining])
                if error_code:
                    break

            process.wait(timeout=2)
            if error_code is None and process.returncode != 0:
                if process.returncode in {-signal.SIGXCPU, -signal.SIGKILL}:
                    error_code = "CPU_OR_MEMORY_LIMIT"
                    resource_limited = True
                else:
                    error_code = f"BACKEND_EXIT_{process.returncode}"
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            if isinstance(error, OSError) and error.errno == errno.ENOMEM:
                error_code = "MEMORY_LIMIT"
                resource_limited = True
            else:
                error_code = "LAUNCH_ERROR"
            if process is not None:
                _kill_process_group(process)
        finally:
            selector.close()
            if process is not None:
                _kill_process_group(process)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            _GLOBAL_REASONER_SLOT.release()

        finished = time.monotonic()
        return LocalRunResult(
            output=bytes(output[: self.config.max_output_bytes]),
            stderr=bytes(stderr),
            error_code=error_code,
            timed_out=timed_out,
            resource_limited=resource_limited,
            input_bytes=input_bytes,
            output_bytes=min(len(output), self.config.max_output_bytes),
            elapsed_ms=(finished - started) * 1_000,
            time_to_first_output_ms=(
                None if first_output is None else (first_output - started) * 1_000
            ),
            peak_incremental_rss_bytes=peak_rss,
            peak_processes=peak_processes,
        )
