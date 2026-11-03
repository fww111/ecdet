"""Bounded, persistent Renode firmware execution with UART-only oracles."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, RuleMeta, Severity


RULE_ID = "ECDET-RENODE-ORACLE"


def rule_metas() -> list[RuleMeta]:
    return [RuleMeta(RULE_ID, "ECDET", "Required", "dynamic",
                     "固件仿真触发指定失败判据")]


def find_renode(binary: str | None = None) -> str | None:
    candidate = binary or os.environ.get("ECDET_RENODE") or "renode"
    resolved = shutil.which(candidate)
    if resolved:
        return resolved
    path = Path(candidate)
    return str(path.resolve()) if path.is_file() else None


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _quoted_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if any(c in value for c in '\r\n\t"`'):
        raise ValueError("Paths must not contain quotes or line breaks")
    return '@' + value.replace(' ', '\\ ')


def _text(value: str | bytes | None) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""


@dataclass
class RenodeResult:
    status: str
    reason: str = ""
    execution_mode: str = "renode-simulation"
    binary: str = ""
    version: str = ""
    firmware: str = ""
    firmware_sha256: str = ""
    platform: str = ""
    platform_sha256: str = ""
    source_hashes: dict[str, str] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)
    run_dir: str = ""
    script: str = ""
    stdout_log: str = ""
    stderr_log: str = ""
    uart_log: str = ""
    uart_text: str = ""
    expected: list[str] = field(default_factory=list)
    missing_expected: list[str] = field(default_factory=list)
    observed_failures: list[str] = field(default_factory=list)
    virtual_seconds: float = 0.0
    uart_input_hex: str = ""
    wall_seconds: float = 0.0
    returncode: int | None = None
    completion_token: str = ""
    execution_completed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def alerts(self) -> list[Alert]:
        if self.status != "FAIL" or not self.observed_failures:
            return []
        # Firmware-level events remain independent: no invented source location.
        return [Alert(
            rule_id=RULE_ID, engine="renode", severity=Severity.ERROR,
            message="固件仿真UART触发失败判据：" + marker,
            location=Location(path=Path(self.firmware).name),
            provenance=Provenance.DETECTED,
            evidence=[Evidence(kind="note", message="实际载体：Renode外设仿真"),
                      Evidence(kind="note", message="失败判据来自UART文件：" + self.uart_log,
                               snippet=marker),
                      Evidence(kind="note", message="固件SHA-256：" + self.firmware_sha256),
                      Evidence(kind="note", message="重放脚本：" + self.script)])
            for marker in self.observed_failures]


class RenodeRunner:
    def __init__(self, binary: str | None = None, timeout: float = 30):
        if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        self.binary = binary
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return find_renode(self.binary) is not None

    def run(self, firmware: str | Path, platform: str | Path, output_dir: str | Path,
            *, uart: str = "sysbus.usart2", expected=(), failure_markers=(),
            virtual_seconds: float = 0.1, source_files=(), uart_input: bytes = b"") -> RenodeResult:
        output = Path(output_dir).resolve()
        output.mkdir(parents=True, exist_ok=True)
        result = RenodeResult(status="INVALID_INPUT")
        def finish():
            payload = json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
            (output / "renode_result.json").write_text(payload, encoding="utf-8")
            if result.run_dir:
                (Path(result.run_dir) / "result.json").write_text(payload, encoding="utf-8")
            return result
        try:
            if not isinstance(expected,(list,tuple)) or not isinstance(failure_markers,(list,tuple)):
                raise ValueError("oracle markers must be lists or tuples")
            result.expected = list(expected)
            fw, plat = Path(firmware).resolve(), Path(platform).resolve()
            if not fw.is_file() or fw.read_bytes()[:4] != b"\x7fELF":
                raise ValueError("firmware must be an existing ELF file")
            if not plat.is_file() or plat.suffix.lower() != ".repl":
                raise ValueError("platform must be an existing .repl file")
            if not re.fullmatch(r"sysbus\.[A-Za-z_][A-Za-z0-9_.]*", uart):
                raise ValueError("UART must be a sysbus peripheral identifier")
            if isinstance(virtual_seconds, bool) or not math.isfinite(virtual_seconds) or virtual_seconds <= 0:
                raise ValueError("virtual_seconds must be positive and finite")
            if any(not isinstance(x, str) or not x or '\n' in x or '\r' in x
                   for x in [*expected, *failure_markers]):
                raise ValueError("oracle markers must be nonempty single-line strings")
            if not expected and not failure_markers:
                raise ValueError("at least one expected or failure marker is required")
            if not isinstance(uart_input, bytes) or len(uart_input)>4096:
                raise ValueError("UART input must be bytes of at most 4096 bytes")
            result.firmware, result.platform = str(fw), str(plat)
            result.firmware_sha256, result.platform_sha256 = _hash(fw), _hash(plat)
            result.source_hashes = {str(Path(p).resolve()): _hash(Path(p)) for p in source_files}
            result.virtual_seconds = virtual_seconds
            result.uart_input_hex = uart_input.hex()
            _quoted_path(fw), _quoted_path(plat)
        except (ValueError, OSError, TypeError) as exc:
            result.reason = str(exc)
            return finish()
        executable = find_renode(self.binary)
        if not executable:
            result.status, result.reason = "NOT_AVAILABLE", "Renode executable unavailable"
            return finish()
        result.binary = executable
        run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=output))
        result.run_dir = str(run_dir)
        script, uart_log = run_dir / "run.resc", run_dir / "uart.log"
        result.script, result.uart_log = str(script), str(uart_log)
        result.stdout_log, result.stderr_log = str(run_dir/"stdout.log"), str(run_dir/"stderr.log")
        result.completion_token = "ECDET_RENODE_COMPLETE_" + uuid.uuid4().hex
        script.write_text('\n'.join([
            'mach create "ecdet"',
            'machine LoadPlatformDescription ' + _quoted_path(plat),
            'sysbus LoadELF ' + _quoted_path(fw),
            uart + ' CreateFileBackend ' + _quoted_path(uart_log) + ' true',
            *(['emulation RunFor "0.001"'] if uart_input else []),
            *[uart+' WriteChar '+str(byte) for byte in uart_input],
            'emulation RunFor "' + format(virtual_seconds, '.9f') + '"',
            uart + ' CloseFileBackend ' + _quoted_path(uart_log),
            'echo "' + result.completion_token + '"',
            'quit', '']), encoding="utf-8")
        # --disable-xwt prevents GUI creation; --console is compatible with redirected I/O.
        result.command = [executable, '--disable-xwt', '--console', '--hide-log',
                          '--execute', 'include ' + _quoted_path(script)]
        try:
            version = subprocess.run([executable, '--version'], capture_output=True,
                encoding="utf-8", errors="replace", timeout=min(self.timeout, 10))
            result.version = (version.stdout + version.stderr).strip()[:2000]
        except (OSError, subprocess.TimeoutExpired):
            result.version = "unavailable"
        started = time.perf_counter()
        try:
            process = subprocess.run(result.command, cwd=Path(executable).parent,
                capture_output=True, encoding="utf-8", errors="replace", timeout=self.timeout)
            result.returncode = process.returncode
            stdout, stderr = process.stdout, process.stderr
            result.status = "ERROR" if process.returncode else "PASS"
            if process.returncode:
                result.reason = "Renode exited with an error"
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = _text(exc.stdout), _text(exc.stderr)
            result.status, result.reason = "TIMEOUT", "Renode exceeded wall-clock budget"
        except OSError as exc:
            stdout, stderr = "", str(exc)
            result.status, result.reason = "ERROR", "Renode process could not start"
        result.wall_seconds = round(time.perf_counter()-started, 6)
        Path(result.stdout_log).write_text(stdout, encoding="utf-8")
        Path(result.stderr_log).write_text(stderr, encoding="utf-8")
        result.uart_text = uart_log.read_text(encoding="utf-8", errors="replace") if uart_log.is_file() else ""
        result.missing_expected = [marker for marker in expected if marker not in result.uart_text]
        result.observed_failures = [marker for marker in failure_markers if marker in result.uart_text]
        result.execution_completed = result.completion_token in [line.strip() for line in stdout.splitlines()]
        if result.status == "PASS":
            if not result.execution_completed:
                result.status, result.reason = "ERROR", "Renode script did not reach its completion marker"
            elif not uart_log.is_file():
                result.status, result.reason = "ERROR", "UART backend output was not created"
            elif result.observed_failures:
                result.status, result.reason = "FAIL", "Firmware emitted an explicit failure marker"
            elif result.missing_expected:
                result.status, result.reason = "FAIL", "Expected UART markers not observed"
        try:
            if _hash(fw)!=result.firmware_sha256 or _hash(plat)!=result.platform_sha256:
                result.status, result.reason = "ERROR", "Firmware or platform changed during execution"
        except OSError:
            result.status, result.reason = "ERROR", "Firmware or platform disappeared during execution"
        return finish()
