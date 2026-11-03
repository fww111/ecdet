"""Bounded libFuzzer execution with persistent corpus and replayed evidence.

The caller supplies a C LLVMFuzzerTestOneInput harness. This adapter compiles
the harness and explicitly named sources, never guesses hardware stubs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, RuleMeta, Severity


LIBFUZZER_RULE = RuleMeta("ECDET-FUZZ-CRASH", "Dynamic", "Required", "dynamic",
                         "libFuzzer输入重放触发错误", ["CWE-119"])
_SIGNAL = re.compile(r"AddressSanitizer:|UndefinedBehaviorSanitizer:|runtime error:|ERROR: libFuzzer:")
_COVERAGE = re.compile(r"#(\d+)\s+\w+.*?cov:\s*(\d+)\s+ft:\s*(\d+)")


def generate_byte_harness(function: str, return_type: str = 'int') -> str:
    """Generate an entrypoint for an explicitly selected byte-buffer API.

    The target contract is int/void function(const uint8_t *, size_t).
    Arbitrary pointer-rich or hardware APIs require their own harness.
    """
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', function or ''):
        raise ValueError('Target must be a C identifier')
    if return_type not in {'int', 'void'}:
        raise ValueError('Target return type must be int or void')
    return ('#include <stddef.h>\n#include <stdint.h>\n'
            f'extern {return_type} {function}(const uint8_t *, size_t);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)\n{\n'
            f'    (void){function}(data, size);\n    return 0;\n}}\n')


def discover_clang(explicit: str | None = None) -> str | None:
    """An explicit or environment compiler always wins over PATH discovery."""
    candidate = explicit or os.environ.get("ECDET_CLANG") or shutil.which("clang")
    if not candidate:
        return None
    located = shutil.which(candidate)
    if located:
        return str(Path(located).resolve())
    path = Path(candidate).expanduser()
    return str(path.resolve()) if path.is_file() else None


def parse_coverage(log: str) -> dict:
    snapshots = [{"runs": int(m[1]), "edges": int(m[2]), "features": int(m[3])}
                 for m in _COVERAGE.finditer(log)]
    executed = re.findall(r"stat::number_of_executed_units:\s*(\d+)", log)
    return {"snapshots": snapshots,
            "initial_edges": snapshots[0]["edges"] if snapshots else None,
            "final_edges": snapshots[-1]["edges"] if snapshots else None,
            "executed_units": int(executed[-1]) if executed else
                              snapshots[-1]["runs"] if snapshots else None,
            "kind": "libFuzzer SanitizerCoverage edges/features"}


@dataclass
class FuzzResult:
    status: str
    reason: str = ""
    alerts: list[Alert] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    receipt_path: str = ""

    def to_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason,
                "alerts": [a.to_dict() for a in self.alerts],
                "metadata": self.metadata, "receipt_path": self.receipt_path}


class LibFuzzerEngine:
    def __init__(self, clang: str | None = None, runs: int = 5000,
                 timeout: int = 30, max_len: int = 4096):
        for name, value in (("runs", runs), ("timeout", timeout), ("max_len", max_len)):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.clang = clang
        self.runs = runs
        self.timeout = timeout
        self.max_len = max_len

    def run(self, root: Path, harness: Path, output_dir: Path,
            sources: list[Path] | None = None, corpus: list[Path] | None = None) -> FuzzResult:
        root = Path(root).resolve()
        output = Path(output_dir).resolve()
        output.mkdir(parents=True, exist_ok=True)
        run_dir = output / "runs" / uuid.uuid4().hex
        run_dir.mkdir(parents=True)
        result = FuzzResult("ERROR", receipt_path=str(run_dir / "receipt.json"))
        meta = result.metadata
        meta.update(mode="host-libfuzzer", runs_budget=self.runs,
                    wall_seconds_budget=self.timeout, max_len=self.max_len,
                    run_directory=str(run_dir), root=str(root))

        def finish(status: str, reason: str = "") -> FuzzResult:
            result.status, result.reason = status, reason
            Path(result.receipt_path).write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
                                                 encoding="utf-8")
            (output / "latest.json").write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
                                               encoding="utf-8")
            return result

        try:
            selected = []
            for source in [harness, *(sources or [])]:
                source = Path(source)
                path = (root/source).resolve() if not source.is_absolute() else source.resolve()
                path.relative_to(root)
                if not path.is_file() or path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                    raise ValueError("Every source must be an existing C/C++ file inside the project")
                if path not in selected:
                    selected.append(path)
            if "LLVMFuzzerTestOneInput" not in selected[0].read_text(encoding="utf-8"):
                raise ValueError("Harness must define LLVMFuzzerTestOneInput")
        except (ValueError, OSError, UnicodeError) as exc:
            return finish("INVALID_INPUT", str(exc))
        meta["sources"] = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in selected}
        compiler = discover_clang(self.clang)
        if not compiler:
            return finish("UNAVAILABLE", "Clang not found; set ECDET_CLANG or --clang")
        meta["compiler"] = compiler
        env = dict(os.environ)
        env["PATH"] = str(Path(compiler).parent) + os.pathsep + env.get("PATH", "")
        env["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1:abort_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        symbolizer = Path(compiler).parent / ("llvm-symbolizer.exe" if os.name == "nt" else "llvm-symbolizer")
        if symbolizer.is_file():
            env["ASAN_SYMBOLIZER_PATH"] = str(symbolizer)
        exe = run_dir / ("fuzz_target.exe" if os.name == "nt" else "fuzz_target")
        try:
            version = subprocess.run([compiler, "--version"], capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=10, env=env)
            meta["compiler_version"] = version.stdout.strip()
            target = subprocess.run([compiler, '-dumpmachine'], capture_output=True, text=True,
                                    timeout=10, encoding='utf-8', errors='replace', env=env)
            meta['compiler_target'] = target.stdout.strip()
            instrumentation = ['-fsanitize=fuzzer,address,undefined']
            libraries = []
            if 'windows-gnu' in target.stdout:
                # LLVM's GNU Windows driver rejects -fsanitize=fuzzer even when
                # compiler-rt ships libFuzzer. Link that runtime explicitly,
                # retaining the same coverage instrumentation and sanitizers.
                resource = subprocess.run([compiler, '-print-resource-dir'], capture_output=True,
                                          text=True, timeout=10, encoding='utf-8', env=env)
                arch = target.stdout.strip().split('-')[0]
                runtime = Path(resource.stdout.strip()) / 'lib/windows' / f'libclang_rt.fuzzer-{arch}.a'
                if not runtime.is_file():
                    return finish('COMPILE_ERROR', 'GNU Windows libFuzzer runtime unavailable')
                instrumentation = ['-fsanitize=address,undefined',
                    '-fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp']
                libraries = [str(runtime), '-lc++']
                meta['fuzzer_link_mode'] = 'compiler-rt-static-runtime'
                meta['fuzzer_runtime_sha256'] = hashlib.sha256(runtime.read_bytes()).hexdigest()
            else:
                meta['fuzzer_link_mode'] = 'clang-sanitize-fuzzer'
            command = [compiler, '-std=c11', '-g', '-O1', '-fno-omit-frame-pointer',
                       *instrumentation, '-fno-sanitize-recover=all', '-I', str(root),
                       *map(str, selected), *libraries, '-o', str(exe)]
            meta['compile_command'] = command
            build = subprocess.run(command, capture_output=True, text=True, timeout=60,
                                   encoding="utf-8", errors="replace", env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return finish("COMPILE_ERROR", type(exc).__name__)
        (run_dir / "compile.log").write_text(build.stdout + build.stderr, encoding="utf-8")
        meta["compile_returncode"] = build.returncode
        if build.returncode != 0 or not exe.is_file():
            return finish("COMPILE_ERROR", "Compiler failed; see compile.log")
        meta["executable_sha256"] = hashlib.sha256(exe.read_bytes()).hexdigest()
        corpus_dir = output / "corpus"
        corpus_dir.mkdir(exist_ok=True)
        artifacts = run_dir / "artifacts"
        artifacts.mkdir()
        try:
            for seed in corpus or []:
                seed = Path(seed)
                seed = (root / seed).resolve() if not seed.is_absolute() else seed.resolve()
                if not seed.exists():
                    raise ValueError('Corpus path must exist')
                paths = [seed] if seed.is_file() else sorted(p for p in seed.rglob('*') if p.is_file())
                for path in paths:
                    data = path.read_bytes()
                    if len(data) > self.max_len:
                        raise ValueError('Corpus seed exceeds max_len')
                    (corpus_dir / hashlib.sha256(data).hexdigest()).write_bytes(data)
        except (OSError, ValueError) as exc:
            return finish("INVALID_INPUT", str(exc))
        if not any(corpus_dir.iterdir()):
            (corpus_dir / "initial").write_bytes(b"\x00")
        command = [str(exe), str(corpus_dir), f"-runs={self.runs}",
                   f"-max_total_time={self.timeout}", f"-timeout={min(5, self.timeout)}",
                   f"-max_len={self.max_len}", "-seed=1", "-print_final_stats=1",
                   f"-artifact_prefix={artifacts}{os.sep}"]
        meta["run_command"] = command
        started = time.perf_counter()
        try:
            execution = subprocess.run(command, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=self.timeout + 5, env=env)
            log = execution.stdout + execution.stderr
            meta["returncode"] = execution.returncode
        except subprocess.TimeoutExpired as exc:
            chunks = [exc.stdout or "", exc.stderr or ""]
            log = "".join(x.decode("utf-8", errors="replace") if isinstance(x, bytes) else x for x in chunks)
            (run_dir / "fuzz.log").write_text(log, encoding="utf-8")
            meta["elapsed_seconds"] = round(time.perf_counter()-started, 3)
            meta["coverage"] = parse_coverage(log)
            return finish("TIMEOUT", "Host wall timeout; no finding accepted without replay")
        except OSError as exc:
            return finish("ERROR", type(exc).__name__)
        meta["elapsed_seconds"] = round(time.perf_counter()-started, 3)
        (run_dir / "fuzz.log").write_text(log, encoding="utf-8")
        coverage = meta["coverage"] = parse_coverage(log)
        (run_dir / "coverage.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
        meta["corpus"] = [{"name": p.name, "bytes": p.stat().st_size,
                            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                           for p in sorted(corpus_dir.iterdir()) if p.is_file()]
        meta["replays"] = []
        for artifact in sorted(artifacts.glob("*")):
            if not artifact.is_file():
                continue
            replay_cmd = [str(exe), str(artifact), "-runs=1", f"-timeout={min(5, self.timeout)}"]
            item = {"input": str(artifact), "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "command": replay_cmd, "status": "UNVERIFIED"}
            meta["replays"].append(item)
            try:
                replay = subprocess.run(replay_cmd, capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace", env=env)
            except (OSError, subprocess.TimeoutExpired) as exc:
                item["reason"] = type(exc).__name__
                continue
            replay_log = replay.stdout + replay.stderr
            replay_path = run_dir / (artifact.name + ".replay.log")
            replay_path.write_text(replay_log, encoding="utf-8")
            item.update(returncode=replay.returncode, log=str(replay_path))
            if replay.returncode == 0 or not _SIGNAL.search(replay_log):
                item["reason"] = "Replay lacks a nonzero sanitizer/libFuzzer failure"
                continue
            item["status"] = "REPRODUCED"
            exact_location = _source_location(replay_log, root, selected[0])
            location = exact_location or Location(selected[0].relative_to(root).as_posix(), 1)
            detail = next((line.strip() for line in replay_log.splitlines() if _SIGNAL.search(line)), "")[:300]
            result.alerts.append(Alert(
                rule_id=LIBFUZZER_RULE.rule_id, engine="libfuzzer", severity=Severity.ERROR,
                message=f"libFuzzer保存输入并重放触发错误：{detail}", location=location,
                provenance=Provenance.DETECTED,
                evidence=[Evidence(kind="note", message=f"实际载体：host-libfuzzer；输入SHA256：{item['sha256']}"),
                          Evidence(kind='note', message=('位置来源：工具栈帧' if exact_location else
                              '精确源码位置不可用；报告位置为驱动入口，不能据此关联静态告警。')),
                          Evidence(kind="note", message=f"重放输入：{artifact}"),
                          Evidence(kind="note", message=f"重放日志：{replay_path}"),
                          Evidence(kind="note", message="仅确认此编译版本与该输入下的执行错误；静态告警保持独立。")]))
        if result.alerts:
            return finish("FINDING", "Saved input reproduced the execution failure")
        if execution.returncode != 0:
            return finish("UNVERIFIED", "Execution failed without a reproducible artifact")
        if coverage["executed_units"] is None or not coverage["snapshots"]:
            return finish("UNVERIFIED", "No libFuzzer execution/coverage receipt")
        return finish("COMPLETED", "Budget completed; no failure reproduced in this run")


def _source_location(log: str, root: Path, harness: Path) -> Location | None:
    # Match known project paths only; third-party runtime frames are not targets.
    paths = list(sorted(root.rglob('*.c')))
    for line in log.splitlines():
        for path in paths:
            for spelling in {str(path), path.as_posix()}:
                match = re.search(re.escape(spelling) + r':(\d+)(?::(\d+))?', line)
                if match and int(match[1]) > 0:
                    return Location(path.relative_to(root).as_posix(), int(match[1]), int(match[2] or 1))
    return None
