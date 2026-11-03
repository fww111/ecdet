"""CodeChecker 核心静态分析接入。

CodeChecker 从 compile_commands.json 执行其可用的 C/C++ 分析器，随后将
``CodeChecker parse --export json`` 的结果映射到 ecdet 的统一告警模型。
CodeChecker Python 包是项目依赖；Clang/Clang-Tidy、GCC 13+ 或 Cppcheck
等至少一个受支持的系统分析器必须可用。
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from ecdet.l2_ir.model import Alert, Evidence, Location, Severity
from ecdet.l3_analysis.engine import AnalysisTarget

_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++"}
_SEVERITY_MAP = {
    "CRITICAL": Severity.ERROR,
    "HIGH": Severity.ERROR,
    "MEDIUM": Severity.WARNING,
    "LOW": Severity.NOTE,
    "ERROR": Severity.ERROR,
    "WARNING": Severity.WARNING,
    "NOTE": Severity.NOTE,
    "STYLE": Severity.NOTE,
}


def _analyzer_environment() -> dict[str, str]:
    """Find installed Windows analyzers even in a process with a stale PATH."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    # Python 3.11 can decode an editable .pth with the Windows locale even
    # when its Unicode source path was written as UTF-8. Native jobs change
    # cwd, so pass the already-loaded package root explicitly to children.
    package_root = str(Path(__file__).resolve().parents[3])
    python_paths = [p for p in env.get('PYTHONPATH', '').split(os.pathsep) if p]
    env['PYTHONPATH'] = os.pathsep.join([package_root, *[p for p in python_paths if p != package_root]])
    if os.name != "nt":
        return env
    candidates: list[Path] = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    program_files = os.environ.get("ProgramFiles")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Programs" / "CppcheckPortable")
        candidates.append(Path(local_app_data) / "Programs" / "ArmGccMSYS-13.3" /
                          "mingw64" / "bin")
    if program_files:
        candidates.extend((Path(program_files) / "Cppcheck",
                           Path(program_files) / "LLVM" / "bin"))
    found = [str(path) for path in candidates if path.is_dir()]
    if found:
        env["PATH"] = os.pathsep.join([*found, env.get("PATH", "")])
    overrides = env.get("CC_ANALYZER_BIN", "")
    if not any(value.startswith("clangsa:") for value in overrides.split(";")):
        clang = _which("clang", env)
        if clang:
            driver = _clangsa_driver(clang)
            if driver != clang:
                env["CC_ANALYZER_BIN"] = ";".join(
                    value for value in (overrides, f"clangsa:{driver}") if value)
    return env


def _which(binary: str, env: dict[str, str]) -> str | None:
    return shutil.which(binary, path=env.get("PATH"))


@lru_cache(maxsize=8)
def _clangsa_driver(binary: str) -> str:
    """LLVM-MinGW wrappers reject CodeChecker's direct cc1 checker query."""
    directory = Path(binary).parent
    candidates = [path for path in directory.glob("clang-*.exe")
                  if re.fullmatch(r"clang-\d+\.exe", path.name)]
    if not candidates:
        return binary
    try:
        help_result = subprocess.run(
            [binary, "-cc1", "-analyzer-checker-help"], capture_output=True,
            text=True, timeout=10, encoding="utf-8", errors="replace")
        if help_result.returncode == 0 and "CHECKERS:" in help_result.stdout:
            return binary
        version = subprocess.run([binary, "--version"], capture_output=True,
                                 text=True, timeout=10, encoding="utf-8",
                                 errors="replace")
        major = re.search(r"clang version (\d+)\.", version.stdout)
        if major:
            candidate = directory / f"clang-{major.group(1)}.exe"
            if candidate in candidates:
                checkers = subprocess.run(
                    [str(candidate), "-cc1", "-analyzer-checker-help"],
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace")
                if checkers.returncode == 0 and "CHECKERS:" in checkers.stdout:
                    return str(candidate)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return binary


def _find_ccdb(root: Path) -> Path | None:
    candidates = (
        root / "compile_commands.json",
        root / "build" / "compile_commands.json",
        root / "ecdet_build" / "cmake" / "compile_commands.json",
        root / "ecdet_build" / "compile_commands.json",
    )
    return next((p for p in candidates if p.is_file()), None)


def _complete_synthetic_ccdb(root: Path, ccdb: Path, output: Path) -> Path:
    """Repair older ecdet source-scan commands without modifying real builds."""
    if ccdb.parent != root / "ecdet_build":
        return ccdb
    entries = json.loads(ccdb.read_text(encoding="utf-8"))
    from ecdet.l3_analysis.engine import collect_sources

    includes = sorted({str((root / path.parent).resolve()) for path in collect_sources(root)
                       if path.suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}})
    changed = False
    for entry in entries if isinstance(entries, list) else []:
        args = entry.get("arguments") or []
        if len(args) < 2 or args[0] not in {"clang", "clang++"} or \
                args[1] != "--target=arm-none-eabi" or entry.get("output") != "":
            continue
        args = list(args)
        for directory in includes:
            if not any(str(arg).replace('\\', '/') == ("-I" + directory).replace('\\', '/')
                       for arg in args):
                args.extend(("-I", directory))
                changed = True
        entry["arguments"] = args
    if changed:
        output.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
        return output
    return ccdb


def _path_key(path: Path) -> str:
    """Normalize path identity using the host OS's case-sensitivity rules."""
    try:
        return os.path.normcase(str(path.resolve()))
    except OSError:
        return os.path.normcase(str(path.absolute()))


def _selected_translation_units(target: AnalysisTarget, ccdb: Path) -> tuple[list[str], bool]:
    """Return target source paths and whether they cover the whole database."""
    try:
        entries = json.loads(ccdb.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], False

    project_sources: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("file")
        if not raw or Path(raw).suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        source = Path(raw)
        if not source.is_absolute():
            source = Path(entry.get("directory") or target.root) / source
        project_sources.add(_path_key(source))

    selected: set[str] = set()
    for rel in target.files:
        if rel.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        selected.add(_path_key(target.root / rel))

    matching = sorted(project_sources & selected)
    if not matching:
        return [], False
    # CodeChecker's --file filter keeps incremental scans aligned with ecdet's
    # impact set. Passing no filter for a full scan avoids unnecessary CLI args.
    return matching, selected >= project_sources


def _project_relative_path(raw: str, root: Path) -> str | None:
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return None


@lru_cache(maxsize=None)
def _compiler_works(binary: str | None) -> bool:
    if not binary:
        return False
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True,
                              timeout=10, check=False)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@lru_cache(maxsize=None)
def _c_standard_headers_work(binary: str | None) -> bool:
    if not _compiler_works(binary):
        return False
    try:
        proc = subprocess.run(
            [binary, "-x", "c", "-fsyntax-only", "-"],
            input="#include <stdio.h>\n", capture_output=True, text=True,
            timeout=10, check=False, encoding="utf-8", errors="replace",
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@lru_cache(maxsize=None)
def _cxx_standard_headers_work(binary: str | None) -> bool:
    if not _compiler_works(binary):
        return False
    try:
        proc = subprocess.run(
            [binary, "-x", "c++", "-fsyntax-only", "-"],
            input="#include <vector>\n", capture_output=True, text=True,
            timeout=10, check=False, encoding="utf-8", errors="replace",
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _write_fallback_ccdb(target: AnalysisTarget, out_path: Path,
                         analyzers: list[str], env: dict[str, str]) -> Path:
    """Create a minimal compile database for --no-build source-only scans."""
    prefer_clang = bool({"clangsa", "clang-tidy"} & set(analyzers))
    c_compiler = None
    cxx_compiler = None
    if prefer_clang:
        clang = _which("clang", env)
        clangxx = _which("clang++", env)
        if _compiler_works(clang):
            c_compiler = clang
            cxx_compiler = clangxx if _compiler_works(clangxx) else clang
    if c_compiler is None and "gcc" in analyzers:
        gcc = _which("gcc", env)
        gxx = _which("g++", env)
        if _compiler_works(gcc):
            c_compiler = gcc
            cxx_compiler = gxx if _compiler_works(gxx) else gcc
    if c_compiler is None:
        raise RuntimeError(
            "CodeChecker 扫描需要 Clang 或 GCC 13+。请安装支持的 C/C++ 分析器，"
            "并将其加入 PATH。"
        )
    arm_source_only = bool(target.svd_path and
                           Path(c_compiler).stem.lower().startswith("clang"))
    if not arm_source_only and not _cxx_standard_headers_work(cxx_compiler):
        gxx = _which("g++", env)
        if _cxx_standard_headers_work(gxx):
            cxx_compiler = gxx
    if not arm_source_only and not _c_standard_headers_work(c_compiler):
        gcc = _which("gcc", env)
        if _c_standard_headers_work(gcc):
            c_compiler = gcc
    from ecdet.l3_analysis.engine import collect_sources

    # Incremental analysis still needs all project TUs for the CTU collect
    # phase. The runner applies the requested-file filter only afterwards.
    project_files = collect_sources(target.root)
    sources = [p for p in project_files if p.suffix.lower() in _SOURCE_SUFFIXES]
    if not sources:
        raise RuntimeError("CodeChecker 没有可分析的 C/C++ 翻译单元。")
    if any(p.suffix.lower() in {".cc", ".cpp", ".cxx", ".c++"}
           for p in sources) and cxx_compiler != c_compiler:
        print(f"[L3] CodeChecker 源码直扫使用 C++ 编译器：{cxx_compiler}")
    include_dirs = {target.root.resolve()}
    include_dirs.update((target.root / p.parent).resolve() for p in project_files)
    entries = []
    for rel in sources:
        src = (target.root / rel).resolve()
        compiler = (cxx_compiler if src.suffix.lower() in
                    {".cc", ".cpp", ".cxx", ".c++"} else c_compiler)
        args = [compiler, "-I", str(target.root.resolve())]
        if arm_source_only:
            args.append("--target=arm-none-eabi")
        for include_dir in sorted(include_dirs):
            if include_dir != target.root.resolve():
                args += ["-I", str(include_dir)]
        args += ["-c", str(src)]
        entries.append({"directory": str(target.root.resolve()),
                        "file": str(src), "arguments": args})
    out_path.write_text(json.dumps(entries, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    return out_path


def _gcc_compatible_ccdb(ccdb: Path, out_path: Path,
                         analyzers: list[str], env: dict[str, str]) -> Path:
    """Adapt ecdet's synthetic Clang commands when GCC is the only analyzer.

    CodeChecker's GCC analyzer invokes its detected GCC binary, so an unavailable
    Clang driver and Clang-only target flag in a synthetic compile command must
    not block the analysis. Project include and define flags are retained.
    """
    if "gcc" not in analyzers or {"clangsa", "clang-tidy"} & set(analyzers):
        return ccdb
    gcc, gxx = _which("gcc", env), _which("g++", env)
    try:
        entries = json.loads(ccdb.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"读取 CodeChecker 编译数据库失败：{exc}") from exc
    if not isinstance(entries, list):
        raise RuntimeError(f"CodeChecker 编译数据库格式错误：{ccdb}")

    changed = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw_args = entry.get("arguments")
        if isinstance(raw_args, list):
            args = [str(arg) for arg in raw_args]
        elif entry.get("command"):
            args = shlex.split(str(entry["command"]), posix=os.name != "nt")
        else:
            continue
        if not args or not Path(args[0].strip('"')).name.lower().startswith("clang"):
            continue

        is_cxx = Path(str(entry.get("file", ""))).suffix.lower() in {
            ".cc", ".cpp", ".cxx", ".c++"
        }
        replacement = gxx if is_cxx and _compiler_works(gxx) else gcc
        if not _compiler_works(replacement):
            raise RuntimeError(
                "CodeChecker 仅检测到 GCC 分析器，但编译数据库使用 Clang，"
                "且本机找不到可运行的 GCC/G++。"
            )
        normalized = [replacement]
        i = 1
        while i < len(args):
            arg = args[i]
            if arg.startswith("--target="):
                i += 1
                continue
            if arg in ("--target", "-target"):
                i += 2
                continue
            normalized.append(arg)
            i += 1
        entry["arguments"] = normalized
        entry.pop("command", None)
        changed = True

    if not changed:
        return ccdb
    out_path.write_text(json.dumps(entries, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print("[L3] CodeChecker 使用 GCC 分析器兼容副本；临时数据库已将不可用的 "
          "Clang 命令转换为本机 GCC，ARM target 参数已移除。当前结果是主机侧 "
          "C/C++ 诊断，不能替代目标架构分析；请安装可用的 Clang/交叉工具链。")
    return out_path


def _has_cross_target(ccdb: Path) -> bool:
    """Detect compiler commands that a native GCC analyzer cannot reproduce."""
    try:
        entries = json.loads(ccdb.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        raw_args = entry.get("arguments")
        if isinstance(raw_args, list):
            args = [str(arg) for arg in raw_args]
        elif entry.get("command"):
            args = shlex.split(str(entry["command"]), posix=os.name != "nt")
        else:
            continue
        if any(arg in ("--target", "-target", "-mthumb") or
               arg.startswith(("--target=", "-target=", "-mcpu=", "-mfpu="))
               for arg in args):
            return True
        compiler = Path(args[0].strip('"')).name.lower() if args else ""
        if compiler.startswith(("arm-none-eabi-", "aarch64-none-elf-")):
            return True
    return False


def _arm_sysroot_ccdb(ccdb: Path, out_path: Path,
                      env: dict[str, str]) -> Path:
    """Provide Newlib headers to synthetic Clang ARM commands when available."""
    cross_gcc = _which("arm-none-eabi-gcc", env)
    if not cross_gcc:
        return ccdb
    sysroot = Path(cross_gcc).resolve().parent.parent / "arm-none-eabi"
    if (sysroot / "include" / "stdio.h").is_file():
        include_root = sysroot / "include"
        base_args = [f"--sysroot={sysroot}"]
    elif (Path("/usr/include/newlib") / "stdio.h").is_file():
        # Debian packages Newlib headers outside the cross compiler sysroot.
        include_root = Path("/usr/include/newlib")
        base_args = ["-isystem", str(include_root)]
    else:
        return ccdb
    try:
        gcc_version = subprocess.run(
            [cross_gcc, "-dumpfullversion"], capture_output=True, text=True,
            timeout=10, env=env, encoding="utf-8", errors="replace",
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        gcc_version = ""
    cxx_root = include_root / "c++" / gcc_version
    try:
        entries = json.loads(ccdb.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"读取 CodeChecker 编译数据库失败：{exc}") from exc
    if not isinstance(entries, list):
        raise RuntimeError(f"CodeChecker 编译数据库格式错误：{ccdb}")

    changed = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw_args = entry.get("arguments")
        if isinstance(raw_args, list):
            args = [str(arg) for arg in raw_args]
        elif entry.get("command"):
            args = shlex.split(str(entry["command"]), posix=os.name != "nt")
        else:
            continue
        if not args or not Path(args[0].strip('"')).name.lower().startswith("clang"):
            continue
        target_arm = any(arg.startswith(("--target=arm-none-eabi",
                                         "-target=arm-none-eabi"))
                         for arg in args)
        target_arm |= any(args[i] in ("--target", "-target") and
                          args[i + 1] == "arm-none-eabi"
                          for i in range(len(args) - 1))
        if not target_arm or any(arg in ("--sysroot", "-isysroot") or
                                 arg.startswith(("--sysroot=", "-isysroot="))
                                 for arg in args):
            continue
        extra = list(base_args)
        if Path(str(entry.get("file", ""))).suffix.lower() in {
            ".cc", ".cpp", ".cxx", ".c++"
        } and cxx_root.is_dir():
            for include_dir in (cxx_root, cxx_root / "arm-none-eabi",
                                cxx_root / "backward"):
                if include_dir.is_dir():
                    extra.extend(("-isystem", str(include_dir)))
        entry["arguments"] = [args[0], *extra, *args[1:]]
        entry.pop("command", None)
        changed = True
    if not changed:
        return ccdb
    out_path.write_text(json.dumps(entries, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"[L3] CodeChecker 为 ARM Clang 编译命令补充 Newlib 头文件：{include_root}")
    return out_path


def parse_codechecker_json(text: str, project_root: str | Path,
                           catalog: dict | None = None) -> list[Alert]:
    """Convert CodeChecker's documented parse JSON report objects to Alerts."""
    try:
        data = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("CodeChecker 报告不是有效的 JSON。") from exc
    if not isinstance(data, dict) or not isinstance(data.get("reports"), list):
        raise RuntimeError("CodeChecker JSON 缺少 reports 数组。")
    root = Path(project_root)
    checker_map = {item["name"]: item for item in (catalog or {}).get("checkers", [])}
    alerts: list[Alert] = []
    for report in data.get("reports", []) if isinstance(data, dict) else []:
        if not isinstance(report, dict):
            continue
        if report.get("review_status") in {"suppress", "false_positive", "intentional"}:
            continue
        file_info = report.get("file") or {}
        raw_path = (file_info.get("original_path") or file_info.get("id")
                    or file_info.get("path") or "")
        rel_path = _project_relative_path(raw_path, root)
        if rel_path is None:
            continue

        checker = str(report.get("checker_name") or report.get("type") or "unknown")
        analyzer = str(report.get("analyzer_name") or "CodeChecker")
        severity_name = str(report.get("severity") or "MEDIUM").upper()
        try:
            line = max(1, int(report.get("line") or 1))
            col = max(1, int(report.get("column") or 1))
        except (TypeError, ValueError):
            line, col = 1, 1
        message = str(report.get("message") or checker)
        evidence = [Evidence(kind="api", message=f"CodeChecker {analyzer}: {checker}")]

        events = [("code", e) for e in report.get("bug_path_events") or []]
        events += [("note", e) for e in report.get("notes") or []]
        events += [("macro", e) for e in report.get("macro_expansions") or []]
        for kind, event in events:
            if not isinstance(event, dict):
                continue
            event_file = event.get("file") or {}
            event_path = (event_file.get("original_path") or event_file.get("id")
                          or event_file.get("path") or "")
            event_rel = _project_relative_path(event_path, root) if event_path else None
            event_line = event.get("line") or (event.get("range") or {}).get("start_line")
            try:
                region = event.get("range") or {}
                event_location = (Location(path=event_rel, line=max(1, int(event_line)),
                                           col=max(1, int(event.get("column") or
                                                          region.get("start_col") or 1)),
                                           end_line=region.get("end_line"),
                                           end_col=region.get("end_col"))
                                  if event_rel and event_line else None)
            except (TypeError, ValueError):
                event_location = None
            event_message = str(event.get("message") or "分析路径步骤")
            evidence.append(Evidence(kind=kind, message=event_message,
                                     location=event_location))

        from ecdet.l3_analysis.codechecker_catalog import checker_cwes
        checker_meta = checker_map.get(checker, {})
        cwes = checker_cwes(checker_meta)
        alerts.append(Alert(
            rule_id=checker,
            engine="codechecker",
            severity=_SEVERITY_MAP.get(severity_name, Severity.WARNING),
            message=message,
            location=Location(path=rel_path, line=line, col=col),
            evidence=evidence,
            fingerprint=str(report.get("report_hash") or ""),
            cwe=cwes[0] if len(cwes) == 1 else None,
            properties={"codechecker": {
                key: report.get(key) for key in (
                    "analyzer_name", "report_hash", "severity", "category", "type",
                    "review_status", "source_code_comments", "bug_path_positions",
                    "macro_expansions", "annotations", "analyzer_result_file_path")
            }, "cwes": cwes, "labels": checker_meta.get("labels", [])},
        ))
    return alerts



def run_codechecker(target: AnalysisTarget, binary: str = "CodeChecker",
                    timeout: int = 600, on_manifest=None) -> list[Alert]:
    from ecdet.l3_analysis.codechecker_runner import run

    return run(target, binary, timeout, on_manifest=on_manifest)
