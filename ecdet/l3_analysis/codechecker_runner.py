"""Persistent CodeChecker analysis: CTU, taint, native reports and comparison."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ecdet.l2_ir.model import Alert
from ecdet.l3_analysis.codechecker_catalog import CORE_PROFILES, command, load_catalog


def _filesystem_path(path: Path) -> Path:
    if os.name != "nt":
        return path
    raw = str(path.resolve())
    if raw.startswith("\\\\?\\"):
        return Path(raw)
    return Path("\\\\?\\UNC\\" + raw[2:] if raw.startswith("\\\\")
                else "\\\\?\\" + raw)


def _write_json(path: Path, data: dict) -> None:
    # Resolve junctions for atomic renames and preserve extended-length paths.
    path = _filesystem_path(path)
    pending = path.with_suffix(path.suffix + ".tmp")
    pending.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    pending.replace(path)


def _ascii_alias(root: Path) -> Path:
    if os.name != "nt" or (str(root).isascii() and len(str(root)) <= 80):
        return root
    import _winapi

    _filesystem_path(root).mkdir(parents=True, exist_ok=True)
    base = Path(os.environ["LOCALAPPDATA"]) / "ecdet" / "source-links"
    base.mkdir(parents=True, exist_ok=True)
    alias = base / hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:20]
    if not alias.exists():
        _winapi.CreateJunction(str(root), str(alias))
    if alias.resolve() != root.resolve():
        raise RuntimeError(f"CodeChecker 源码路径映射指向了其他目录：{alias}")
    if not str(alias).isascii():
        raise RuntimeError("LLVM Windows CTU 映射工具需要 ASCII 路径，当前用户目录不满足要求。")
    return alias


def _source_alias(root: Path, env: dict[str, str]) -> None:
    alias = _ascii_alias(root)
    env["ECODET_CODECHECKER_SOURCE_ROOT"] = str(root)
    env["ECODET_CODECHECKER_SOURCE_ALIAS"] = str(alias)


def _project_config(root: Path) -> tuple[dict, Path | None]:
    explicit = os.environ.get("ECODET_CODECHECKER_CONFIG")
    path = Path(explicit) if explicit else root / ".ecdet" / "codechecker.json"
    if explicit and not path.is_absolute():
        path = root / path
    if not path.is_file():
        if explicit:
            raise RuntimeError(f"CodeChecker 配置文件不存在：{path}")
        return {}, None
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"CodeChecker 配置读取失败：{path}: {exc}") from exc
    if not isinstance(config, dict):
        raise RuntimeError(f"CodeChecker 配置应为 JSON 对象：{path}")
    for phase in ("analyze", "parse"):
        values = config.get(phase, [])
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise RuntimeError(f"CodeChecker 配置 {phase} 必须是参数字符串数组。")
        owned = {"-o", "--output", "--makefile", "--ctu", "--ctu-all",
                 "--ctu-collect", "--ctu-analyze"}
        if any(value.split("=", 1)[0] in owned for value in values):
            raise RuntimeError("CodeChecker 的输入、输出及 CTU 阶段由 ecdet 管理，"
                               "项目配置不能覆盖这些参数。")
    return config, path


def run(target, binary: str, timeout: int, on_manifest=None) -> list[Alert]:
    from ecdet.l3_analysis.adapters.codechecker import (
        _analyzer_environment, _arm_sysroot_ccdb, _find_ccdb,
        _gcc_compatible_ccdb, _has_cross_target, _selected_translation_units,
        _write_fallback_ccdb, _complete_synthetic_ccdb, parse_codechecker_json,
    )
    from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES

    root = target.root.resolve()
    base = _ascii_alias((target.artifact_dir or root / "ecdet_reports" / "codechecker").resolve())
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    work = base / "runs" / run_id
    work.mkdir(parents=True, exist_ok=False)
    previous_path = base / "latest-full.json"
    try:
        previous = json.loads(previous_path.read_text(encoding="utf-8")) if previous_path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        previous = {}
    manifest = {"schema_version": 1, "run_id": run_id, "run_dir": str(work),
                "project_root": str(root), "status": "running", "phases": [],
                "started_at": datetime.now(timezone.utc).isoformat(),
                "hash_mode": "context-free-v2"}
    env = _analyzer_environment()
    cmd = command(binary)

    def save() -> None:
        _write_json(work / "manifest.json", manifest)
        _write_json(base / "latest.json", manifest)

    def phase(name: str, args: list[str], allowed=(0,)) -> subprocess.CompletedProcess:
        invocation = cmd + args
        started = time.monotonic()
        try:
            proc = subprocess.run(invocation, cwd=str(root), env=env,
                                  capture_output=True, text=True, timeout=timeout,
                                  encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired) as exc:
            parts = [str(exc)]
            for output in (getattr(exc, "stdout", None), getattr(exc, "stderr", None)):
                if output:
                    parts.append(output.decode("utf-8", errors="replace")
                                 if isinstance(output, bytes) else output)
            (work / f"{name}.log").write_text("\n".join(parts), encoding="utf-8")
            manifest["phases"].append({"name": name, "command": invocation,
                                       "exit_code": None,
                                       "timed_out": isinstance(exc, subprocess.TimeoutExpired),
                                       "log": f"{name}.log"})
            save()
            raise RuntimeError(f"CodeChecker {name} 失败：{exc}；日志：{work}") from exc
        (work / f"{name}.log").write_text(proc.stdout + "\n" + proc.stderr,
                                          encoding="utf-8")
        manifest["phases"].append({"name": name, "command": invocation,
                                   "exit_code": proc.returncode,
                                   "seconds": round(time.monotonic() - started, 3),
                                   "log": f"{name}.log"})
        save()
        if proc.returncode not in allowed:
            raise RuntimeError(f"CodeChecker {name} 失败（退出码 {proc.returncode}）。"
                               f"日志：{work / (name + '.log')}\n"
                               f"{(proc.stderr or proc.stdout)[-1800:]}")
        return proc

    save()
    try:
        catalog = load_catalog(binary, env)
        _write_json(work / "catalog.json", catalog)
        analyzers = [item["name"] for item in catalog["analyzers"]
                     if item.get("path") and item.get("version") != "NOT FOUND"]
        if not analyzers:
            raise RuntimeError("CodeChecker 没有可运行的静态分析器。")
        source_db = _find_ccdb(root)
        if source_db is None:
            ccdb = _write_fallback_ccdb(target, work / "compile_commands.json", analyzers, env)
        else:
            (work / "compile_commands.original.json").write_text(
                source_db.read_text(encoding="utf-8"), encoding="utf-8")
            ccdb = _complete_synthetic_ccdb(root, source_db, work / "compile_commands.includes.json")
            ccdb = _gcc_compatible_ccdb(ccdb, work / "compile_commands.gcc.json", analyzers, env)
        ccdb = _arm_sysroot_ccdb(ccdb, work / "compile_commands.arm.json", env)
        if _has_cross_target(ccdb) and "gcc" in analyzers and \
                {"clangsa", "clang-tidy"} & set(analyzers):
            analyzers.remove("gcc")
        effective_db = work / "compile_commands.json"
        if ccdb != effective_db:
            effective_db.write_text(ccdb.read_text(encoding="utf-8"), encoding="utf-8")
        selected, full_scan = _selected_translation_units(target, effective_db)
        headers = [str((root / path).resolve()) for path in target.files
                   if path.suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}]
        if not selected and not headers:
            raise RuntimeError("CodeChecker 编译数据库中没有本次扫描的源文件。")
        caps = catalog["capabilities"]
        ctu = "clangsa" in analyzers and caps["ctu"]
        stats = "clangsa" in analyzers and caps["statistical_analysis"]
        if ctu or os.name == "nt":
            _source_alias(root, env)
        execution_work = base / "runs" / run_id
        config, config_path = _project_config(root)
        flags = ["--report-hash", "context-free-v2", "--capture-analysis-output",
                 "--jobs", str(min(4, os.cpu_count() or 1))]
        if source_db is None and "clangsa" in analyzers:
            # Keep missing-declaration diagnostics in source-only inputs while
            # allowing symbolic analysis. CodeChecker strips warning flags
            # from compile databases, so forward this through its native API.
            args_file = execution_work / "source-only-clang.args"
            (work / args_file.name).write_text(
                "-Wno-error=implicit-function-declaration\n", encoding="utf-8")
            flags += ["--analyzer-config", f"clangsa:cc-verbatim-args-file={args_file}"]
        for profile in CORE_PROFILES:
            flags += ["--enable", profile]
        if "gcc" in analyzers:
            flags += ["--enable", "prefix:gcc-analyzer"]
        if "infer" in analyzers:
            flags += ["--enable", "prefix:infer"]
        if target.analysis_profile == "automotive":
            flags += ["--enable", "guideline:misra-c"]
        if ctu:
            flags += ["--ctu-ast-mode",
                      "load-from-pch" if os.name == "nt" else "parse-on-demand"]
        if stats:
            flags += ["--stats"]
        project_dir = root / ".ecdet"
        if (project_dir / "skip.txt").is_file():
            flags += ["--ignore", str(project_dir / "skip.txt"),
                      "--drop-reports-from-skipped-files"]
        if (project_dir / "review_status.yaml").is_file():
            flags += ["--review-status-config", str(project_dir / "review_status.yaml")]
        if (root / ".clang-tidy").is_file() and "clang-tidy" in analyzers:
            flags += ["--analyzer-config", "clang-tidy:take-config-from-directory=true"]
        taint = project_dir / "taint.yaml"
        if taint.is_file() and "clangsa" in analyzers:
            checker = next((c["name"] for c in catalog["checkers"] if c["name"] in
                            {"optin.taint.GenericTaint", "alpha.security.taint.TaintPropagation"}), None)
            if not checker:
                raise RuntimeError("配置了 taint.yaml，但当前 Clang 没有污点传播检查器。")
            model = ("optin.taint.TaintPropagation" if checker == "optin.taint.GenericTaint"
                     else checker)
            model_path = Path(env.get("ECODET_CODECHECKER_SOURCE_ALIAS", str(root))) / ".ecdet" / "taint.yaml"
            flags += ["--enable", f"checker:{checker}", "--checker-config",
                      f"clangsa:{model}:Config={model_path}"]
        flags += config.get("analyze", [])
        builtin_ids = {item.rule_id for item in BUILTIN_RULES}
        for value in target.rule_enable:
            if value not in builtin_ids:
                flags += ["--enable", value]
        for value in target.rule_disable:
            if value not in builtin_ids:
                flags += ["--disable", value]
        effective_config = {"analyze": flags, "parse": config.get("parse", [])}
        _write_json(work / "effective-config.json", effective_config)
        manifest.update(analyzers=analyzers, capabilities=caps, ctu=ctu,
                        statistical_analysis=stats, full_scan=full_scan,
                        compile_database_source=str(source_db) if source_db else "source-only",
                        selected_translation_units=selected,
                        requested_headers=headers,
                        config_source=str(config_path) if config_path else None)
        save()
        print(f"[L3] CodeChecker：{', '.join(analyzers)}；CTU {'启用' if ctu else '不可用'}；原生报告：{work}")
        reports = execution_work / "reports"
        analyze_args = ["analyze", str(execution_work / "compile_commands.json"),
                        "--output", str(reports),
                        "--config", str(execution_work / "effective-config.json"),
                        "--analyzers", *analyzers]
        if ctu:
            phase("ctu-collect", analyze_args + ["--clean", "--ctu-collect"])
            analyze_args += ["--ctu-analyze"]
        else:
            analyze_args += ["--clean"]
        if not full_scan:
            analyze_args += ["--file", *selected, *headers]
        analyzed = phase("analyze", analyze_args, allowed=(0, 3))
        if reports.is_dir():
            # Preserve every review status in the native JSON audit trail.
            phase("parse-json", ["parse", str(reports), "--export", "json",
                                 "--output", str(execution_work / "results.json"),
                                 "--config", str(execution_work / "effective-config.json"),
                                 "--review-status", "unreviewed", "confirmed",
                                 "false_positive", "intentional", "suppress"], allowed=(0, 2))
            phase("parse-sarif", ["parse", str(reports), "--export", "sarif",
                                  "--output", str(execution_work / "results.sarif")], allowed=(0, 2))
            phase("parse-baseline", ["parse", str(reports), "--export", "baseline",
                                     "--output", str(execution_work / "reports.baseline")], allowed=(0, 2))
        if analyzed.returncode:
            raise RuntimeError(f"CodeChecker 有翻译单元分析失败，不能视为干净扫描；原生结果与失败复现保存在 {work}")
        native_metadata = reports / "metadata.json"
        if native_metadata.is_file():
            if "clangsa" in analyzers and not any(reports.glob("*.plist")):
                raise RuntimeError(f"CodeChecker 没有实际分析任何翻译单元，不能视为干净扫描；请检查文件过滤和编译数据库。日志：{work}")
            metadata = json.loads(native_metadata.read_text(encoding="utf-8"))
            manifest["executed_analyzers"] = sorted({
                name for tool in metadata.get("tools", [])
                for name in tool.get("analyzers", {})
            })
            manifest["enabled_checkers"] = sorted({
                name for tool in metadata.get("tools", [])
                for analyzer in tool.get("analyzers", {}).values()
                for name, active in analyzer.get("checkers", {}).items() if active
            })
        raw_text = (work / "results.json").read_text(encoding="utf-8")
        alerts = parse_codechecker_json(raw_text, root, catalog)
        manifest["report_count"] = len(json.loads(raw_text)["reports"])
        manifest["active_report_count"] = len(alerts)
        if full_scan and previous.get("status") == "complete":
            old = Path(previous["run_dir"]) / "reports"
            if old.is_dir():
                for state in ("new", "resolved", "unresolved"):
                    diff = phase(f"diff-{state}", ["cmd", "diff", "-b", str(old),
                                                  "-n", str(reports), f"--{state}",
                                                  "--output", "json", "--review-status",
                                                  "unreviewed", "confirmed", "false_positive",
                                                  "intentional"], allowed=(0, 2))
                    (work / f"diff-{state}.json").write_text(diff.stdout, encoding="utf-8")
                manifest["comparison_base"] = previous["run_dir"]
                manifest["comparison_scope"] = "native-all-review-statuses"
        manifest["status"] = "complete"
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
        if full_scan:
            _write_json(previous_path, manifest)
        if on_manifest:
            on_manifest(manifest)
        return alerts
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = str(exc)
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
        if isinstance(exc, RuntimeError):
            raise
        raise RuntimeError(f"CodeChecker 执行失败：{exc}；诊断目录：{work}") from exc
