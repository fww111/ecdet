"""构建复现主流程 —— BuildReconstruct（方案 3.3.1 伪代码的工程化实现）。

procedure BuildReconstruct(repo, target):
    if has CMakeLists.txt : cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    elif has Makefile     : bear -- make        # 构建拦截
    elif has *.ewp|*.uvprojx : IdeProjectParser(xml)
    else : directory-scan（源码直扫兜底）
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l1_build.iar import parse_ewp
from ecdet.l1_build.keil import parse_uvprojx

# Keil/IAR 工程产出等价 clang 交叉命令行时使用的驱动前端
_CROSS_DRIVER = "clang"
_TARGET_TRIPLE_DEFAULT = "arm-none-eabi"


@dataclass
class CompileCommand:
    """compile_commands.json 单条编译命令。"""

    directory: str
    file: str
    arguments: list[str] = field(default_factory=list)
    output: str = ""

    def to_dict(self) -> dict:
        return {
            "directory": self.directory,
            "file": self.file,
            "arguments": self.arguments,
            "output": self.output,
        }


@dataclass
class BuildReconResult:
    method: str                      # cmake / bear / keil-xml / iar-xml / makefile-scan / directory-scan
    commands: list[CompileCommand] = field(default_factory=list)
    ccdb_path: Path | None = None
    warnings: list[str] = field(default_factory=list)
    target_hint: str = ""            # 目标平台提示（Keil/IAR 工程中的芯片型号）


def _carry_warnings(target: BuildReconResult, source: BuildReconResult) -> BuildReconResult:
    """降级时保留上一通道累积的过程警告。"""
    target.warnings = source.warnings + target.warnings
    return target


def reconstruct(project_root: str | Path, build_cmd: str | None = None,
                out_dir: str | Path | None = None) -> BuildReconResult:
    """入口：识别工程类型并产出 compile_commands.json。"""
    root = Path(project_root).resolve()
    out = Path(out_dir) if out_dir else root / "ecdet_build"
    out.mkdir(parents=True, exist_ok=True)

    if build_cmd:
        return _via_intercept(root, out, build_cmd)
    if (root / "CMakeLists.txt").exists():
        return _via_cmake(root, out)
    if (root / "Makefile").exists() or (root / "makefile").exists():
        return _via_makefile(root, out)
    uvprojx = sorted(root.rglob("*.uvprojx"))
    if uvprojx:
        return _via_uvprojx(root, out, uvprojx[0])
    ewp = sorted(root.rglob("*.ewp"))
    if ewp:
        return _via_ewp(root, out, ewp[0])
    return _via_directory_scan(root, out)


# ---------------------------------------------------------------------------
# 通道 1：CMake 原生导出
# ---------------------------------------------------------------------------


def _via_cmake(root: Path, out: Path) -> BuildReconResult:
    res = BuildReconResult(method="cmake")
    if shutil.which("cmake") is None:
        res.warnings.append("检测到 CMakeLists.txt 但本机未安装 cmake，退化为源码直扫")
        return _carry_warnings(_via_directory_scan(root, out), res)
    proc = subprocess.run(
        ["cmake", "-S", str(root), "-B", str(out / "cmake"),
         "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
        capture_output=True, text=True, timeout=600,
        encoding="utf-8", errors="replace",
    )
    ccdb = out / "cmake" / "compile_commands.json"
    if proc.returncode != 0 or not ccdb.exists():
        res.warnings.append(
            f"cmake 配置失败（退出码 {proc.returncode}），退化为源码直扫：\n"
            f"{(proc.stderr or '')[-500:]}")
        return _via_directory_scan(root, out)
    return _finish_from_ccdb(ccdb, "cmake", res)


# ---------------------------------------------------------------------------
# 通道 2：Bear 构建拦截 / 自定义构建命令拦截
# ---------------------------------------------------------------------------


def _via_intercept(root: Path, out: Path, build_cmd: str) -> BuildReconResult:
    res = BuildReconResult(method=f"intercept:{build_cmd}")
    bear = shutil.which("bear")
    if bear is None:
        res.warnings.append("本机未安装 bear，无法拦截构建，退化为源码直扫")
        return _carry_warnings(_via_directory_scan(root, out), res)
    proc = subprocess.run(
        ["bear", "--", *build_cmd.split()],
        cwd=str(root), capture_output=True, text=True, timeout=1800,
        encoding="utf-8", errors="replace",
    )
    ccdb = root / "compile_commands.json"
    if proc.returncode != 0 or not ccdb.exists():
        res.warnings.append(f"bear 拦截失败（退出码 {proc.returncode}），退化为源码直扫")
        return _carry_warnings(_via_directory_scan(root, out), res)
    return _finish_from_ccdb(ccdb, res.method, res)


# ---------------------------------------------------------------------------
# 通道 3：Makefile（bear 优先，缺 bear 则扫描 Makefile 变量）
# ---------------------------------------------------------------------------


def _via_makefile(root: Path, out: Path) -> BuildReconResult:
    res = BuildReconResult(method="makefile-scan")
    if shutil.which("bear") is not None and shutil.which("make") is not None:
        intercepted = _via_intercept(root, out, "make")
        if intercepted.commands:
            return intercepted
        res.warnings.append("bear+make 未产出编译数据库，改用 Makefile 静态解析")
    include_flags, define_flags = _scan_makefile_flags(root)
    return _synthesize_from_sources(root, out, res, include_flags, define_flags)


def _scan_makefile_flags(root: Path) -> tuple[list[str], list[str]]:
    mk = root / "Makefile"
    if not mk.exists():
        mk = root / "makefile"
    text = mk.read_text(encoding="utf-8", errors="replace")
    includes: list[str] = []
    defines: list[str] = []
    import re
    for m in re.finditer(r"-I\s*([^\s]+)", text):
        p = m.group(1).strip("'\"")
        includes.append((root / p).resolve().as_posix() if not Path(p).is_absolute() else p)
    for m in re.finditer(r"-D\s*([A-Za-z_][\w]*)", text):
        defines.append(m.group(1))
    return includes, defines


# ---------------------------------------------------------------------------
# 通道 4：Keil / IAR 工程 XML 解析
# ---------------------------------------------------------------------------


def _via_uvprojx(root: Path, out: Path, proj: Path) -> BuildReconResult:
    res = BuildReconResult(method="keil-xml")
    try:
        parsed = parse_uvprojx(proj)
    except Exception as e:  # noqa: BLE001 —— XML 格式各异，解析失败降级
        res.warnings.append(f"Keil 工程解析失败（{e}），退化为源码直扫")
        return _carry_warnings(_via_directory_scan(root, out), res)
    res.target_hint = parsed.target_hint
    src_dir = proj.parent
    includes = [(src_dir / p).resolve().as_posix() for p in parsed.include_paths]
    defines = [f"-D{d}" for d in parsed.defines]
    return _synthesize_from_sources(
        root, out, res, [f"-I{p}" for p in includes], defines,
        sources=parsed.source_files, base_dir=src_dir,
    )


def _via_ewp(root: Path, out: Path, proj: Path) -> BuildReconResult:
    res = BuildReconResult(method="iar-xml")
    try:
        parsed = parse_ewp(proj)
    except Exception as e:  # noqa: BLE001
        res.warnings.append(f"IAR 工程解析失败（{e}），退化为源码直扫")
        return _carry_warnings(_via_directory_scan(root, out), res)
    res.target_hint = parsed.target_hint
    src_dir = proj.parent
    includes = [(src_dir / p).resolve().as_posix() for p in parsed.include_paths]
    defines = [f"-D{d}" for d in parsed.defines]
    return _synthesize_from_sources(
        root, out, res, [f"-I{p}" for p in includes], defines,
        sources=parsed.source_files, base_dir=src_dir,
    )


# ---------------------------------------------------------------------------
# 通道 5：源码目录直扫（零人工干预兜底）
# ---------------------------------------------------------------------------

_SKIP_DIRS = {".git", ".svn", "build", "ecdet_build", "node_modules", "__pycache__"}


def _via_directory_scan(root: Path, out: Path) -> BuildReconResult:
    res = BuildReconResult(method="directory-scan")
    # 以根目录与各源文件所在目录为包含路径，可覆盖绝大多数小型裸机工程
    includes = [f"-I{root.resolve().as_posix()}"]
    src_dirs = {p.parent.resolve().as_posix() for p in _iter_sources(root)}
    includes += [f"-I{d}" for d in sorted(src_dirs)]
    return _synthesize_from_sources(root, out, res, includes, [])


def _iter_sources(root: Path):
    for p in root.rglob("*"):
        if p.suffix.lower() == ".c" and not any(part in _SKIP_DIRS for part in p.parts):
            yield p


def _synthesize_from_sources(root: Path, out: Path, res: BuildReconResult,
                             include_flags: list[str], define_flags: list[str],
                             sources: list[str] | None = None,
                             base_dir: Path | None = None) -> BuildReconResult:
    base = (base_dir or root).resolve()
    files = sources or [p.relative_to(root).as_posix() for p in _iter_sources(root)]
    for rel in files:
        abs_file = (base / rel).resolve()
        file_arg = abs_file.as_posix()
        args = ([_CROSS_DRIVER, f"--target={_TARGET_TRIPLE_DEFAULT}"]
                + include_flags + define_flags + ["-c", file_arg])
        res.commands.append(
            CompileCommand(directory=base.as_posix(),
                           file=file_arg, arguments=args, output="")
        )
    if not res.commands:
        res.warnings.append("未发现任何 C 源文件，产出空编译数据库")
    return _write_ccdb(out, res)


# ---------------------------------------------------------------------------
# 收尾：写出 compile_commands.json
# ---------------------------------------------------------------------------


def _finish_from_ccdb(ccdb: Path, method: str, res: BuildReconResult) -> BuildReconResult:
    res.method = method
    try:
        entries = json.loads(ccdb.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        res.warnings.append(f"编译数据库读取失败：{e}")
        return res
    for e in entries:
        args = e.get("arguments")
        if args is None and e.get("command"):
            args = e["command"].split()
        res.commands.append(
            CompileCommand(directory=e.get("directory", ""),
                           file=e.get("file", ""),
                           arguments=args or [],
                           output=e.get("output", ""))
        )
    return _write_ccdb(ccdb.parent, res)


def _write_ccdb(out: Path, res: BuildReconResult) -> BuildReconResult:
    ccdb = out / "compile_commands.json"
    ccdb.write_text(
        json.dumps([c.to_dict() for c in res.commands],
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    res.ccdb_path = ccdb
    return res
