"""harness 生成与编译验证闭环（方案 3.3.5 之 harness 自动生成）。

以 L2 元数据（函数签名、目标文件）为骨架生成模板 harness：激励组合表
由 Python 侧确定性预生成并嵌入 C 常量数组，运行期以 argv 索引激活——
每函数只需编译一次，PoC 以 `harness.exe <seed>` 一键重放。编译日志
回传驱动修正（未解析符号自动打桩），即"生成→编译→运行→修正"闭环的
确定性 MVP；LLM 参与初版生成与复杂激励建模的接口预留（3.3.7
动态测试智能体的工具之一）。
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l3_analysis.dynamic.inputs import InputModel, param_value

_UNDEF_REF_RE = re.compile(r"undefined reference to [`'](\w+)'")
# GCC 14+ 在编译期即将隐式函数声明判为错误，需与链接期未解析符号一并收集
_IMPLICIT_DECL_RE = re.compile(r"implicit declaration of function [`'](\w+)'")
_STUBABLE = re.compile(r"^[A-Za-z_]\w*$")


@dataclass
class Harness:
    """单目标 harness：一份二进制覆盖全部激励组合。"""

    func_name: str
    target_rel: str
    n_seeds: int
    source: str = ""
    exe_path: Path | None = None
    stubs: list[str] = field(default_factory=list)

    def replay_seed(self, seed_idx: int) -> str:
        """触发第 seed_idx 组激励的命令行参数（PoC 重放）。"""
        return str(seed_idx % max(self.n_seeds, 1))


def generate_harness(model: InputModel, target_rel: str, n_seeds: int) -> Harness:
    """为目标函数生成覆盖 n_seeds 组激励的 harness 源码。"""
    n = max(min(n_seeds, max(model.n_specials, 1)), 1)
    ptr_params = [p for p in model.params if p.is_pointer]
    int_params = [p for p in model.params if not p.is_pointer]

    # 激励组合表：行=seed，列=整型参数
    rows = []
    for s in range(n):
        rows.append([param_value(p, s) for p in int_params])
    width = max((len(r) for r in rows), default=0)
    table_lines = ["{\n"]
    for row in rows:
        padded = row + ["0"] * (width - len(row))
        table_lines.append("{" + ", ".join(padded) + "},\n")
    table = "".join(table_lines) + "}"

    buffers = "\n".join(
        f"    char ecdet_buf_{p.name}[64];\n"
        f"    memset(ecdet_buf_{p.name}, 0x41, sizeof(ecdet_buf_{p.name}) - 1);\n"
        f"    ecdet_buf_{p.name}[sizeof(ecdet_buf_{p.name}) - 1] = 0;"
        for p in ptr_params)

    # 实参表达式：指针参数用预置缓冲区，整型参数查组合表
    arg_exprs: list[str] = []
    k = 0
    for p in model.params:
        if p.is_pointer:
            arg_exprs.append(f"ecdet_buf_{p.name}")
        else:
            arg_exprs.append(f"ecdet_combo[idx][{k}]")
            k += 1
    args = ", ".join(arg_exprs) if arg_exprs else "0"

    mmio = [p for p in int_params if p.mmio_reg]
    mmio_note = (f"（MMIO 语义分片：{','.join(p.name for p in mmio)}）"
                 if mmio else "")

    source = f"""\
/* ecdet dynamic harness — generated (target: {target_rel}::{model.func.name}) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "{Path(target_rel).name}"          /* 目标翻译单元整体包含 */

static const int ecdet_combo[{n}][{max(width, 1)}] = {table};

int main(int argc, char **argv) {{
    unsigned ecdet_seed = (unsigned)(argc > 1 ? strtoul(argv[1], 0, 0) : 0);
    int idx = (int)(ecdet_seed % {n}u);
{buffers}
    /* 激励：{n} 组确定性特殊值 + 散列采样{mmio_note} */
    volatile int ecdet_sink = {model.func.name}({args});
    (void)ecdet_sink;
    printf("ok\\n");
    return 0;
}}
"""
    return Harness(func_name=model.func.name, target_rel=target_rel,
                   n_seeds=n, source=source)


def compile_harness(harness: Harness, workdir: Path,
                    include_dirs: list[Path], gcc: str = "gcc",
                    max_fix_rounds: int = 3, timeout: int = 60,
                    fixer=None) -> tuple[bool, str]:
    """编译闭环：未解析符号自动打桩重编（生成-编译-修正）。

    确定性打桩失败后，若提供 fixer（LLM harness 修正器，方案 3.3.5），
    以"编译日志回传 → LLM 重写 → 再编译"最多 2 轮收尾。
    返回 (是否成功, 错误摘要)。
    """
    src = workdir / f"harness_{harness.func_name}.c"
    exe = workdir / f"harness_{harness.func_name}.exe"
    cmd_base = [gcc, "-w", "-g", "-O0", "-std=gnu99",
                *[f"-I{d}" for d in include_dirs if d.exists()]]
    stubs: list[str] = []
    err_tail = ""

    def _try_compile() -> tuple[bool, str, str]:
        """返回 (是否成功, 完整 stderr, 错误摘要尾部)。"""
        try:
            proc = subprocess.run(cmd_base + [str(src), "-o", str(exe)],
                                  capture_output=True, text=True,
                                  timeout=timeout, encoding="utf-8",
                                  errors="replace")
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, "", f"编译器调用异常：{e}"
        if proc.returncode == 0:
            harness.exe_path = exe
            harness.stubs = stubs
            return True, "", ""
        full_err = proc.stderr or ""
        return False, full_err, full_err[-500:]

    for _ in range(max_fix_rounds + 1):
        harness.source = _apply_stubs(harness.source, stubs)
        src.write_text(harness.source, encoding="utf-8")
        ok, full_err, err_tail = _try_compile()
        if ok:
            return True, ""
        # 缺失符号必须扫描完整 stderr：GCC 多条 implicit 错误中
        # 前面的会被尾部截断，漏收会导致打桩半截、下轮重复插入
        missing = [m for m in (_UNDEF_REF_RE.findall(full_err)
                               + _IMPLICIT_DECL_RE.findall(full_err))
                   if _STUBABLE.match(m) and m not in stubs
                   and m != harness.func_name]
        if not missing:
            break
        stubs.extend(dict.fromkeys(missing))

    # LLM 修正闭环（3.3.5：编译与执行日志回传驱动修正）
    if fixer is not None:
        for _ in range(2):
            fixed = fixer.fix(harness.source, full_err)
            if not fixed:
                break
            harness.source = fixed[0]
            src.write_text(harness.source, encoding="utf-8")
            ok, _full, err_tail = _try_compile()
            if ok:
                return True, ""
    return False, err_tail


def _apply_stubs(source: str, stubs: list[str]) -> str:
    """打桩插入点在目标 include 之前：调用点必须先见到声明。

    GCC 14+ 将隐式函数声明定为错误，故桩需以旧式无原型声明
    （`long name();`，gnu99 合法、兼容任意实参）置于 include 之前，
    定义随声明一并前置。
    """
    if not stubs:
        return source
    block = "\n".join(f"long {name}();                     /* ecdet stub */\n"
                      f"long {name}() {{ return 0; }}"
                      for name in stubs)
    # 插到 #include "target" 之前
    lines = source.splitlines(keepends=True)
    include_idx = next((i for i, ln in enumerate(lines)
                        if ln.startswith('#include "')), len(lines) - 1)
    return "".join(lines[:include_idx]) + block + "\n\n" + \
        "".join(lines[include_idx:])
