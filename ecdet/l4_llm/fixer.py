"""LLM候选补丁与独立验证。

逐项记录函数范围、原告警重放、新错误和编译结果。动态与业务行为
未执行时保留SKIPPED；静态及语法通过不代表业务语义等价。
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l2_ir.model import Alert, Severity
from ecdet.l3_analysis.builtin_rules.checks import ProjectContext, build_file_facts
from ecdet.l4_llm.slicer import slice_context

FIX_SYSTEM_PROMPT = (
    "你是嵌入式 C 代码修复专家。针对给定告警修改该函数，要求："
    "最小改动、不改变函数签名与语义意图、消除告警且不引入新缺陷。"
    '只输出一个 JSON 对象：{"patched_function": "修改后的完整函数源码", '
    '"explanation": "中文修改说明"}。不要输出 JSON 以外内容。'
)


@dataclass
class FixProposal:
    rule_id: str
    path: str
    func_name: str
    func_start: int
    func_end: int
    original_code: str
    patched_code: str = ""
    explanation: str = ""
    verified: bool = False
    fail_reason: str = ""
    diff: str = ""
    source_engine: str = "builtin"
    alert_line: int = 0
    alert_col: int = 1
    validation: dict = field(default_factory=dict)
    client_mode: str = "unknown"
    candidate_status: str = "UNCONFIRMED_CANDIDATE"

    def to_props(self) -> dict:
        return {
            "verified": self.verified,
            "explanation": self.explanation,
            "fail_reason": self.fail_reason,
            "validation": self.validation,
            "client_mode": self.client_mode,
            "candidate_status": self.candidate_status,
            "source_engine": self.source_engine,
        }


def fix_candidate_status(alert: Alert) -> str:
    """A missing triage is a candidate, never an implicit confirmed defect."""
    triage = alert.triage
    if not triage:
        return "UNCONFIRMED_CANDIDATE"
    if triage.get("review_pending") or triage.get("review_status") == "PENDING":
        return "REVIEW_PENDING"
    if triage.get("verdict") == "TRUE_POSITIVE" and triage.get("verified") is True:
        return "EVIDENCE_CHECKED_CANDIDATE"
    return "REVIEW_REQUIRED"


def fix_candidate_allowed(alert: Alert) -> bool:
    return fix_candidate_status(alert) in {"UNCONFIRMED_CANDIDATE", "EVIDENCE_CHECKED_CANDIDATE"}


def apply_patch(source: str, start_line: int, end_line: int,
                patched_code: str) -> str:
    """用补丁文本替换源文件 [start_line, end_line] 行区间。"""
    lines = source.splitlines()
    new_lines = lines[:start_line - 1] + patched_code.splitlines() + lines[end_line:]
    return "\n".join(new_lines) + ("\n" if source.endswith("\n") else "")


def extract_patched_function(raw: str) -> dict:
    """从 LLM 输出解析 {"patched_function": ..., "explanation": ...}。"""
    if not isinstance(raw, str):
        return {}
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("explanation"), str):
        return {}
    patched = data.get("patched_function")
    if not isinstance(patched, str) or not patched.strip():
        return {}
    # 剥离可能的 markdown 代码栅栏
    fence = re.match(r"\s*```[cC]?\n(.*?)\n?```\s*$", patched, re.S)
    if fence:
        patched = fence.group(1)
    return {"patched_function": patched.rstrip(),
            "explanation": str(data.get("explanation", ""))[:500]}


class FixProposer:
    """修复建议生成器。client 传 Mock 即离线模式。"""

    def __init__(self, client, budget_chars: int = 8000):
        self.client = client
        self.budget_chars = budget_chars

    def propose(self, alert: Alert, ctx: ProjectContext) -> FixProposal:
        slice_ = slice_context(alert, ctx, self.budget_chars)
        proposal = FixProposal(
            rule_id=alert.rule_id, path=alert.location.path,
            func_name=slice_.func_name, func_start=slice_.func_start,
            func_end=slice_.func_end, original_code=slice_.function_text,
            source_engine=alert.engine, alert_line=alert.location.line,
            alert_col=alert.location.col, candidate_status=fix_candidate_status(alert),
            client_mode=getattr(self.client, "mode", "mock" if isinstance(self.client, MockFixClient) else "unknown"))
        if not fix_candidate_allowed(alert):
            proposal.fail_reason = "告警尚待复核，不能进入修复采纳流程"
            proposal.validation["generation"] = {"status": "SKIPPED", "detail": proposal.fail_reason}
            return proposal
        if not slice_.func_name:
            proposal.fail_reason = "告警不在函数内，无法生成函数级补丁"
            return proposal
        if slice_.truncated:
            proposal.fail_reason = "函数上下文已截断，不能生成完整函数替换"
            proposal.validation["generation"] = {"status": "SKIPPED", "detail": proposal.fail_reason}
            return proposal
        user = "\n".join([
            "## 告警",
            f"规则：{alert.rule_id}；位置：{alert.location.path}:{alert.location.line}",
            f"说明：{alert.message}",
            "",
            "## 当前函数",
            "```c",
            slice_.function_text,
            "```",
            "",
            "## 任务",
            "输出修复后的完整函数（JSON）。",
        ])
        try:
            raw = self.client.complete(FIX_SYSTEM_PROMPT, user)
            parsed = extract_patched_function(raw)
        except Exception as exc:
            # This is the client boundary: a failed model task must not stop
            # other proposals in the batch, including custom client adapters.
            proposal.fail_reason = f"LLM修复调用失败：{type(exc).__name__}"
            proposal.validation["generation"] = {"status": "ERROR", "detail": proposal.fail_reason}
            return proposal
        if not parsed:
            proposal.fail_reason = "LLM 输出不可解析（非结构化 JSON）"
            proposal.validation["generation"] = {"status": "FAIL", "detail": proposal.fail_reason}
            return proposal
        proposal.patched_code = parsed["patched_function"]
        proposal.explanation = parsed["explanation"]
        proposal.validation["generation"] = {"status": "PASS", "detail": "候选补丁已解析，尚未验证"}
        return proposal


class MockFixClient:
    """确定性 Mock：对可确定性修复的规则给出正确补丁，
    其余原样返回（真实修复能力来自设置页配置的真实端点）。"""

    def complete(self, system: str, user: str) -> str:
        rule = ""
        m = re.search(r"规则：(.+?)；", user)
        if m:
            rule = m.group(1).strip()
        fm = re.search(r"```c\n(.*?)\n```", user, re.S)
        func = fm.group(1) if fm else ""
        if rule == "CERT C STR31-C":
            patched = re.sub(
                r'strcpy\s*\(\s*(\w+)\s*,\s*("[^"]*")\s*\)',
                r'strncpy(\1, \2, sizeof(\1) - 1);\n    \1[sizeof(\1) - 1] = 0',
                func)
            return json.dumps({
                "patched_function": patched,
                "explanation": "将无界 strcpy 改为限长 strncpy 并补终止符"},
                ensure_ascii=False)
        if rule == "ECDET-CWE-197":
            # 类型拓宽：溢出的定宽初始化升级到能表示字面量的类型
            patched = re.sub(
                r"u?int(8|16)_t(\s+\w+\s*=\s*)(\d+)",
                lambda m: self._widen(m.group(1), m.group(2), m.group(3)),
                func)
            if patched != func:
                return json.dumps({
                    "patched_function": patched,
                    "explanation": "初始化值超出定宽类型，拓宽类型（uint8→uint16→uint32）"},
                    ensure_ascii=False)
        if rule == "ECDET-CWE-1284":
            # scanf %s → 以函数内首个缓冲区长度-1 限宽
            buf = re.search(r"char\s+(\w+)\s*\[\s*(\d+)\s*\]", func)
            if buf and "%s" in func:
                width = max(int(buf.group(2)) - 1, 1)
                patched = func.replace("%s", f"%{width}s")
                return json.dumps({
                    "patched_function": patched,
                    "explanation": f"为 %s 限定最大宽度 %{width}s（按缓冲区大小）"},
                    ensure_ascii=False)
        if rule == "CERT C ARR30-C":
            return json.dumps({
                "patched_function": func,      # 无效补丁：原样返回
                "explanation": "调整访问顺序（Mock：无效补丁路径）"},
                ensure_ascii=False)
        return json.dumps({
            "patched_function": func,
            "explanation": "维持原实现（Mock：无变化路径）"},
            ensure_ascii=False)

    @staticmethod
    def _widen(cur_bits: str, tail: str, value: str) -> str:
        v = int(value)
        for bits, tname in ((16, "uint16_t"), (32, "uint32_t"), (64, "uint64_t")):
            if v <= (1 << bits) - 1:
                if bits <= int(cur_bits):
                    return f"uint{cur_bits}{tail}{value}"
                return f"{tname}{tail}{value}"
        return f"uint64{tail}{value}"


class FixVerifier:
    """Replay the original builtin analysis and track each validation step.

    verified means the required static and syntax checks passed. It does not
    claim behavior equivalence; dynamic replay and behavior remain explicit.
    """

    def __init__(self, project_root, use_compiler: bool = True, svd_path=None,
                 profile=None, enable=None, disable=None):
        self.root = Path(project_root).resolve()
        self.use_compiler = use_compiler
        self.profile = profile
        self.enable = list(enable or [])
        self.disable = list(disable or [])
        self._gcc = shutil.which("gcc") if use_compiler else None
        self.svd_path = Path(svd_path) if svd_path else None
        if self.svd_path and not self.svd_path.is_absolute():
            self.svd_path = self.root / self.svd_path
        self._all_rules = set()          # 由 run 时注入
        self._include_dirs: list[Path] = []
        self._source_origins: dict[str, str] = {}
        from ecdet.l3_analysis.codechecker_verifier import NativeFixValidator
        self._native = NativeFixValidator(self.root, svd_path=self.svd_path,
                                          profile=profile, enable=self.enable,
                                          disable=self.disable)

    def _prepare(self, ctx: ProjectContext):
        from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES
        from ecdet.l3_analysis.engine import resolve_enabled
        self._all_rules = resolve_enabled(BUILTIN_RULES, self.profile, self.disable, self.enable)
        dirs = {self.root, self.root / "include", self.root / "inc"}
        for f in ctx.facts:
            dirs.add(self.root / Path(f.path).parent)
        self._include_dirs = sorted(dirs)

    @staticmethod
    def _step(proposal: FixProposal, step: str, status: str, detail: str) -> None:
        proposal.validation[step] = {"status": status, "detail": detail}

    def _reject(self, proposal: FixProposal, step: str, status: str, detail: str) -> FixProposal:
        self._step(proposal, step, status, detail)
        proposal.fail_reason = detail
        proposal.verified = False
        return proposal

    def _sources(self, ctx: ProjectContext) -> dict[str, str]:
        from ecdet.l3_analysis.engine import collect_sources
        sources = {}
        origins = {}
        for facts in ctx.facts:
            name = facts.path.replace("\\", "/")
            path = (self.root/name).resolve()
            path.relative_to(self.root)
            if path.is_file():
                sources[name] = path.read_text(encoding="utf-8", errors="replace")
                origins[name] = "disk"
            else:
                sources[name] = "\n".join(facts.lex.source_lines)
                origins[name] = "context-memory"
        for rel in collect_sources(self.root):
            name = rel.as_posix()
            sources[name] = (self.root/rel).read_text(encoding="utf-8", errors="replace")
            origins[name] = "disk"
        self._source_origins = origins
        return sources

    def _scan(self, sources: dict[str, str], svd_path: Path | None) -> list[Alert]:
        from types import SimpleNamespace
        from ecdet.l3_analysis.engine import BuiltinEngine
        target = SimpleNamespace(root=self.root, files=[Path(p) for p in sorted(sources)],
                                 svd_path=svd_path, read=lambda rel: sources[rel.as_posix()])
        return BuiltinEngine().run(target, self._all_rules)

    @staticmethod
    def _patch_scope(proposal: FixProposal, source: str) -> str:
        lines = source.splitlines()
        if not 1 <= proposal.func_start <= proposal.func_end <= len(lines):
            return "补丁函数边界无效"
        original = "\n".join(lines[proposal.func_start-1:proposal.func_end])
        if original.strip() != proposal.original_code.strip():
            return "源码已变化，补丁原函数与当前版本不一致"
        old = build_file_facts(proposal.path, original)
        new = build_file_facts(proposal.path, proposal.patched_code)
        if len(old.functions) != 1 or len(new.functions) != 1:
            return "补丁必须保留唯一目标函数"
        before, after = old.functions[0], new.functions[0]
        signature = lambda fn: re.sub(r"\s+", "", fn.signature)
        if before.name != proposal.func_name or after.name != before.name or signature(before) != signature(after):
            return "补丁修改函数身份或签名，需显式设计变更"
        tokens = new.lex.tokens
        opening = next((i for i,t in enumerate(tokens) if t.value == "{"), -1)
        closing, depth = -1, 0
        for i in range(opening,len(tokens)):
            depth += (tokens[i].value == "{") - (tokens[i].value == "}")
            if depth == 0:
                closing = i
                break
        signature_tokens = build_file_facts("signature.c", after.signature).lex.tokens
        if (new.lex.pp_lines or closing != len(tokens)-1
                or [t.value for t in tokens[:opening]] != [t.value for t in signature_tokens]):
            return "补丁超出目标函数范围"
        # Reject an empty function or a trivial return replacing active logic.
        meaningful = [t for t in after.tokens if t.value not in {"return", ";", "0", "1", "(", ")"}]
        if before.tokens and not meaningful:
            return "补丁删除了目标函数的执行逻辑"
        if before.calls_in_body() and not after.calls_in_body():
            return "补丁移除了全部原函数调用，需行为验证后人工评审"
        mutations = {"=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>=", "++", "--"}
        if any(t.value in mutations for t in before.tokens) and not any(t.value in mutations for t in after.tokens):
            return "补丁移除了全部执行写入，需行为验证后人工评审"
        return ""

    @staticmethod
    def _error_instances(alerts: list[Alert], line_map: dict[int, int] | None = None,
                         changed_path: str = "") -> Counter:
        instances = Counter()
        for alert in alerts:
            if alert.severity != Severity.ERROR:
                continue
            path = alert.location.path.replace("\\", "/")
            line = alert.location.line
            if line_map is not None and path == changed_path:
                line = line_map.get(line, -line)
            instances[(alert.rule_id, path, line, alert.location.col, alert.message)] += 1
        return instances

    @staticmethod
    def _line_map(before: str, after: str) -> dict[int, int]:
        mapping = {}
        matcher = difflib.SequenceMatcher(None, before.splitlines(), after.splitlines(), autojunk=False)
        for op, old_start, old_end, new_start, new_end in matcher.get_opcodes():
            if op in {"equal", "replace"}:
                for offset in range(min(old_end-old_start, new_end-new_start)):
                    mapping[new_start+offset+1] = old_start+offset+1
        return mapping

    def verify(self, proposal: FixProposal, ctx: ProjectContext,
               source_text: str) -> FixProposal:
        proposal.verified = False
        for name in ("patch_scope", "snapshot", "baseline", "static_replay", "new_errors", "compile", "native_replay", "dynamic_replay", "behavior"):
            self._step(proposal, name, "SKIPPED", "未执行")
        self._step(proposal, "behavior", "SKIPPED", "未提供业务行为回归，不声称语义等价")
        self._step(proposal, "dynamic_replay", "SKIPPED", "本验证器仅执行静态与编译检查")
        if proposal.fail_reason:
            return proposal
        self._prepare(ctx)
        if proposal.patched_code.strip() == proposal.original_code.strip():
            return self._reject(proposal,"patch_scope","FAIL","补丁未改变函数，拒绝")
        scope_error = self._patch_scope(proposal, source_text)
        if scope_error:
            return self._reject(proposal,"patch_scope","FAIL",scope_error)
        path = proposal.path.replace("\\", "/")
        try:
            (self.root/path).resolve().relative_to(self.root)
        except ValueError:
            return self._reject(proposal,"patch_scope","FAIL","补丁路径超出项目范围")
        self._step(proposal,"patch_scope","PASS","函数身份、签名与替换范围通过检查")
        try:
            current = (self.root/path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return self._reject(proposal,"snapshot","ERROR",f"当前目标源码不可读：{type(exc).__name__}")
        if current != source_text:
            return self._reject(proposal,"snapshot","FAIL","当前磁盘源码与补丁验证快照不一致，需重新生成候选")
        builtin_source = proposal.source_engine in {"builtin", "builtin-hw", "builtin-absint"}
        native_source = proposal.source_engine == "codechecker"
        if not native_source and (not builtin_source or proposal.rule_id not in self._all_rules):
            return self._reject(proposal,"static_replay","UNSUPPORTED","原告警引擎或规则不可由当前验证器重放")
        svd = self.svd_path
        if svd is None:
            from ecdet.l3_analysis.engine import project_files
            candidates = sorted(p for p in project_files(self.root) if p.suffix.lower() == ".svd")
            if len(candidates) == 1:
                svd = candidates[0]
            elif len(candidates) > 1:
                return self._reject(proposal,"static_replay","UNSUPPORTED","发现多个SVD，需明确原扫描所用硬件描述")
        if proposal.source_engine == "builtin-hw" and svd is None:
            return self._reject(proposal,"static_replay","UNSUPPORTED","缺少原硬件描述，不能验证硬件告警")
        if svd:
            from ecdet.l3_analysis.hw_model.svd import parse_svd
            try:
                parse_svd(svd)
            except (ValueError, OSError) as exc:
                return self._reject(proposal,"static_replay","ERROR",f"SVD加载失败：{exc}")
        try:
            sources = self._sources(ctx)
            sources[path] = source_text
            self._step(proposal,"snapshot","PASS","目标与当前磁盘一致；依赖优先读取当前磁盘，内存来源单独标记")
            proposal.validation["snapshot"]["sources"] = dict(self._source_origins)
            baseline = self._scan(sources,svd)
            original_line = proposal.alert_line
            original = [a for a in baseline if a.rule_id == proposal.rule_id
                        and a.location.path.replace("\\", "/") == path
                        and a.engine == proposal.source_engine
                        and (a.location.line == original_line if original_line else proposal.func_start <= a.location.line <= proposal.func_end)]
            if builtin_source:
                if not original:
                    return self._reject(proposal,"baseline","FAIL","原告警未在当前引擎、位置与上下文重现")
                self._step(proposal,"baseline","PASS",f"原告警重现{len(original)}条，来源{proposal.source_engine}")
            modified = apply_patch(source_text, proposal.func_start, proposal.func_end, proposal.patched_code)
            sources[path] = modified
            after = self._scan(sources,svd)
        except Exception as exc:
            return self._reject(proposal,"static_replay","ERROR",f"静态重放失败：{type(exc).__name__}")
        end = proposal.func_start + len(proposal.patched_code.splitlines()) - 1
        if builtin_source and any(a.rule_id == proposal.rule_id and a.engine == proposal.source_engine
               and a.location.path.replace("\\", "/") == path
               and proposal.func_start <= a.location.line <= end for a in after):
            return self._reject(proposal,"static_replay","FAIL","原告警在补丁后仍存在，拒绝")
        if builtin_source:
            self._step(proposal,"static_replay","PASS","完整内置引擎重扫，原告警已消除")
        new_errors = self._error_instances(after,self._line_map(source_text,modified),path) - self._error_instances(baseline)
        if new_errors:
            return self._reject(proposal,"new_errors","FAIL",f"补丁引入新的error告警实例{sum(new_errors.values())}条")
        self._step(proposal,"new_errors","PASS","未新增error告警实例，已映射行号漂移")
        proposal.diff = "\n".join(difflib.unified_diff(source_text.splitlines(), modified.splitlines(),
            fromfile=f"a/{proposal.path}", tofile=f"b/{proposal.path}", lineterm=""))
        if not self._gcc:
            return self._reject(proposal,"compile","SKIPPED","编译器缺失或编译检查被关闭，候选补丁尚未验证通过")
        try:
            ok, reason = self._compile_check(proposal.path, modified)
        except Exception as exc:
            return self._reject(proposal,"compile","ERROR",f"编译检查执行失败：{type(exc).__name__}")
        if not ok:
            return self._reject(proposal,"compile","FAIL",f"编译语法检查失败：{reason}")
        self._step(proposal,"compile","PASS","编译语法检查通过")
        memory_sources = [name for name, origin in self._source_origins.items()
                          if origin != "disk"]
        if memory_sources:
            return self._reject(proposal,"native_replay","UNSUPPORTED",
                "上下文包含仅内存存在的依赖，不能声明完整磁盘工程重放通过：" + ", ".join(sorted(memory_sources)))
        self._native.svd_path = svd
        try:
            native_ok, native_reason = self._native.verify(proposal, modified)
        except Exception as exc:
            return self._reject(proposal,"native_replay","ERROR",f"完整静态重放异常：{type(exc).__name__}")
        if not native_ok:
            if native_source:
                native_steps = getattr(self._native, "last_validation", {})
                self._step(proposal,"baseline",native_steps.get("baseline", "SKIPPED"), native_reason)
                self._step(proposal,"static_replay",native_steps.get("static_replay", "SKIPPED"),native_reason)
            return self._reject(proposal,"native_replay","FAIL",native_reason)
        self._step(proposal,"native_replay","PASS","CodeChecker与完整静态流水线已重放，原告警消失且未新增error")
        if native_source:
            self._step(proposal,"baseline","PASS","CodeChecker原告警已按引擎、规则和源码位置重现")
            self._step(proposal,"static_replay","PASS","CodeChecker原告警在补丁后已消除")
        proposal.verified = True
        return proposal

    def _compile_check(self, rel_path: str, modified: str) -> tuple[bool, str]:
        original = self.root / rel_path
        handle = tempfile.NamedTemporaryFile(prefix=".ecdet_fix_",suffix=".c",dir=original.parent,delete=False)
        tmp = Path(handle.name)
        handle.close()
        try:
            tmp.write_text(modified, encoding="utf-8")
            cmd, cwd = self._compile_command(original,tmp)
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                               encoding="utf-8", errors="replace", cwd=str(cwd))
            if r.returncode != 0:
                return False, (r.stderr or r.stdout)[-300:]
        except (subprocess.TimeoutExpired, OSError, ValueError, TypeError, KeyError) as e:
            return False, f"编译器调用异常：{e}"
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        return True, ""

    def _compile_command(self, original: Path, patched: Path) -> tuple[list[str], Path]:
        ccdb = next((path for path in (self.root/"build"/"compile_commands.json",self.root/"compile_commands.json") if path.exists()), None)
        if ccdb:
            entries = json.loads(ccdb.read_text(encoding="utf-8"))
            if not isinstance(entries,list):
                raise ValueError("编译数据库必须为数组")
            for entry in entries:
                if not isinstance(entry,dict) or not isinstance(entry.get("file"),str):
                    raise ValueError("编译数据库条目无效")
                directory = Path(entry.get("directory",str(self.root)))
                if not directory.is_absolute():
                    directory = self.root/directory
                source = Path(entry["file"])
                source = source if source.is_absolute() else directory/source
                if source.resolve() != original.resolve():
                    continue
                args = entry.get("arguments")
                if args is None:
                    args = shlex.split(entry.get("command",""),posix=os.name != "nt")
                    args = [arg[1:-1] if len(arg)>1 and arg[0]==arg[-1] and arg[0] in {'"',"'"} else arg for arg in args]
                if not isinstance(args,list) or not args or any(not isinstance(arg,str) for arg in args):
                    raise ValueError("编译数据库缺少有效命令")
                # This verifier supports GCC/Clang-style syntax checks only.
                executable = Path(args[0]).name.lower()
                if not any(name in executable for name in ("gcc","g++","clang","cc")) or executable in {"ccache","sccache"}:
                    raise ValueError("当前验证器不支持该编译器命令")
                clean = [args[0]]
                skip = False
                replaced = False
                for arg in args[1:]:
                    if skip:
                        skip = False
                        continue
                    if arg in {"-o","-MF","-MT","-MQ"}:
                        skip = True
                        continue
                    if arg in {"-c","-MD","-MMD","-MP"} or arg.startswith(("-o","-MF","-MT","-MQ")):
                        continue
                    candidate = Path(arg)
                    candidate = candidate if candidate.is_absolute() else directory/candidate
                    if candidate.resolve() == original.resolve():
                        clean.append(str(patched))
                        replaced = True
                    else:
                        clean.append(arg)
                if not replaced:
                    raise ValueError("编译命令未引用目标源码")
                clean.append("-fsyntax-only")
                return clean,directory
            raise ValueError("编译数据库中没有原目标的编译命令")
        cmd = [self._gcc,"-fsyntax-only","-std=gnu89","-w"]
        cmd += [f"-I{directory}" for directory in self._include_dirs if directory.exists()]
        return cmd+[str(patched)], self.root
