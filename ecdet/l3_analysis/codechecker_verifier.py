"""Verify proposed fixes with the complete static pipeline in a project copy."""

from __future__ import annotations

import hashlib
import difflib
import json
import os
import re
import shutil
import uuid
from collections import Counter
from pathlib import Path

from ecdet.l2_ir.model import Alert, Severity
from ecdet.l3_analysis.engine import AnalysisTarget, collect_sources, project_files, run_all_engines


class NativeFixValidator:
    def __init__(self, root: Path, svd_path: Path | None = None,
                 profile=None, enable=None, disable=None):
        self.root = root.resolve()
        self.svd_path = svd_path
        self.profile = profile
        self.enable = enable
        self.disable = disable
        self._signature = ""
        self._baseline: list[Alert] = []
        self._workspace: Path | None = None
        self._artifacts: Path | None = None
        self.last_validation: dict[str, str] = {}

    def _snapshot(self) -> None:
        from ecdet.l3_analysis.adapters.codechecker import _find_ccdb
        from ecdet.l3_analysis.codechecker_runner import _ascii_alias

        files = collect_sources(self.root)
        inputs = {self.root / rel for rel in files}
        excluded_inputs = {".git", ".svn", ".venv", "__pycache__", "node_modules", "ecdet_reports"}
        inputs.update(path for path in project_files(self.root, excluded_inputs) if path.is_file()
                      and path.suffix.lower() in {".h", ".hpp", ".hh", ".hxx", ".rsp", ".svd"}
                      and not excluded_inputs.intersection(path.relative_to(self.root).parts))
        if self.svd_path and self.svd_path.is_file():
            inputs.add(self.svd_path)
        inputs.update(path for path in (self.root / ".ecdet").glob("**/*")
                      if path.is_file())
        if (self.root / ".clang-tidy").is_file():
            inputs.add(self.root / ".clang-tidy")
        ccdb = _find_ccdb(self.root)
        if ccdb:
            inputs.add(ccdb)
        digest = hashlib.sha256()
        for path in sorted(inputs):
            digest.update(str(path).encode("utf-8"))
            digest.update(path.read_bytes())
        if digest.hexdigest() == self._signature:
            return

        # Keep evidence inside the project while accessing deep Windows paths
        # through the same short junction used by native analyzer runs.
        artifacts = _ascii_alias(self.root / "ecdet_reports" / "fix-verification" / uuid.uuid4().hex)
        workspace = artifacts / "workspace"
        workspace.parent.mkdir(parents=True, exist_ok=True)
        # Keep generated headers/build context, but never recurse into our own
        # reports or copy installed environments and repository history.
        excluded = {".git", ".svn", ".venv", "__pycache__", "node_modules", "ecdet_reports"}

        def ignore(directory, names):
            ignored = set(names) & excluded
            if Path(directory).name == "ecdet_build":
                ignored |= set(names) & {"codechecker_audit"}
            return ignored

        shutil.copytree(self.root, workspace, ignore=ignore)

        def remap(value):
            if isinstance(value, str):
                for before, after in ((str(self.root), str(workspace)),
                                      (self.root.as_posix(), workspace.as_posix())):
                    value = re.sub(re.escape(before) + r"(?=$|[/\\\s'\";,])",
                                   lambda _: after, value,
                                   flags=re.IGNORECASE if os.name == "nt" else 0)
                return value
            if isinstance(value, list):
                return [remap(item) for item in value]
            if isinstance(value, dict):
                return {key: remap(item) for key, item in value.items()}
            return value

        if ccdb:
            database = remap(json.loads(ccdb.read_text(encoding="utf-8")))
            # Keep the database at its original relative location so ecdet's
            # synthetic-command repairs remain distinguishable from real builds.
            destination = workspace / ccdb.relative_to(self.root)
            destination.write_text(json.dumps(database, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        for path in [*workspace.rglob("*.rsp"), workspace / ".clang-tidy",
                     *(workspace / ".ecdet").glob("**/*")]:
            if path.is_file():
                try:
                    content = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                rewritten = (json.dumps(remap(json.loads(content)), ensure_ascii=False, indent=2)
                             if path.suffix == ".json" else remap(content))
                if rewritten != content:
                    path.write_text(rewritten, encoding="utf-8")

        self._workspace = workspace
        self._artifacts = artifacts
        self._baseline = self._scan("before")
        self._signature = digest.hexdigest()

    def _scan(self, label: str) -> list[Alert]:
        svd = self.svd_path
        if svd:
            try:
                svd = self._workspace / svd.resolve().relative_to(self.root)
            except ValueError:
                pass
        else:
            svd = next(iter(sorted((p for p in project_files(self._workspace) if p.suffix.lower() == ".svd"))), None)
        target = AnalysisTarget(root=self._workspace,
                                files=collect_sources(self._workspace),
                                svd_path=svd,
                                artifact_dir=self._artifacts / label)
        alerts, _ = run_all_engines(target, profile=self.profile,
                                    enable=self.enable, disable=self.disable)
        return alerts

    def verify(self, proposal, modified: str) -> tuple[bool, str]:
        self.last_validation = {"baseline": "SKIPPED", "static_replay": "SKIPPED",
                                "new_errors": "SKIPPED"}
        try:
            self._snapshot()
            rel = (self.root / proposal.path).resolve().relative_to(self.root)
            target = self._workspace / rel
            if target.read_text(encoding="utf-8", errors="replace") != (
                    self.root / rel).read_text(encoding="utf-8", errors="replace"):
                return False, "完整静态验证的工作区快照与当前源码不一致，拒绝"
            original = target.read_bytes()
            try:
                target.write_text(modified, encoding="utf-8")
                after = self._scan("after-" + uuid.uuid4().hex[:8])
            finally:
                target.write_bytes(original)
        except (RuntimeError, OSError, ValueError) as exc:
            return False, f"完整静态验证失败，拒绝：{exc}"

        def in_function(alert, end):
            return (alert.rule_id == proposal.rule_id and
                    alert.engine == proposal.source_engine and
                    alert.location.path == rel.as_posix() and
                    proposal.func_start <= alert.location.line <= end)

        def original_instance(alert):
            if not in_function(alert, proposal.func_end):
                return False
            if proposal.alert_line:
                return (alert.location.line == proposal.alert_line and
                        (not proposal.alert_col or alert.location.col == proposal.alert_col))
            return True

        if not any(original_instance(a) for a in self._baseline):
            self.last_validation["baseline"] = "FAIL"
            return False, "完整静态重扫无法复现原告警，拒绝"
        self.last_validation["baseline"] = "PASS"
        end = proposal.func_start + len(proposal.patched_code.splitlines()) - 1
        if any(in_function(a, end) for a in after):
            self.last_validation["static_replay"] = "FAIL"
            return False, "CodeChecker/完整静态重扫后原告警仍存在，拒绝"
        self.last_validation["static_replay"] = "PASS"

        delta = end - proposal.func_end
        unchanged_lines = {}
        matcher = difflib.SequenceMatcher(a=proposal.original_code.splitlines(),
                                          b=proposal.patched_code.splitlines(), autojunk=False)
        for block in matcher.get_matching_blocks():
            for offset in range(block.size):
                unchanged_lines[proposal.func_start + block.a + offset] = (
                    proposal.func_start + block.b + offset)

        def identity(alert, before=False):
            line = alert.location.line
            if before and alert.location.path == rel.as_posix():
                if line > proposal.func_end:
                    line += delta
                else:
                    line = unchanged_lines.get(line, line)
            # A CodeChecker report hash includes source context and can change
            # when a different defect in the same statement is repaired. Keep
            # the hash as evidence, but compare actual diagnostic instances.
            return (alert.engine, alert.rule_id, alert.location.path, line,
                    alert.location.col, alert.message)

        prior = Counter(identity(a, True) for a in self._baseline if a.severity == Severity.ERROR)
        introduced = []
        for alert in after:
            if alert.severity != Severity.ERROR:
                continue
            key = identity(alert)
            if prior[key]:
                prior[key] -= 1
            else:
                introduced.append(alert)
        if introduced:
            self.last_validation["new_errors"] = "FAIL"
            return False, ("补丁引入新的 error 告警，拒绝：" +
                           ", ".join(sorted({a.rule_id for a in introduced})) +
                           f"；验证报告：{self._artifacts}")
        self.last_validation["new_errors"] = "PASS"
        return True, ""
