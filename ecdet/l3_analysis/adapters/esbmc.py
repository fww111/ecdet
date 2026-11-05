"""Bounded ESBMC execution with explicit engineering coverage receipts."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity
from ecdet.l3_analysis.engine import AnalysisTarget, ExternalEngineAdapter

_PROPERTY_RE = re.compile(r"^\s*\[\w+(?:\.\w+)*\]\s+(.*(?:FAILED|SUCCEEDED))\s*$", re.M)


def parse_esbmc_output(text: str, src_name: str = "") -> list[Alert]:
    """A counterexample proves a violation under the executed model, not safety."""
    if not re.search(r"VERIFICATION\s+FAILED", text):
        return []
    props = _PROPERTY_RE.findall(text)
    detail = "；".join(p.strip() for p in props[:3]) or "ESBMC报告性质违反"
    location = Location(src_name, 1)
    match = re.search(r"Violated property:\s*\n\s*file (.+?) line (\d+)", text)
    if match:
        location = Location(match[1], int(match[2]))
    return [Alert("ESBMC-CHECK", "esbmc", Severity.ERROR,
        "有界模型检查发现反例："+detail, location,
        provenance=Provenance.PROVEN,
        evidence=[Evidence("runtime", "ESBMC VERIFICATION FAILED；结论限于执行模型和展开界", location)],
        properties={"scope": "bounded execution model"})]


class ESBMCAdapter(ExternalEngineAdapter):
    """Check a linked project entry; missing context is an analysis status."""
    name = "esbmc"
    binary = "esbmc"

    def available(self) -> bool:
        return shutil.which(os.environ.get("ECDET_ESBMC", self.binary)) is not None

    def run(self, target: AnalysisTarget, enabled_rules: set[str]) -> list[Alert]:
        base = target.artifact_dir or target.root / "ecdet_reports"
        out = (base.parent if base.name == "codechecker" else base) / "esbmc"
        out.mkdir(parents=True, exist_ok=True)
        receipt = dict(status="ERROR", model="native Windows host" if os.name == "nt" else "native host",
                       hardware_execution=False, pointer_checks=True, sources=[])
        self.scan_manifest = receipt
        alerts = []
        try:
            alerts = self._run_project(target, out, receipt)
        except (OSError, ValueError) as exc:
            receipt.update(status="ERROR", detail=str(exc))
        (out/"receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
        if receipt["status"] not in {"PASS", "FAIL"}:
            alerts.append(Alert("ECDET-ESBMC-INCOMPLETE", "esbmc-status", Severity.ERROR,
                "ESBMC分析未完成："+receipt.get("detail", receipt["status"]), Location("", 1),
                provenance=Provenance.SUSPECTED,
                evidence=[Evidence("tool-status", "状态与执行日志见ESBMC回执")],
                properties={"analysis_status": receipt["status"], "is_defect": False,
                            "receipt": str(out/"receipt.json")}))
        return alerts

    def _run_project(self, target, out, receipt):
        from ecdet.l3_analysis.builtin_rules.checks import build_file_facts
        root = target.root.resolve()
        binary = shutil.which(os.environ.get("ECDET_ESBMC", self.binary))
        if not binary:
            receipt.update(status="UNSUPPORTED", detail="ESBMC binary unavailable"); return []
        entry = os.environ.get("ECDET_ESBMC_FUNCTION", "main")
        timeout = float(os.environ.get("ECDET_ESBMC_TIMEOUT", "60"))
        unwind = int(os.environ.get("ECDET_ESBMC_UNWIND", "5"))
        if not re.fullmatch(r"[A-Za-z_]\w*", entry) or not math.isfinite(timeout) or not 0 < timeout <= 3600 or not 1 <= unwind <= 10000:
            raise ValueError("Invalid ESBMC entry, timeout or unwind configuration")
        receipt.update(entry=entry, unwind=unwind, timeout=timeout)
        files = []
        definitions = []
        for rel in target.files:
            source = (root/rel).resolve()
            if not source.is_relative_to(root): raise ValueError("ESBMC input outside project root")
            if source.suffix.lower() not in {".c", ".h"}: continue
            files.append(source)
            if source.suffix.lower() == ".c":
                syntax = build_file_facts(str(rel), source.read_text(encoding="utf-8")).syntax
                if not syntax or not syntax.reliable:
                    receipt.update(status="UNSUPPORTED", detail="Reliable source structure unavailable"); return []
                definitions.extend(str(rel) for f in syntax.functions if f.name == entry and not f.conditional)
        receipt["sources"] = [p.relative_to(root).as_posix() for p in files]
        if len(definitions) != 1:
            receipt.update(status="UNSUPPORTED", detail="Expected one unconditional entry definition: "+entry); return []
        cache = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "ecdet" / "esbmc-runs"
        work = cache / uuid.uuid4().hex
        work.mkdir(parents=True)
        if not str(work).isascii():
            receipt.update(status="UNSUPPORTED", detail="ASCII ESBMC workspace unavailable"); return []
        hashes = {}
        for source in files:
            rel = source.relative_to(root); destination = work/rel
            if not rel.as_posix().isascii():
                receipt.update(status="UNSUPPORTED", detail="Non-ASCII source filename unsupported"); return []
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            hashes[rel.as_posix()] = hashlib.sha256(source.read_bytes()).hexdigest()
        includes = {work, work/"include", *(work/p.relative_to(root).parent for p in files if p.suffix.lower() == ".h")}
        command = [binary, *[str(work/p.relative_to(root)) for p in files if p.suffix.lower() == ".c"],
                   "--function", entry, "--unwind", str(unwind),
                   *["-I"+str(p) for p in sorted(includes)]]
        receipt.update(command=command, source_sha256=hashes, workspace=str(work))
        try:
            run = subprocess.run(command, cwd=work, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            # TimeoutExpired can contain bytes even with text=True; callers and
            # platform subprocess implementations can also supply mixed types.
            parts = [value.decode('utf-8', errors='replace') if isinstance(value, bytes)
                     else value for value in (exc.stdout, exc.stderr) if value]
            (out/"run.log").write_text(''.join(parts), encoding='utf-8')
            receipt.update(status="TIMEOUT", detail="ESBMC execution exceeded timeout"); return []
        text = run.stdout + run.stderr
        (out/"run.log").write_text(text, encoding="utf-8")
        receipt["returncode"] = run.returncode
        if any(hashlib.sha256((root/name).read_bytes()).hexdigest() != h for name, h in hashes.items()):
            receipt.update(status="ERROR", detail="Project inputs changed during ESBMC execution"); return []
        if "VERIFICATION FAILED" in text and run.returncode == 1:
            if re.search(r"unwinding assertion.*(?:FAILED|violated)|unwinding assertion loop", text, re.I):
                receipt.update(status="BOUND_EXHAUSTED", detail="Loop unwind bound exhausted"); return []
            receipt.update(status="FAIL", detail="Counterexample under bounded host model")
            alerts = parse_esbmc_output(text, definitions[0])
            for alert in alerts:
                location = Path(alert.location.path)
                if location.is_relative_to(work): alert.location.path = location.relative_to(work).as_posix()
                alert.properties.update(receipt=str(out/"receipt.json"), unwind=unwind, entry=entry)
                alert.properties.update(host_model=receipt['model'], hardware_execution=False,
                                        needs_hardware_review=bool(target.svd_path))
                if target.svd_path:
                    alert.provenance = Provenance.SUSPECTED
                    alert.message = '宿主模型反例，需核对硬件语义：' + alert.message
            return alerts
        if "VERIFICATION SUCCESSFUL" in text and run.returncode == 0:
            receipt.update(status="PASS", detail="Reachable properties passed under recorded host model and bounds"); return []
        receipt.update(status="ERROR", detail="Parser, linker or solver failure; see run.log")
        return []
