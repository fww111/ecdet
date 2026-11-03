"""Execute real clang-tidy positive/negative cases and audit the adapter path."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from ecdet.l2_ir.model import RuleMeta
from ecdet.l2_ir.sarif import build_sarif
from ecdet.l3_analysis.adapters.clang_tidy import parse_clang_tidy_output, run_clang_tidy
from ecdet.l3_analysis.engine import AnalysisTarget

CHECK = 'clang-analyzer-core.NullDereference'


def find_clang_tidy(explicit: str | Path | None = None) -> Path | None:
    """Use an explicit binary, PATH, or the documented Visual Studio layout."""
    requested = explicit or os.environ.get('ECDET_CLANG_TIDY')
    if requested:
        path = Path(requested).expanduser().resolve()
        return path if path.is_file() else None
    candidates = [shutil.which('clang-tidy')]
    candidates.extend([Path(os.environ.get('ProgramFiles', 'C:/Program Files'))/'LLVM/bin/clang-tidy.exe'])
    if os.name == 'nt':
        vswhere = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
        if vswhere.is_file():
            try:
                result = subprocess.run([str(vswhere), '-products', '*', '-property', 'installationPath'],
                                        capture_output=True, text=True, timeout=10)
                candidates.extend(Path(line.strip())/'VC/Tools/Llvm/x64/bin/clang-tidy.exe'
                                  for line in result.stdout.splitlines() if line.strip())
            except (OSError, subprocess.TimeoutExpired):
                pass
    return next((Path(value).expanduser().resolve() for value in candidates
                 if value and Path(value).expanduser().is_file()), None)


@contextmanager
def _tool_path(binary: Path):
    original = os.environ.get('PATH', '')
    original_tool = os.environ.get('ECDET_CLANG_TIDY')
    os.environ['PATH'] = str(binary.parent) + os.pathsep + original
    os.environ['ECDET_CLANG_TIDY'] = str(binary)
    try:
        yield
    finally:
        os.environ['PATH'] = original
        if original_tool is None:
            os.environ.pop('ECDET_CLANG_TIDY',None)
        else:
            os.environ['ECDET_CLANG_TIDY'] = original_tool


def _execute(command: list[str], cwd: Path, prefix: Path, timeout: int) -> dict:
    started = time.perf_counter()
    try:
        process = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'ERROR', 'command': command, 'error_type': type(exc).__name__,
                'seconds': time.perf_counter()-started}
    prefix.with_suffix('.stdout.txt').write_text(process.stdout, encoding='utf-8')
    prefix.with_suffix('.stderr.txt').write_text(process.stderr, encoding='utf-8')
    diagnostics = parse_clang_tidy_output(process.stdout, process.stderr)
    # A compilation error means the fixture was not analysed as intended.
    compile_errors = len(re.findall(r'^(?:.*:\d+:\d+:\s*)?(?:fatal )?error:',
                                    process.stdout+'\n'+process.stderr, re.MULTILINE))
    return {'status':'PASS' if process.returncode == 0 and not compile_errors else 'ERROR',
            'command':command,'returncode':process.returncode,
            'seconds':time.perf_counter()-started,'compile_errors':compile_errors,
            'target_diagnostics':sum(a.rule_id == CHECK for a in diagnostics),
            'diagnostics':[a.to_dict() for a in diagnostics]}


def validate_clang_tidy(binary: str | Path, output_dir: str | Path, timeout: int = 60) -> dict:
    binary = Path(binary).expanduser().resolve()
    if not binary.is_file():
        raise FileNotFoundError(f'clang-tidy binary missing: {binary}')
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    workspace = output/'workspace'
    workspace.mkdir(exist_ok=True)
    fixture_root = PROJECT/'examples/clang_tidy_validation'
    sources = ['null_bad.c','null_good.c']
    for name in sources:
        shutil.copyfile(fixture_root/name, workspace/name)
    commands = [{'directory':str(workspace),'file':str(workspace/name),
                 'arguments':['clang','-x','c','-std=c11','-c',str(workspace/name)]}
                for name in sources]
    (workspace/'compile_commands.json').write_text(json.dumps(commands, indent=2),encoding='utf-8')
    version = subprocess.run([str(binary),'--version'], capture_output=True, text=True,
                             encoding='utf-8',errors='replace',timeout=timeout)
    (output/'version.txt').write_text(version.stdout+version.stderr,encoding='utf-8')
    result = {'mode':'real','binary':str(binary),'version':version.stdout.strip(),
              'status':'ERROR','source_sha256':{name:hashlib.sha256((workspace/name).read_bytes()).hexdigest() for name in sources},
              'cases':{}}
    for name in sources:
        command = [str(binary),'-p',str(workspace),'--quiet',f'--checks=-*,{CHECK}',str(workspace/name)]
        result['cases'][name] = _execute(command,workspace,output/Path(name).stem,timeout)

    # Exercise run_clang_tidy itself, rather than only parse copied diagnostics.
    log_handler = logging.FileHandler(output/'adapter.log',encoding='utf-8')
    logger = logging.getLogger('ecdet.l3_analysis.adapters.clang_tidy')
    previous_level = logger.level
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)
    started = time.perf_counter()
    try:
        with _tool_path(binary):
            resolved = shutil.which(os.environ['ECDET_CLANG_TIDY'])
            if not resolved or not Path(resolved).samefile(binary):
                raise ValueError('Selected binary does not match clang-tidy resolved by the adapter')
            alerts = run_clang_tidy(AnalysisTarget(workspace,[Path(name) for name in sources]),timeout=timeout)
    finally:
        logger.removeHandler(log_handler)
        logger.setLevel(previous_level)
        log_handler.close()
    target_alerts = [a for a in alerts if a.rule_id == CHECK]
    result['adapter'] = {'binary_resolved':str(Path(resolved).resolve()),
                         'command':[str(binary),'-p',str(workspace),'--quiet',
                                    '--checks=clang-analyzer-*,bugprone-*,cert-*,misc-*,readability-*',
                                    *[str(workspace/name) for name in sources]],
                         'seconds':time.perf_counter()-started,'alerts':[a.to_dict() for a in alerts],
                         'bad_target_diagnostics':sum(Path(a.location.path).name == 'null_bad.c' for a in target_alerts),
                         'good_target_diagnostics':sum(Path(a.location.path).name == 'null_good.c' for a in target_alerts)}
    rules = [RuleMeta(rule,'clang-tidy','Required','dataflow',
                      '空指针解引用' if rule == CHECK else rule,
                      ['CWE-476'] if rule == CHECK else [])
             for rule in sorted({a.rule_id for a in alerts})]
    sarif = build_sarif(alerts,rules)
    sarif_path = output/'results.sarif'
    sarif_path.write_text(json.dumps(sarif,ensure_ascii=False,indent=2),encoding='utf-8')
    loaded = json.loads(sarif_path.read_text(encoding='utf-8'))
    result['sarif'] = {'path':str(sarif_path),'target_rules':sorted({r['ruleId'] for r in loaded['runs'][0]['results'] if r['ruleId'] == CHECK})}
    expected = {'null_bad.c':1,'null_good.c':0}
    passed = (version.returncode == 0
              and all(result['cases'][name]['status'] == 'PASS' and result['cases'][name]['target_diagnostics'] == count for name,count in expected.items())
              and result['adapter']['bad_target_diagnostics'] == 1
              and result['adapter']['good_target_diagnostics'] == 0
              and result['sarif']['target_rules'] == [CHECK])
    result['status'] = 'PASS' if passed else 'ERROR'
    (output/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return result


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',help='Absolute or relative path to real clang-tidy')
    parser.add_argument('--output-dir',default=str(PROJECT/'ecdet_reports/clang_tidy_live'))
    args=parser.parse_args(argv)
    binary=find_clang_tidy(args.binary)
    if binary is None:
        print('Real clang-tidy unavailable; validation not executed.',file=sys.stderr)
        return 2
    try:
        result=validate_clang_tidy(binary,args.output_dir)
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status':'ERROR','mode':'real','error_type':type(exc).__name__,
                          'reason':str(exc)},ensure_ascii=False),file=sys.stderr)
        return 2
    print(json.dumps({'status':result['status'],'mode':result['mode'],'version':result['version'],
                      'output_dir':str(Path(args.output_dir).resolve())},ensure_ascii=False,indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
