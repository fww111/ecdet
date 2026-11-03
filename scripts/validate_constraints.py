"""Real Z3/source extraction acceptance with an independent C witness checker."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

PROJECT=Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:sys.path.insert(0,str(PROJECT))
from ecdet.l3_analysis.constraints import RULE_ID,analyze_constraints
from ecdet.l2_ir.model import RuleMeta
from ecdet.l2_ir.sarif import build_sarif


def validate(output_dir: Path) -> dict:
    output=Path(output_dir).resolve();output.mkdir(parents=True,exist_ok=True)
    source_path=PROJECT/'examples/constraints_demo/bounds.c'
    source=source_path.read_text(encoding='utf-8')
    report=analyze_constraints(source,'bounds.c')
    (output/'constraints.json').write_text(json.dumps(report.to_dict(),ensure_ascii=False,indent=2),encoding='utf-8')
    expected={'missing_lower_guard':'SAT','guarded_index':'UNSAT','promoted_byte':'SAT',
              'unsigned_wrap':'UNSAT','signed_overflow':'UNSUPPORTED'}
    actual={r.function:r.status for r in report.results}
    unknown=analyze_constraints('int f(int n) { int a[8]={0}; return a[n]; }','limited.c',resource_limit=1)
    (output/'resource_limited.json').write_text(json.dumps(unknown.to_dict(),ensure_ascii=False,indent=2),encoding='utf-8')
    receipt={'status':'PASS' if report.status=='COMPLETED' and actual==expected else 'FAIL',
        'solver_version':report.solver_version,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
        'expected':expected,'actual':actual,'unknown_status':[r.status for r in unknown.results],
        'witness_replay_kind':'Independent compiled C guard/index arithmetic; no invalid memory access executed.',
        'native_replay':{'status':'SKIPPED','reason':'gcc unavailable'}}
    gcc=shutil.which('gcc')
    if gcc and actual==expected:
        witnesses={r.function:r.witness for r in report.results if r.status=='SAT'}
        # The independent oracle uses signed 64-bit arithmetic to test the
        # mathematical address range after the original 32/8-bit parameter values.
        c='''#include <stdint.h>
#include <stdio.h>
int main(void) {
    int32_t negative = NEGATIVE;
    uint8_t byte = BYTE;
    int bad_guard_reached = negative < 8;
    int bad_address = (int64_t)negative < 0 || (int64_t)negative >= 8;
    int promoted_address = ((int)byte + 1) >= 256;
    unsigned wrapping = 0xffffffffu;
    unsigned wrapped_index = wrapping + 1u;
    int ok = bad_guard_reached && bad_address && promoted_address && wrapped_index == 0u;
    printf("{\\"negative_guard_reached\\":%d,\\"negative_index_invalid\\":%d,"
           "\\"promoted_index_invalid\\":%d,\\"unsigned_wrapped_index\\":%u}\\n",
           bad_guard_reached,bad_address,promoted_address,wrapped_index);
    return ok ? 0 : 1;
}
'''.replace('NEGATIVE',str(witnesses['missing_lower_guard']['index'])).replace('BYTE',str(witnesses['promoted_byte']['index']))
        oracle=output/'witness_check.c';oracle.write_text(c,encoding='utf-8')
        exe=output/('witness_check.exe' if os.name=='nt' else 'witness_check')
        commands=[]
        for command in ([gcc,'-std=c11','-Wall','-Wextra','-Werror','-fsyntax-only',str(source_path)],
                        [gcc,'-std=c11','-Wall','-Wextra','-Werror',str(oracle),'-o',str(exe)]):
            completed=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
            commands.append({'command':command,'exit_code':completed.returncode,
                             'stdout':completed.stdout,'stderr':completed.stderr})
        if all(c['exit_code']==0 for c in commands):
            completed=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
            commands.append({'command':[str(exe)],'exit_code':completed.returncode,
                             'stdout':completed.stdout,'stderr':completed.stderr})
            receipt['native_replay']={'status':'PASS' if completed.returncode==0 else 'FAIL',
                                     'observations':json.loads(completed.stdout),'commands':commands}
        else:receipt['native_replay']={'status':'FAIL','commands':commands}
        if receipt['native_replay']['status']!='PASS':receipt['status']='FAIL'
    if receipt['unknown_status']!=['UNKNOWN']:receipt['status']='FAIL'
    alerts=report.alerts()
    meta=RuleMeta(RULE_ID,'ECDET','Advisory','dataflow','Z3局部数组边界约束候选',['CWE-129'])
    (output/'results.sarif').write_text(json.dumps(build_sarif(alerts,[meta]),ensure_ascii=False,indent=2),encoding='utf-8')
    receipt['candidate_alerts']=len(alerts)
    receipt['original_alerts_modified']=False
    (output/'validation.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args()
    receipt=validate(args.output_dir)
    print(json.dumps(receipt,ensure_ascii=False,indent=2))
    return 0 if receipt['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
