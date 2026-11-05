"""Opt-in native execution of reviewed business contracts.

Contracts bind a requirement, an exact source/function and an executable oracle.
They are trusted test code, not inferred requirements. A FAIL requires actual
entry into the instrumented target and an oracle assertion failure. Compilation,
timeouts and incomplete observations remain separate from defect findings.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import uuid

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, RuleMeta, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts

RULE=RuleMeta('ECDET-BUSINESS-CONTRACT','ECDET','Required','dynamic',
              '显式业务契约执行失败',[])


def _file(base, name):
    if not isinstance(name,str) or not name or Path(name).is_absolute():
        raise ValueError('Contract paths must be nonempty relative paths')
    path=(base/name).resolve()
    if not path.is_relative_to(base.resolve()) or not path.is_file():
        raise ValueError('Contract file missing or outside its allowed root: '+name)
    return path


def _load(root,spec):
    data=json.loads(spec.read_text(encoding='utf-8'))
    if not isinstance(data,dict) or type(data.get('version')) is not int or data['version']!=1:
        raise ValueError('Expected contract schema version 1')
    cases=data.get('contracts')
    if not isinstance(cases,list) or not 1<=len(cases)<=100:
        raise ValueError('Expected 1..100 contracts')
    seen=set()
    for case in cases:
        if not isinstance(case,dict):raise ValueError('Expected contract object')
        for name in ('id','function','requirement'):
            if not isinstance(case.get(name),str) or not case[name].strip():
                raise ValueError('Missing contract field: '+name)
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}',case['id']) or case['id'] in seen:
            raise ValueError('Invalid or duplicate contract ID')
        if not re.fullmatch(r'[A-Za-z_]\w*',case['function']):raise ValueError('Invalid function name')
        seen.add(case['id'])
        _file(root,case.get('source'));_file(spec.parent,case.get('harness'))
        sources=case.get('sources',[])
        if not isinstance(sources,list):raise ValueError('Expected sources array')
        for name in sources:_file(root,name)
    return cases


def _header(identifier):
    return f'''#ifndef ECDET_CONTRACT_H
#define ECDET_CONTRACT_H
#include <stdio.h>
static unsigned ecdet_contract_checks;
static void ecdet_contract_enter(void) {{
    fprintf(stderr,"ECDET_TARGET:{identifier}\\n"); fflush(stderr);
}}
#define ECDET_CHECK(x) do {{ ++ecdet_contract_checks; if (!(x)) {{ \
    fprintf(stderr,"ECDET_FAIL:{identifier}:%u:%s\\n",__LINE__,#x); \
    fflush(stderr); return 10; }} }} while (0)
#define ECDET_PASS() do {{ fprintf(stderr,"ECDET_PASS:{identifier}:%u\\n", \
    ecdet_contract_checks); fflush(stderr); return 0; }} while (0)
#endif
'''


def _execute(root,spec,case,directory,compiler,timeout):
    source=_file(root,case['source']);harness=_file(spec.parent,case['harness'])
    original=source.read_bytes();oracle=harness.read_bytes()
    item=dict(id=case['id'],source=case['source'],function=case['function'],
              requirement=case['requirement'],status='ERROR',line=1,
              source_sha256=hashlib.sha256(original).hexdigest(),
              harness_sha256=hashlib.sha256(oracle).hexdigest(),
              execution='native-host',artifact_dir=str(directory))
    compiler_path=shutil.which(compiler)
    if not compiler_path:
        item.update(status='UNSUPPORTED',detail='Native compiler unavailable');return item
    target=build_file_facts(case['source'],original.decode('utf-8')).syntax
    test=build_file_facts(harness.name,oracle.decode('utf-8')).syntax
    if not target or not test or not target.reliable or not test.reliable:
        item.update(status='UNSUPPORTED',detail='Reliable C syntax unavailable; install ecdet[syntax]');return item
    functions=[f for f in target.functions if f.name==case['function'] and not f.conditional]
    mains=[f for f in test.functions if f.name=='main' and not f.conditional]
    if len(functions)!=1 or len(mains)!=1:
        item['detail']='Expected one unconditional target definition and one oracle main';return item
    calls={c.name for c in mains[0].calls if c.kind=='direct'}
    if not {case['function'],'ECDET_CHECK','ECDET_PASS'}<=calls:
        item['detail']='Oracle main must call the target, ECDET_CHECK and ECDET_PASS';return item
    fn=functions[0];item['line']=fn.def_line
    insertion=fn.body_start_byte+1
    if original[fn.body_start_byte:insertion]!=b'{':
        item['detail']='Target body range mismatch';return item
    (directory/'ecdet_contract.h').write_text(_header(case['id']),encoding='utf-8')
    modified=(b'#include "ecdet_contract.h"\n'+original[:insertion]
              +b'\necdet_contract_enter();\n'+original[insertion:])
    target_copy=directory/'target.c';target_copy.write_bytes(modified)
    oracle_copy=directory/'oracle.c';oracle_copy.write_bytes(oracle)
    executable=directory/'oracle.exe'
    includes=sorted({root,source.parent,root/'include',spec.parent,directory})
    extra=[_file(root,name) for name in case.get('sources',[]) if name!=case['source']]
    inputs={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [source,*extra,*root.rglob('*.h')] if 'ecdet_reports' not in p.parts}
    item['input_sha256']=inputs
    command=[compiler_path,'-std=c11','-O0','-g','-ffunction-sections','-fdata-sections',
             *['-I'+str(p) for p in includes],str(target_copy),str(oracle_copy),
             *map(str,extra),'-Wl,--gc-sections','-lm','-o',str(executable)]
    item['compile_command']=command
    try:
        compiled=subprocess.run(command,cwd=root,capture_output=True,text=True,
                                encoding='utf-8',errors='replace',timeout=60)
        (directory/'compile.log').write_text(compiled.stdout+compiled.stderr,encoding='utf-8')
        item['compile_returncode']=compiled.returncode
        if compiled.returncode:
            item['detail']='Oracle compilation failed; see compile.log';return item
        run=subprocess.run([str(executable)],cwd=directory,capture_output=True,text=True,
                           encoding='utf-8',errors='replace',timeout=timeout)
        output=run.stdout+run.stderr
        (directory/'run.log').write_text(output,encoding='utf-8')
        item['returncode']=run.returncode
        item['target_entered']='ECDET_TARGET:'+case['id'] in output
        failed='ECDET_FAIL:'+case['id']+':' in output
        passed=re.search(r'ECDET_PASS:'+re.escape(case['id'])+r':([0-9]+)',output)
        if item['target_entered'] and run.returncode==10 and failed:
            item.update(status='FAIL',detail='Observed target execution and business assertion failure')
        elif item['target_entered'] and run.returncode==0 and passed and int(passed[1])>0 and not failed:
            item.update(status='PASS',detail='All executed assertions passed',assertions=int(passed[1]))
        else:item['detail']='Missing observations or unexpected process termination'
    except subprocess.TimeoutExpired:
        item.update(status='TIMEOUT',detail='Compilation or oracle execution timed out')
    except OSError as exc:
        item.update(status='ERROR',detail=str(exc))
    if any(hashlib.sha256((root/name).read_bytes()).hexdigest()!=h for name,h in inputs.items()):
        item.update(status='ERROR',detail='Input source changed during contract execution')
    return item


def run_contracts(root: Path,spec: Path,out: Path,*,compiler=None,timeout=5.0):
    """Run explicitly selected native tests and return receipts plus defect alerts."""
    root=Path(root).resolve();spec=Path(spec).resolve();out=Path(out).resolve()
    if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or not 0<timeout<=60:
        raise ValueError('Contract timeout must be in (0,60] seconds')
    cases=_load(root,spec);out.mkdir(parents=True,exist_ok=True)
    results=[];alerts=[]
    for case in cases:
        directory=out/(case['id']+'-'+uuid.uuid4().hex[:12]);directory.mkdir()
        item=_execute(root,spec,case,directory,compiler or 'gcc',timeout)
        (directory/'receipt.json').write_text(json.dumps(item,ensure_ascii=False,indent=2),encoding='utf-8')
        results.append(item)
        if item['status']=='FAIL':
            location=Location(case['source'],item['line'])
            alerts.append(Alert(RULE.rule_id,'business-contract',Severity.ERROR,
                '业务契约未满足：'+case['requirement'],location,
                provenance=Provenance.DETECTED,
                evidence=[Evidence('runtime','目标函数已执行，业务断言失败；见契约执行回执',location)],
                properties={'contract_id':case['id'],'contract_receipt':item,
                            'scope':'explicit tested inputs on native host'}))
    receipt=dict(schema_version=1,spec_sha256=hashlib.sha256(spec.read_bytes()).hexdigest(),
                 status_counts=dict(Counter(r['status'] for r in results)),results=results)
    (out/'contracts.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
    return receipt,alerts
