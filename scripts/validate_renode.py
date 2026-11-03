"""Compile and execute positive/negative Cortex-M4 UART fixtures in real Renode."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

PROJECT=Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path: sys.path.insert(0,str(PROJECT))
from ecdet.l3_analysis.dynamic.renode import RenodeRunner, rule_metas
from ecdet.l2_ir.sarif import save_sarif


def validate(output: Path, *, renode=None, clang=None) -> dict:
    output=output.resolve();output.mkdir(parents=True,exist_ok=True)
    compiler=clang or shutil.which('clang')
    receipt={'execution_mode':'renode-simulation','compiler':compiler,'cases':{}}
    if not compiler:
        receipt['status']='NOT_AVAILABLE'
        receipt['reason']='ARM-target-capable clang unavailable'
    else:
        fixture=PROJECT/'examples/renode_demo'
        for name,failure in [('good',False),('bad',True)]:
            case=output/name;case.mkdir(exist_ok=True)
            elf=case/'firmware.elf'
            command=[compiler,'--target=arm-none-eabi','-mcpu=cortex-m4','-mthumb',
                     '-nostdlib','-ffreestanding','-fno-builtin','-fuse-ld=lld','-O1','-g',
                     '-Wl,-T,'+str(fixture/'link.ld'),str(fixture/'firmware.c'),'-o',str(elf)]
            if failure:command.insert(1,'-DINJECT_FAILURE=1')
            try:
                built=subprocess.run(command,capture_output=True,encoding='utf-8',errors='replace',timeout=45)
                (case/'build.log').write_text(built.stdout+built.stderr,encoding='utf-8')
                entry={'compile_command':command,'compile_returncode':built.returncode}
                if not built.returncode:
                    result=RenodeRunner(renode,timeout=30).run(elf,fixture/'stm32f4_minimal.repl',case,
                        expected=['ECDET_BOOT_OK','ECDET_STATUS_OK'],
                        failure_markers=['ECDET_SELFTEST_FAIL'],uart_input=b's',
                        source_files=[fixture/'firmware.c',fixture/'link.ld'])
                    entry['result']=result.to_dict()
                    save_sarif(result.alerts(),rule_metas(),case/'results.sarif')
                receipt['cases'][name]=entry
            except (OSError,subprocess.TimeoutExpired) as exc:
                receipt['cases'][name]={'status':'ERROR','error_type':type(exc).__name__}
        good=receipt['cases'].get('good',{}).get('result',{})
        bad=receipt['cases'].get('bad',{}).get('result',{})
        receipt['status']='PASS' if good.get('status')=='PASS' and bad.get('status')=='FAIL' and bad.get('observed_failures') else 'FAIL'
    receipt['fixture_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (PROJECT/'examples/renode_demo').iterdir() if p.is_file()}
    (output/'validation.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--renode');parser.add_argument('--clang')
    args=parser.parse_args()
    receipt=validate(args.output_dir,renode=args.renode,clang=args.clang)
    print(json.dumps({'status':receipt['status'],'cases':{
        name:case.get('result',{}).get('status','NOT_RUN') for name,case in receipt['cases'].items()}}))
    return 0 if receipt['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
