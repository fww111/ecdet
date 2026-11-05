"""Reproduce six business misses and their guarded controls from this checkout."""
import argparse
import json
from pathlib import Path
import shutil
import sys

BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent.parent))
from ecdet.l3_analysis.business_contracts import run_contracts


def verify(out,compiler='gcc'):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    changes=json.loads((BASE/'reference_changes.json').read_text(encoding='utf-8'))
    rows=[]
    for project,patches in changes.items():
        source=BASE/'projects'/project
        reference=out/'reference'/project
        shutil.copytree(source,reference,dirs_exist_ok=True)
        for patch in patches:
            path=reference/patch['file'];text=path.read_text(encoding='utf-8')
            assert text.count(patch['before'])==1,patch['id']
            path.write_text(text.replace(patch['before'],patch['after']),encoding='utf-8')
        for variant,root in [('original',source),('reference',reference)]:
            receipt,alerts=run_contracts(root,BASE/'contracts'/project/'contracts.json',
                                        out/project/variant,compiler=compiler)
            rows.extend(dict(project=project,variant=variant,**r) for r in receipt['results'])
            print(project,variant,receipt['status_counts'],flush=True)
    (out/'pairs.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
    return rows


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--compiler',default='gcc');args=parser.parse_args()
    rows=verify(args.output,args.compiler)
    raise SystemExit(0 if len(rows)==12 and all(r['status']==('FAIL' if r['variant']=='original' else 'PASS') for r in rows) else 1)
