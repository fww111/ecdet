"""Create full-project repaired controls without changing defective fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(output,compiler='gcc'):
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    binary=shutil.which(compiler)
    if not binary:raise RuntimeError('Native compiler unavailable: '+compiler)
    base=ROOT/'examples/spacecraft_suite'
    manifest=json.loads((base/'manifest.json').read_text(encoding='utf-8'))
    changes=json.loads((base/'reference_changes.json').read_text(encoding='utf-8'))
    projects={p['name']:p for p in manifest['projects']};receipts=[]
    for name,patches in changes.items():
        original=ROOT/projects[name]['path'];target=output/name
        if target.exists():raise ValueError('Refusing to overwrite existing control: '+str(target))
        expected=projects[name]['normalized_source_sha256']
        assert all(hashlib.sha256((original/n).read_bytes().replace(b'\r\n',b'\n')).hexdigest()==h for n,h in expected.items())
        before={n:digest(original/n) for n in expected}
        for relative in [*expected,'CMakeLists.txt']:
            source=original/relative;destination=target/relative
            destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,destination)
        for patch in patches:
            path=(target/patch['file']).resolve()
            assert path.is_relative_to(target),patch['file']
            text=path.read_text(encoding='utf-8')
            assert text.count(patch['before'])==1,patch['id']
            path.write_text(text.replace(patch['before'],patch['after']),encoding='utf-8')
        assert all(digest(original/n)==h for n,h in before.items()),'Original fixture changed'
        entries=[dict(directory=str(target),file=str(p),arguments=[binary,'-std=c99','-I'+str(target/'include'),'-c',str(p)])
                 for p in sorted((target/'src').glob('*.c'))]
        database=target/'ecdet_build/compile_commands.json';database.parent.mkdir()
        database.write_text(json.dumps(entries,indent=2),encoding='utf-8')
        receipt=dict(project=name,applied=[p['id'] for p in patches],
                     original_source_sha256=before,reference_source_sha256={n:digest(target/n) for n in expected},
                     manifest_sha256=digest(base/'manifest.json'),patches_sha256=digest(base/'reference_changes.json'))
        (target/'reference_preparation.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
        receipts.append(receipt);print(name,len(patches),flush=True)
    (output/'preparation.json').write_text(json.dumps(receipts,ensure_ascii=False,indent=2),encoding='utf-8')
    return receipts


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    parser.add_argument('--compiler',default='gcc');args=parser.parse_args()
    prepare(args.output,args.compiler)
