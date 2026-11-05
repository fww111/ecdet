"""Generate native compile databases for the eight reviewed projects."""
import argparse,json,shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def prepare(compiler='gcc'):
    binary=shutil.which(compiler)
    if not binary:raise RuntimeError('Native compiler unavailable: '+compiler)
    manifest=json.loads((ROOT/'examples/spacecraft_suite/manifest.json').read_text(encoding='utf-8'))
    for project in manifest['projects']:
        root=ROOT/project['path']
        entries=[dict(directory=str(root),file=str(p),arguments=[binary,'-std=c99','-I'+str(root/'include'),'-c',str(p)]) for p in sorted(root.glob('src/*.c'))]
        out=root/'ecdet_build/compile_commands.json';out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(entries,indent=2),encoding='utf-8')
        print(project['name'],len(entries))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--compiler',default='gcc');args=parser.parse_args();prepare(args.compiler)
