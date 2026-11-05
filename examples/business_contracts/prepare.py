"""Create native compile databases for the bundled host-executable fixtures."""
import argparse
import json
from pathlib import Path
import shutil


def prepare(compiler='gcc'):
    executable=shutil.which(compiler)
    if not executable:raise RuntimeError('Native compiler unavailable: '+compiler)
    base=Path(__file__).resolve().parent/'projects'
    for project in sorted(base.iterdir()):
        if not project.is_dir():continue
        entries=[dict(directory=str(project),file=str(p),arguments=[executable,'-std=c11',
                 '-I'+str(project/'include'),'-c',str(p)]) for p in sorted((project/'src').glob('*.c'))]
        destination=project/'ecdet_build/compile_commands.json'
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(entries,indent=2),encoding='utf-8')
        print(destination)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--compiler',default='gcc')
    prepare(parser.parse_args().compiler)
