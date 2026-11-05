"""Build the local sample and emit an exact GCC compilation database."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    compiler = shutil.which(args.cc)
    if not compiler:
        raise SystemExit('Compiler not found: ' + args.cc)
    build = root / 'build'
    build.mkdir(exist_ok=True)
    sources = sorted((root / 'src').glob('*.c'))
    database = []
    objects = []
    logs = []
    for path in sources:
        obj = build / (path.stem + '.o')
        command = [compiler, '-std=c11', '-O0', '-g', '-Wall', '-Wextra',
                   '-Wpedantic', '-I', str(root / 'include'), '-c', str(path), '-o', str(obj)]
        database.append({'directory': str(root), 'file': str(path),
                         'arguments': command, 'output': str(obj)})
        objects.append(str(obj))
    (root / 'compile_commands.json').write_text(json.dumps(database, indent=2), encoding='utf-8')
    executable = build / ('spacecraft.exe' if os.name == 'nt' else 'spacecraft')
    commands = [row['arguments'] for row in database]
    commands.append([compiler, *objects, '-lm', '-o', str(executable)])
    for command in commands:
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, errors='replace')
        logs.append(json.dumps(command) + '\n' + result.stdout + result.stderr)
        if result.returncode:
            (build / 'build.log').write_text('\n'.join(logs), encoding='utf-8')
            sys.stdout.write(result.stdout + result.stderr)
            return result.returncode
    (build / 'build.log').write_text('\n'.join(logs), encoding='utf-8')
    print('BUILD PASS:', root.name)
    if args.run:
        result = subprocess.run([str(executable), '--self-check'], cwd=root,
                                capture_output=True, text=True, errors='replace')
        (build / 'nominal.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        print(result.stdout, end='')
        return result.returncode
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
