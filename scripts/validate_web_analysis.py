"""Exercise all three analysis backends through a real loopback HTTP server."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ecdet.webui import WebUI


def validate(output_dir: Path, *, clang: str, renode: str) -> dict:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    session = output_dir / ('session-' + uuid.uuid4().hex[:12])
    session.mkdir()
    receipt = {'status': 'ERROR', 'mode': 'real-http-real-backends',
               'session': str(session), 'cases': [], 'requests': [],
               'model_calls': 0, 'user_settings_used': False}
    httpd = None
    ui = None
    try:
        if os.name == 'nt':
            ctypes.windll.kernel32.SetErrorMode(3)
        if not Path(clang).is_file() or not Path(renode).is_file():
            receipt['status'] = 'NOT_AVAILABLE'
            raise RuntimeError('Explicit Clang and Renode executables are required')
        fixtures = session / 'fixtures'
        fixtures.mkdir()
        for name, example in [('constraints', 'constraints_demo'),
                              ('fuzz', 'libfuzzer_demo'), ('firmware', 'renode_demo')]:
            shutil.copytree(REPO/'examples'/example, fixtures/name)
        firmware_root = fixtures/'firmware'
        receipt['builds'] = {}
        for label in ['good', 'bad']:
            elf = firmware_root/(label+'.elf')
            command = [clang, '--target=arm-none-eabi', '-mcpu=cortex-m4', '-mthumb',
                       '-nostdlib', '-ffreestanding', '-fno-builtin', '-fuse-ld=lld', '-O1', '-g',
                       '-Wl,-T,'+str(firmware_root/'link.ld'), str(firmware_root/'firmware.c'),
                       '-o', str(elf)]
            if label == 'bad':
                command.insert(1, '-DINJECT_FAILURE=1')
            built = subprocess.run(command, capture_output=True, encoding='utf-8',
                                   errors='replace', timeout=45)
            (session/(label+'-build.log')).write_text(built.stdout+built.stderr, encoding='utf-8')
            receipt['builds'][label] = {'command': command, 'exit_code': built.returncode}
            assert built.returncode == 0, f'{label} firmware compilation failed'
        (fixtures/'fuzz/seed.bin').write_bytes(bytes([0xa5, 0]))

        ui = WebUI(session/'data', port=0)
        httpd = ui.make_server()
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        base = 'http://127.0.0.1:' + str(httpd.server_address[1])
        receipt['origin'] = base
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def request(method, path, payload=None, *, raw=None):
            data = raw if raw is not None else (json.dumps(payload).encode('utf-8')
                                               if payload is not None else None)
            req = urllib.request.Request(base+path, data=data, method=method,
                                         headers={'Content-Type': 'application/json'})
            try:
                response = opener.open(req, timeout=15)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                body = response.read()
                status = response.code
                ctype = response.headers.get('Content-Type', '')
            receipt['requests'].append({'method': method, 'path': path, 'status': status,
                                        'bytes': len(body)})
            return status, body, ctype

        def json_request(method, path, payload=None, *, code=200, raw=None):
            status, body, _ = request(method, path, payload, raw=raw)
            assert status == code, (path, status, body.decode('utf-8', errors='replace')[:500])
            return json.loads(body.decode('utf-8'))

        original_settings = json_request('GET', '/api/settings')
        configured = json_request('POST', '/api/analysis-tools/settings',
                                  {'clang_path': clang, 'renode_path': renode})
        receipt['configured_tool_paths'] = configured
        tools = json_request('GET', '/api/analysis-tools')
        receipt['tool_probe'] = tools
        assert all(tools['tools'][name]['available'] for name in ['constraints', 'fuzz', 'firmware'])
        assert json_request('GET', '/api/settings') == original_settings
        projects = {}
        for kind in ['constraints', 'fuzz', 'firmware']:
            projects[kind] = json_request('POST', '/api/projects', {
                'name': 'HTTP '+kind, 'source_type': 'path', 'path': str(fixtures/kind)})['project_id']

        def wait_run(run_id):
            deadline = time.monotonic()+90
            while time.monotonic() < deadline:
                run = json_request('GET', '/api/runs/'+str(run_id))
                if run['status'] in {'done', 'failed'}:
                    return run
                time.sleep(0.15)
            raise TimeoutError(f'Run {run_id} did not reach a terminal state')

        def run_case(name, kind, options, expected_status, expected_alerts,
                     *, expected_run='done', expected_provenance=None):
            run_id = json_request('POST', f'/api/projects/{projects[kind]}/analyze',
                                  {'kind': kind, **options})['run_id']
            run = wait_run(run_id)
            analysis = json_request('GET', f'/api/runs/{run_id}/analysis')
            assert run['status'] == expected_run, (name, run)
            assert analysis['status'] == expected_status, (name, analysis)
            alerts = json_request('GET', f'/api/runs/{run_id}/alerts')['alerts']
            assert len(alerts) == expected_alerts, (name, alerts)
            if expected_provenance:
                assert all(a['provenance'] == expected_provenance for a in alerts), name
            assert run['stats']['analysis']['status'] == expected_status
            status, sarif_bytes, _ = request('GET', f'/api/runs/{run_id}/sarif')
            assert status == 200
            sarif = json.loads(sarif_bytes)
            assert all(r['ruleIndex'] is not None for r in sarif['runs'][0]['results']), name
            status, html, ctype = request('GET', f'/api/runs/{run_id}/report')
            assert status == 200 and b'<html' in html.lower() and 'text/html' in ctype
            artifacts = []
            for artifact in analysis.get('artifacts', [])[:12]:
                path = str(artifact['path'])
                status, body, _ = request('GET', f'/api/runs/{run_id}/artifact?path='+
                                           urllib.parse.quote(path, safe=''))
                assert status == 200, (name, path, status)
                artifacts.append({'path': path, 'bytes': len(body),
                                  'sha256': hashlib.sha256(body).hexdigest()})
            assert artifacts, (name, 'No downloadable artifacts')
            case = {'name': name, 'kind': kind, 'run_id': run_id, 'run_status': run['status'],
                    'backend_status': analysis['status'], 'alert_count': len(alerts),
                    'provenance': [a['provenance'] for a in alerts],
                    'summary': analysis['summary'], 'downloaded_artifacts': artifacts}
            receipt['cases'].append(case)
            (session/(name+'-analysis.json')).write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding='utf-8')
            (session/(name+'.sarif')).write_bytes(sarif_bytes)
            return run_id

        run_case('constraints_bad', 'constraints', {'function': 'missing_lower_guard'},
                 'FINDING', 1, expected_provenance='suspected')
        run_case('constraints_good', 'constraints', {'function': 'guarded_index'}, 'PASS', 0)
        run_case('constraints_partial', 'constraints', {}, 'PARTIAL', 2,
                 expected_provenance='suspected')
        fuzz_options = {'harness': 'harness.c', 'runs': 5000, 'timeout': 20,
                        'max_len': 64, 'corpus': ['seed.bin']}
        run_case('fuzz_bad', 'fuzz', {**fuzz_options, 'sources': ['packet_bad.c']},
                 'FINDING', 1, expected_provenance='detected')
        last_run = run_case('fuzz_fixed', 'fuzz', {**fuzz_options, 'sources': ['packet_fixed.c']},
                            'COMPLETED', 0)
        firmware_options = {'platform': 'stm32f4_minimal.repl', 'uart': 'sysbus.usart2',
                            'input_hex': '73', 'expected': ['ECDET_BOOT_OK', 'ECDET_STATUS_OK'],
                            'failure_markers': ['ECDET_SELFTEST_FAIL'], 'sources': ['firmware.c'],
                            'seconds': 0.1, 'timeout': 30}
        run_case('firmware_good', 'firmware', {**firmware_options, 'firmware': 'good.elf'}, 'PASS', 0)
        run_case('firmware_bad', 'firmware', {**firmware_options, 'firmware': 'bad.elf'},
                 'FAIL', 1, expected_provenance='detected')
        json_request('POST', '/api/analysis-tools/settings', {
            'clang_path': str(session/'missing-clang.exe'), 'renode_path': renode})
        run_case('missing_clang', 'fuzz', {**fuzz_options, 'sources': ['packet_fixed.c']},
                 'UNAVAILABLE', 0, expected_run='failed')
        json_request('POST', '/api/analysis-tools/settings', {'clang_path': clang, 'renode_path': renode})
        run_case('after_failed_job', 'constraints', {'function': 'guarded_index'}, 'PASS', 0)
        bad_inputs = [
            ('escape_source', 'fuzz', {**fuzz_options, 'harness': '../outside.c'}),
            ('bad_budget', 'fuzz', {**fuzz_options, 'runs': True}),
            ('bad_hex', 'firmware', {**firmware_options, 'firmware': 'good.elf', 'input_hex': 'zz'}),
            ('unknown_kind', 'constraints', {'kind': 'unknown'}),
        ]
        receipt['rejections'] = []
        for name, kind, options in bad_inputs:
            status, body, _ = request('POST', f'/api/projects/{projects[kind]}/analyze',
                                      {'kind': kind, **options})
            assert status == 400, (name, status, body[:300])
            receipt['rejections'].append({'name': name, 'http_status': status})
        json_request('POST', f'/api/projects/{projects["fuzz"]}/analyze', code=400, raw=b'{invalid json')
        code, _, _ = request('GET', f'/api/runs/{last_run}/artifact?path=../outside')
        assert code in {400, 403, 404}, ('artifact traversal', code)
        receipt['rejections'].append({'name': 'artifact_escape', 'http_status': code})
        assert json_request('GET', '/api/settings') == original_settings
        receipt['status'] = 'PASS'
    except Exception as exc:
        receipt['error_type'] = type(exc).__name__
        receipt['error'] = str(exc)[:3000]
    finally:
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if ui is not None:
            ui.store._conn.close()
        (session/'validation.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
        (output_dir/'validation.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--clang', required=True)
    parser.add_argument('--renode', required=True)
    args = parser.parse_args()
    result = validate(args.output_dir, clang=str(Path(args.clang).resolve()),
                      renode=str(Path(args.renode).resolve()))
    print(json.dumps({'status': result['status'], 'session': result['session'],
                      'cases': [{k: c[k] for k in ('name', 'run_status', 'backend_status', 'alert_count')}
                                for c in result['cases']],
                      **{key: result[key] for key in ['error_type', 'error'] if key in result}}, ensure_ascii=False))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
