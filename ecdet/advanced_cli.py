"""Command entrypoints for explicit fuzzing, constraint, and firmware runs."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path

from ecdet.l2_ir import save_sarif
from ecdet.l2_ir.model import RuleMeta
from ecdet.l5_report import aggregate, build_compliance_records, render_html_report


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('Value must be a positive integer')
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('Value must be finite and positive')
    return number


def hex_bytes(value):
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Input must be hexadecimal bytes') from exc
    if len(data) > 4096:
        raise argparse.ArgumentTypeError('UART input exceeds 4096 bytes')
    return data


def write_reports(output, alerts, receipt, project):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rules = {}
    for alert in alerts:
        rules.setdefault(alert.rule_id, RuleMeta(
            alert.rule_id, 'ECDET', 'Required', 'tool-based', alert.rule_id,
            cwes=[alert.cwe] if alert.cwe else []))
    metas = list(rules.values())
    save_sarif(alerts, metas, output / 'results.sarif')
    result = aggregate(alerts, metas)
    render_html_report(result, build_compliance_records(result),
                       project_name=project, out_path=output / 'report.html')
    (output / 'analysis.json').write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')


def analyze_constraint_files(root, files, *, function=None, timeout_ms=1000):
    from ecdet.l3_analysis.constraints import analyze_constraints
    reports, alerts = [], []
    for relative in files:
        path = root / relative
        if path.suffix.lower() != '.c':
            continue
        report = analyze_constraints(path.read_text(encoding='utf-8', errors='replace'),
                                     path=relative.as_posix(), function=function,
                                     timeout_ms=timeout_ms)
        reports.append(report.to_dict())
        alerts.extend(report.alerts())
    counts = Counter()
    for report in reports:
        if report.get('results'):
            counts.update(item['status'] for item in report['results'])
            if report['status'] != 'COMPLETED':
                counts[report['status']] += 1
        else:
            counts[report['status']] += 1
    return {'backend': 'z3', 'files': reports, 'status_counts': dict(counts),
            'scope': 'Supported function-local C subset; UNSAT applies only to the recorded access and model.'}, alerts


def cmd_constraints(args):
    from ecdet.l3_analysis.engine import collect_sources
    target = Path(args.path).resolve()
    if not target.exists() or (target.is_file() and target.suffix.lower() != '.c'):
        print('错误：需要存在的C文件或工程目录')
        return 2
    root = target if target.is_dir() else target.parent
    files = collect_sources(root) if target.is_dir() else [Path(target.name)]
    receipt, alerts = analyze_constraint_files(root, files, function=args.function,
                                               timeout_ms=args.timeout_ms)
    output = Path(args.output).resolve() if args.output else root / 'ecdet_reports/constraints'
    write_reports(output, alerts, receipt, root.name)
    counts = receipt['status_counts']
    print(f"约束检查：{dict(counts)}；候选 {len(alerts)} 条；报告：{output}")
    if alerts:
        return 1
    return 0 if counts and set(counts) <= {'UNSAT'} else 2


def cmd_fuzz(args):
    from ecdet.l3_analysis.dynamic.libfuzzer import LibFuzzerEngine
    root = Path(args.path).resolve()
    if not root.is_dir():
        print('错误：工程目录不存在')
        return 2
    output = Path(args.output).resolve() if args.output else root / 'ecdet_reports/fuzz'
    engine = LibFuzzerEngine(clang=args.clang, runs=args.runs, timeout=args.timeout,
                            max_len=args.max_len)
    result = engine.run(root, Path(args.harness), output,
                        sources=[Path(p) for p in args.source],
                        corpus=[Path(p) for p in args.corpus])
    write_reports(output, result.alerts, result.to_dict(), root.name)
    print(f'模糊测试：{result.status}；动态发现 {len(result.alerts)} 条；报告：{output}')
    if result.alerts:
        return 1
    return 0 if result.status in {'PASS', 'COMPLETED', 'NO_FINDINGS'} else 2


def cmd_firmware(args):
    from ecdet.l3_analysis.dynamic.renode import RenodeRunner
    firmware = Path(args.firmware).resolve()
    output = Path(args.output).resolve() if args.output else firmware.parent / 'ecdet_reports/firmware'
    runner = RenodeRunner(binary=args.renode, timeout=args.timeout)
    result = runner.run(firmware, Path(args.platform).resolve(), output,
                        uart=args.uart, expected=args.expect,
                        failure_markers=args.failure_marker, virtual_seconds=args.seconds,
                        source_files=[Path(p).resolve() for p in args.source], uart_input=args.input_hex)
    alerts = result.alerts()
    write_reports(output, alerts, result.to_dict(), firmware.name)
    print(f'固件仿真：{result.status}；运行判据发现 {len(alerts)} 条；报告：{output}')
    return 1 if alerts else 0 if result.status == 'PASS' else 2


def register_commands(sub):
    parser = sub.add_parser('constraints', help='Z3验证受支持的C整数路径与数组边界')
    parser.add_argument('path', help='C文件或工程目录')
    parser.add_argument('--function', help='仅分析指定函数')
    parser.add_argument('--timeout-ms', type=positive_int, default=1000)
    parser.add_argument('--output', '-o', help='报告输出目录')
    parser.set_defaults(func=cmd_constraints)

    parser = sub.add_parser('fuzz', help='libFuzzer覆盖率引导的函数测试')
    parser.add_argument('path', help='工程根目录')
    parser.add_argument('--harness', required=True, help='LLVMFuzzerTestOneInput驱动文件')
    parser.add_argument('--source', action='append', default=[], help='额外链接的项目源文件，可重复')
    parser.add_argument('--corpus', action='append', default=[], help='初始语料文件或目录，可重复')
    parser.add_argument('--clang', help='Clang可执行文件路径')
    parser.add_argument('--runs', type=positive_int, default=5000)
    parser.add_argument('--timeout', type=positive_int, default=30, help='运行秒数上限')
    parser.add_argument('--max-len', type=positive_int, default=4096)
    parser.add_argument('--output', '-o', help='报告、语料和崩溃输入输出目录')
    parser.set_defaults(func=cmd_fuzz)

    parser = sub.add_parser('firmware', help='Renode加载并执行固件，采集独立串口日志')
    parser.add_argument('firmware', help='ELF固件路径')
    parser.add_argument('--platform', required=True, help='Renode平台描述REPL路径')
    parser.add_argument('--uart', default='sysbus.usart2')
    parser.add_argument('--input-hex', type=hex_bytes, default=b'', help='注入串口的十六进制字节，最多4096字节')
    parser.add_argument('--expect', action='append', default=[], help='必须出现的串口文本，可重复')
    parser.add_argument('--failure-marker', action='append', default=[], help='错误判据文本，可重复')
    parser.add_argument('--seconds', type=positive_float, default=0.1, help='虚拟执行时间')
    parser.add_argument('--timeout', type=positive_int, default=30, help='进程秒数上限')
    parser.add_argument('--renode', help='Renode可执行文件路径')
    parser.add_argument('--source', action='append', default=[], help='证据关联的源码路径，可重复')
    parser.add_argument('--output', '-o', help='固件日志与报告输出目录')
    parser.set_defaults(func=cmd_firmware)
