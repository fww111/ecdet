"""Validated web jobs for the three optional analysis backends."""
from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path
import re

from ecdet.advanced_cli import analyze_constraint_files, write_reports
from ecdet.l3_analysis.dynamic.libfuzzer import LibFuzzerEngine, discover_clang
from ecdet.l3_analysis.dynamic.renode import RenodeRunner, find_renode
from ecdet.l3_analysis.engine import collect_sources
from ecdet.l5_report import aggregate


LABELS = {
    'PASS':'当前检查通过', 'FINDING':'发现可复核结果', 'COMPLETED':'预算内测试完成',
    'FAIL':'运行判据未满足', 'PARTIAL':'部分检查未完成', 'UNKNOWN':'求解未得到确定结果',
    'UNSUPPORTED':'当前输入不受支持', 'UNAVAILABLE':'工具或依赖不可用',
    'ERROR':'执行错误', 'TIMEOUT':'执行超时', 'COMPILE_ERROR':'编译失败',
    'UNVERIFIED':'错误未通过重放确认', 'INVALID_INPUT':'输入文件或参数无效',
}
COMPLETED_STATES = {'PASS','FINDING','COMPLETED','FAIL','PARTIAL'}


def _integer(data, name, default, low, high):
    value = data.get(name, default)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{name}须为{low}至{high}之间的整数')
    return value


def _number(data, name, default, low, high):
    value = data.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int,float)) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError(f'{name}须为{low}至{high}之间的有限数值')
    return value


def _string(data, name, default='', limit=2048):
    value = data.get(name, default)
    if not isinstance(value, str) or len(value)>limit or any(c in value for c in '\x00\r\n'):
        raise ValueError(f'{name}须为有效的单行文本')
    return value.strip()


def _list(data, name, *, markers=False):
    value=data.get(name, [])
    if not isinstance(value,list) or len(value)>128:
        raise ValueError(f'{name}须为不超过128项的数组')
    result=[]
    for item in value:
        text=_string({'item':item},'item',limit=1024 if markers else 2048)
        if not text:
            raise ValueError(f'{name}不能包含空项')
        result.append(text)
    return result


def project_path(root: Path, value: str, *, suffixes=None, directory=False) -> Path:
    root=Path(root).resolve()
    path=Path(value)
    path=(root/path).resolve() if not path.is_absolute() else path.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError('输入文件须位于注册工程目录中') from exc
    if not value or not path.exists() or (not directory and not path.is_file()):
        raise ValueError('输入文件或目录不存在')
    if suffixes and path.suffix.lower() not in suffixes:
        raise ValueError('输入文件类型不匹配')
    return path


def normalize_request(root: Path, data) -> dict:
    if not isinstance(data,dict):
        raise ValueError('分析参数须为JSON对象')
    kind=data.get('kind')
    if not isinstance(kind,str) or kind not in {'constraints','fuzz','firmware'}:
        raise ValueError('请选择有效的分析功能')
    root=Path(root).resolve()
    result={'kind':kind}
    def relative(value, **kwargs):
        return project_path(root,value,**kwargs).relative_to(root).as_posix()
    if kind=='constraints':
        result['source']=_string(data,'source')
        if result['source']:
            result['source']=relative(result['source'],suffixes={'.c'})
        result['function']=_string(data,'function',limit=128)
        if result['function'] and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',result['function']):
            raise ValueError('函数名须为有效的C标识符')
        result['timeout_ms']=_integer(data,'timeout_ms',1000,1,10000)
    elif kind=='fuzz':
        result['harness']=relative(_string(data,'harness'),suffixes={'.c','.cc','.cpp','.cxx'})
        result['sources']=[relative(p,suffixes={'.c','.cc','.cpp','.cxx'}) for p in _list(data,'sources')]
        result['corpus']=[relative(p,directory=True) for p in _list(data,'corpus')]
        result['runs']=_integer(data,'runs',5000,1,1000000)
        result['timeout']=_integer(data,'timeout',30,1,300)
        result['max_len']=_integer(data,'max_len',4096,1,1048576)
    else:
        result['firmware']=relative(_string(data,'firmware'),suffixes={'.elf'})
        with (root/result['firmware']).open('rb') as stream:
            elf_header=stream.read(4)
        if elf_header!=b'\x7fELF':
            raise ValueError('固件文件须为ELF格式')
        result['platform']=relative(_string(data,'platform'),suffixes={'.repl'})
        result['uart']=_string(data,'uart','sysbus.usart2',128)
        if not re.fullmatch(r'sysbus\.[A-Za-z_][A-Za-z0-9_.]*',result['uart']):
            raise ValueError('UART标识无效')
        result['input_hex']=_string(data,'input_hex',limit=12288)
        try:
            raw=bytes.fromhex(result['input_hex'])
        except ValueError as exc:
            raise ValueError('串口输入须为十六进制字节') from exc
        if len(raw)>4096:
            raise ValueError('串口输入不能超过4096字节')
        result['input_hex']=raw.hex()
        result['expected']=_list(data,'expected',markers=True)
        result['failure_markers']=_list(data,'failure_markers',markers=True)
        if not result['expected'] and not result['failure_markers']:
            raise ValueError('至少提供一项预期输出或失败标记')
        result['seconds']=_number(data,'seconds',.1,.001,30)
        result['timeout']=_integer(data,'timeout',30,1,300)
        result['sources']=[relative(p) for p in _list(data,'sources')]
    return result


def constraint_status(counts: dict) -> str:
    if counts.get('ERROR'):return 'ERROR'
    if counts.get('UNAVAILABLE'):return 'UNAVAILABLE'
    supported=counts.get('SAT',0)+counts.get('UNSAT',0)
    incomplete=set(counts)-{'SAT','UNSAT'}
    if supported and incomplete:return 'PARTIAL'
    if not supported:
        return 'UNKNOWN' if counts.get('UNKNOWN') else 'UNSUPPORTED'
    return 'FINDING' if counts.get('SAT') else 'PASS'


def tool_settings(store) -> dict:
    cfg=store.get_settings()
    return {'clang_path':cfg.get('analysis_clang',''),'renode_path':cfg.get('analysis_renode','')}


def save_tool_settings(store, data) -> dict:
    if not isinstance(data,dict):raise ValueError('工具设置须为JSON对象')
    if set(data)-{'clang_path','renode_path'}:raise ValueError('存在未知工具设置')
    selected={key:_string(data,key) for key in data}
    for key,value in selected.items():
        store.set_setting('analysis_clang' if key=='clang_path' else 'analysis_renode',value)
    return tool_settings(store)


def tools_view(store) -> dict:
    cfg=tool_settings(store)
    try:
        solver=all(importlib.util.find_spec(name) is not None for name in ['z3','tree_sitter','tree_sitter_c'])
    except (ImportError,ValueError):
        solver=False
    compiler=discover_clang(cfg['clang_path'] or None)
    renode=find_renode(cfg['renode_path'] or None)
    return {**cfg,'tools':{
        'constraints':{'available':solver,'note':'依赖已安装' if solver else '请安装constraints扩展'},
        'fuzz':{'available':bool(compiler),'note':'已找到Clang，运行支持将在任务中验证' if compiler else '请配置Clang路径'},
        'firmware':{'available':bool(renode),'note':'已找到Renode' if renode else '请配置Renode路径'}}}


def artifact_path(output: Path, relative: str) -> Path:
    if not isinstance(relative,str) or not relative or Path(relative).is_absolute():
        raise ValueError('请提供运行产物的相对路径')
    output=Path(output).resolve()
    path=(output/relative).resolve()
    try:path.relative_to(output)
    except ValueError as exc:raise ValueError('文件不在运行目录中') from exc
    if not path.is_file():raise ValueError('运行产物不存在')
    return path


def _artifacts(output):
    files=[p for p in sorted(output.rglob('*')) if p.is_file() and p.suffix.lower() not in {'.exe','.dll'}]
    files.sort(key=lambda p:(p.suffix not in {'.log','.json','.sarif','.html','.resc'},len(p.parts),str(p)))
    result=[]
    for path in files:
        try:
            if path.resolve().is_relative_to(output.resolve()):
                result.append({'name':path.name,'path':path.relative_to(output).as_posix()})
        except OSError:continue
        if len(result)>=256:break
    return result


def execute_analysis(store, data_dir: Path, run_id: int) -> None:
    run=store.get_run(run_id)
    project=store.get_project(run['project_id'])
    root=Path(project['workspace']).resolve()
    output=Path(data_dir)/'runs'/str(run_id)
    output.mkdir(parents=True,exist_ok=True)
    store.set_run_status(run_id,'running',out_dir=str(output))
    options=run['params']['analysis']
    kind=options['kind']
    alerts=[]
    details={}
    summary={}
    try:
        # Inputs may have changed while queued; repeat the same validation.
        options=normalize_request(root,options)
        settings=tool_settings(store)
        if kind=='constraints':
            files=[Path(options['source'])] if options['source'] else collect_sources(root)
            details,alerts=analyze_constraint_files(root,files,function=options['function'] or None,timeout_ms=options['timeout_ms'])
            status=constraint_status(details['status_counts'])
            summary['status_counts']=details['status_counts']
            summary['scope']='UNSAT仅对应所列局部模型；未完成项单独显示'
        elif kind=='fuzz':
            engine=LibFuzzerEngine(clang=settings['clang_path'] or None,runs=options['runs'],
                timeout=options['timeout'],max_len=options['max_len'])
            result=engine.run(root,Path(options['harness']),output,
                sources=[Path(p) for p in options['sources']],corpus=[Path(p) for p in options['corpus']])
            details=result.to_dict();alerts=result.alerts;status=result.status
            coverage=result.metadata.get('coverage',{})
            summary.update(coverage=coverage,executions=coverage.get('executed_units'),reason=result.reason)
        else:
            result=RenodeRunner(binary=settings['renode_path'] or None,timeout=options['timeout']).run(
                root/options['firmware'],root/options['platform'],output,uart=options['uart'],
                expected=options['expected'],failure_markers=options['failure_markers'],
                virtual_seconds=options['seconds'],source_files=[root/p for p in options['sources']],
                uart_input=bytes.fromhex(options['input_hex']))
            details=result.to_dict();alerts=result.alerts()
            status='UNAVAILABLE' if result.status=='NOT_AVAILABLE' else result.status
            summary.update(missing_expected=result.missing_expected,observed_failures=result.observed_failures,
                           reason=result.reason,execution_mode=result.execution_mode)
    except Exception as exc:
        status='ERROR';details={'error_type':type(exc).__name__,'reason':str(exc)}
        summary['reason']=str(exc)
    summary.update(label=LABELS.get(status,status),alerts=len(alerts),alert_count=len(alerts))
    payload={'kind':kind,'status':status,'summary':summary,'details':details,'artifacts':[]}
    write_reports(output,alerts,payload,project['name'])
    payload['artifacts']=_artifacts(output)
    (output/'analysis.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
    rows=[]
    for alert in alerts:
        rows.append({'rule_id':alert.rule_id,'engine':alert.engine,'severity':alert.severity.value,
            'path':alert.location.path,'line':alert.location.line,'message':alert.message,
            'cwe':alert.cwe,'provenance':alert.provenance.value,'triage':alert.triage,
            'fingerprint':alert.ensure_fingerprint(),'evidence':[
                {'kind':e.kind,'message':e.message,'path':e.location.path if e.location else '',
                 'line':e.location.line if e.location else None} for e in alert.evidence]})
    store.put_alerts(run_id,rows)
    from ecdet.webui.snapshot import create_snapshot
    snapshot=create_snapshot(data_dir,run_id,root)
    stats=dict(aggregate(alerts,[]).stats)
    stats.update(analysis={'kind':kind,'status':status,'summary':summary},snapshot=snapshot,
                 files=len(collect_sources(root)),out_dir=str(output),warnings=[])
    done=status in COMPLETED_STATES
    store.set_run_status(run_id,'done' if done else 'failed',stats=stats,
                         error=None if done else summary.get('reason') or summary['label'],out_dir=str(output))
