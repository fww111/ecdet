"""Compile-database-backed preprocessing for the restricted local Z3 model.

The compiler selects includes/macros and validates C syntax. Z3 still models
only the explicitly supported local integer subset, never external state.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from .constraints import ConstraintReport, _Function, _Unsupported, _walk


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _database(root):
    for relative in ('compile_commands.json','ecdet_build/compile_commands.json','build/compile_commands.json'):
        path=root/relative
        if path.is_file():return path
    return None


def _flags(entry, source):
    argv=entry.get('arguments')
    if argv is None:
        argv=shlex.split(entry.get('command',''),posix=False)
        argv=[a[1:-1] if len(a)>1 and a[0]==a[-1]=='"' else a for a in argv]
    if not isinstance(argv,list) or not argv or not all(isinstance(a,str) for a in argv):
        raise _Unsupported('Invalid compilation database arguments')
    cwd=Path(entry['directory']).resolve()
    compiler=shutil.which(argv[0]) or (str((cwd/argv[0]).resolve()) if (cwd/argv[0]).is_file() else None)
    if not compiler:raise FileNotFoundError('Compilation database compiler unavailable')
    args=[];skip=False
    for arg in argv[1:]:
        if skip:skip=False;continue
        if arg in ('-o','-MF','-MT','-MQ'):skip=True;continue
        if arg in ('-c','-S','-E','-MD','-MMD','-MP'):continue
        if arg.startswith(('-o','-MF','-MT','-MQ')):continue
        if not arg.startswith('-') and (cwd/arg).resolve()==source:continue
        if arg.startswith('@') or arg in ('--','-x') or arg.startswith(('-save-temps','-fplugin','-specs','--specs')):
            raise _Unsupported('Unsupported compiler argument for isolated preprocessing: '+arg)
        args.append(arg)
    return compiler,cwd,args


def _line_map(preprocessed,cwd):
    mapping=[];lines=[];file=None;line=0;dependencies=set()
    for text in preprocessed.splitlines(keepends=True):
        marker=re.match(r'^#\s+(\d+)\s+"((?:\\.|[^"\\])*)"',text)
        if marker:
            name=marker[2].replace('\\\\','\\').replace('\\"','"')
            file=(cwd/name).resolve() if not name.startswith('<') else None
            line=int(marker[1]);lines.append('\n');mapping.append(None)
            if file and file.is_file():dependencies.add(file)
        else:
            mapping.append((file,line));line+=1;lines.append(text)
    return ''.join(lines),mapping,dependencies


def analyze_translation_unit(root,relative,*,function=None,timeout_ms=1000):
    root=Path(root).resolve();source=(root/relative).resolve();path=Path(relative).as_posix()
    original=source.read_text(encoding='utf-8');sha=hashlib.sha256(original.encode()).hexdigest()
    database=_database(root)
    if database is None:
        from .constraints import analyze_constraints
        report=analyze_constraints(original,path,function=function,timeout_ms=timeout_ms)
        report.context={'preprocessing':'not performed','reason':'Compilation database unavailable'}
        return report
    report=ConstraintReport('UNSUPPORTED',path,sha)
    report.context={'preprocessing':'not completed','compile_database_sha256':_digest(database)}
    try:
        import z3
        from tree_sitter import Language,Parser
        import tree_sitter_c
        entries=json.loads(database.read_text(encoding='utf-8'))
        selected=[e for e in entries if (Path(e['directory'])/e['file']).resolve()==source]
        if len(selected)!=1:raise _Unsupported('Expected one unambiguous compile configuration for source')
        compiler,cwd,args=_flags(selected[0],source)
        context=report.context
        context['compiler']=compiler
        before={p:_digest(p) for p in [source,database,*root.rglob('*.h')]}
        def execute(flags):
            command=[compiler,*args,*flags,str(source)]
            proc=subprocess.run(command,cwd=cwd,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
            if proc.returncode:
                report.status='ERROR';context['compiler_returncode']=proc.returncode
                # Full diagnostics can include source literals; record status without logging those values.
                raise _Unsupported('Compiler validation/preprocessing failed')
            return proc.stdout
        execute(['-fsyntax-only'])
        macros=execute(['-E','-dM'])
        definitions={k:v.strip() for k,v in re.findall(r'^#define[ \t]+(\w+)[ \t]+([^\r\n]+)',macros,re.M)}
        if any(definitions.get(k)!=v for k,v in {'__CHAR_BIT__':'8','__SIZEOF_SHORT__':'2','__SIZEOF_INT__':'4'}.items()):
            raise _Unsupported('Compiler target does not match the 8/16/32-bit local integer model')
        text=execute(['-E'])
        if len(text.encode())>8*1024*1024:raise _Unsupported('Preprocessed translation unit exceeds 8 MiB budget')
        expanded,mapping,dependencies=_line_map(text,cwd)
        # Parse only active source lines. System-header bodies may use compiler
        # extensions; the separate map retains each original source line.
        selected=[(line,origin) for line,origin in zip(expanded.splitlines(keepends=True),mapping)
                  if origin and origin[0]==source]
        selected_text=''.join(line for line,_ in selected)
        mapping=[origin for _,origin in selected]
        raw=selected_text.encode();language=Language(tree_sitter_c.language())
        parser=Parser(language);tree=parser.parse(raw)
        context.update(preprocessing='complete',preprocessed_sha256=hashlib.sha256(expanded.encode()).hexdigest(),
                       target_macros={k:definitions[k] for k in ('__CHAR_BIT__','__SIZEOF_SHORT__','__SIZEOF_INT__')},
                       input_sha256={p.relative_to(root).as_posix() if p.is_relative_to(root) else str(p):_digest(p) for p in dependencies|{database}})
        if any(_digest(p)!=h for p,h in before.items()):raise _Unsupported('Source/header/compile database changed during preprocessing')
        # Canonical compiler-validated typedefs, rather than assumptions from names.
        aliases={};ambiguous=set()
        for value,name in re.findall(r'(?m)^[ \t]*typedef[ \t]+([A-Za-z_][A-Za-z0-9_ \t]*)[ \t]+([A-Za-z_]\w*)[ \t]*;',expanded):
            value=' '.join(value.split())
            if name in aliases and aliases[name]!=value:ambiguous.add(name)
            aliases[name]=value
        class Function(_Function):
            def ctype(self,name):
                seen=set()
                while name in aliases:
                    if name in seen or name in ambiguous:raise _Unsupported('Ambiguous typedef: '+name)
                    seen.add(name);name=aliases[name]
                if re.fullmatch(r'u?int(?:8|16|32)_t',name):raise _Unsupported('Unresolved fixed-width typedef: '+name)
                return super().ctype(name)
        funcs=[]
        for node in tree.root_node.named_children:
            if node.type!='function_definition':continue
            start=mapping[node.start_point.row]
            if not start or start[0]!=source:continue
            decl=node.child_by_field_name('declarator');name=decl.child_by_field_name('declarator') if decl else None
            name=raw[name.start_byte:name.end_byte].decode() if name else ''
            if function is None or function==name:funcs.append((node,name))
        if len(funcs)>64 or len({name for _,name in funcs})!=len(funcs):raise _Unsupported('Function identity/count budget unsupported')
        if function is not None and not funcs:raise _Unsupported('Requested function not found in active compiler configuration')
        report.status='COMPLETED';report.solver_version=z3.get_version_string()
        for node,name in funcs:
            analyzer=Function(z3,raw,path,node,sha,timeout_ms,0);analyzer.name=name
            accesses=[n for n in _walk(node) if n.type=='subscript_expression']
            if not accesses:continue
            try:
                if node.has_error or len(accesses)>128:raise _Unsupported('Function syntax/access budget unsupported')
                results=analyzer.run()
            except (_Unsupported,RecursionError) as exc:
                results=[analyzer.result(n,status='UNSUPPORTED',reason=str(exc)) for n in accesses]
                report.diagnostics.append(name+': '+str(exc))
            except z3.Z3Exception as exc:
                results=[];report.status='ERROR'
                report.diagnostics.append(name+': solver error: '+type(exc).__name__)
            for result in results:
                start=mapping[result.line-1];end=mapping[result.end_line-1]
                if not start or not end or start[0]!=source or end[0]!=source:
                    result.status='UNSUPPORTED';result.reason='Access spans unmappable preprocessing locations'
                else:
                    result.line=start[1];result.end_line=end[1];result.col=1;result.end_col=1
                report.results.append(result)
        if not report.results and report.status=='COMPLETED':
            report.status='NO_QUERIES';report.diagnostics.append('No array-access query sites in selected source functions')
    except ImportError as exc:
        report.status='UNAVAILABLE';report.diagnostics.append('Optional dependency unavailable: '+str(exc.name))
    except FileNotFoundError:
        report.status='UNAVAILABLE';report.diagnostics.append('Compilation database compiler unavailable')
    except subprocess.TimeoutExpired:
        report.status='TIMEOUT';report.diagnostics.append('Compiler preprocessing exceeded 30 seconds')
    except (_Unsupported,ValueError,KeyError,TypeError,OSError) as exc:
        if report.status not in ('ERROR','UNAVAILABLE'):report.status='UNSUPPORTED'
        report.diagnostics.append(str(exc))
    return report
