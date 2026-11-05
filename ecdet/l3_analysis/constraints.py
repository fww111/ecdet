"""Bounded, optional Z3 checks for a deliberately restricted C integer subset.

The model uses 8-bit bytes, 16-bit short, and 32-bit int, with two's-complement
fixed-width integer types. Results apply to one access and the stated model.
Unsupported C constructs never produce a safety result or suppress an alert.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import re

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity

RULE_ID = 'ECDET-Z3-BOUNDS'
MODEL = 'C11 subset: CHAR_BIT=8, short=16, int=32, two-complement; signed overflow excluded'


@dataclass
class ConstraintResult:
    status: str
    path: str
    function: str
    line: int
    col: int
    end_line: int
    end_col: int
    expression: str
    array: str = ''
    capacity: int = 0
    reason: str = ''
    witness: dict[str, int] = field(default_factory=dict)
    input_types: dict[str, dict] = field(default_factory=dict)
    constraints: str = ''
    source_sha256: str = ''
    model: str = MODEL

    def to_dict(self):
        return asdict(self)


@dataclass
class ConstraintReport:
    status: str
    path: str
    source_sha256: str
    results: list[ConstraintResult] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    solver_version: str = ''
    model: str = MODEL
    context: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    def alerts(self) -> list[Alert]:
        """SAT is a model candidate; host/firmware execution can confirm it later."""
        return [Alert(rule_id=RULE_ID, engine='z3', severity=Severity.WARNING,
            message=f'约束模型发现数组越界候选：{r.expression}；输入 {r.witness}',
            location=Location(r.path,r.line,r.col,r.end_line,r.end_col), cwe='CWE-129',
            provenance=Provenance.SUSPECTED,
            evidence=[Evidence('code',r.expression,Location(r.path,r.line,r.col),r.expression),
                      Evidence('note',f'模型：{r.model}；源码SHA256：{r.source_sha256}'),
                      Evidence('note',f'输入类型：{r.input_types}；模型输入：{r.witness}'),
                      Evidence('note','SAT为所列模型的可满足候选，需独立执行重放。')])
                for r in self.results if r.status=='SAT']


class _Unsupported(Exception):
    pass


@dataclass(frozen=True)
class _Type:
    bits: int
    signed: bool


@dataclass
class _Value:
    bv: object
    type: _Type
    defined: object


@dataclass
class _State:
    env: dict
    arrays: dict
    guard: object
    defined: object

    def copy(self):
        return _State(dict(self.env),dict(self.arrays),self.guard,self.defined)


def _walk(node):
    pending=[node]
    while pending:
        current=pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


class _Function:
    def __init__(self,z3,raw,path,node,sha,timeout_ms,resource_limit):
        self.z=z3; self.raw=raw; self.path=path; self.node=node; self.sha=sha
        self.timeout=timeout_ms; self.resource=resource_limit
        self.name=''; self.inputs={}; self.input_types={}; self.queries={}

    def text(self,node):
        return self.raw[node.start_byte:node.end_byte].decode('utf-8') if node else ''

    def result(self,node,**kw):
        line=node.start_point.row+1; end_line=node.end_point.row+1
        lines=self.raw.splitlines()
        col=len(lines[line-1][:node.start_point.column].decode('utf-8'))+1
        end_col=len(lines[end_line-1][:node.end_point.column].decode('utf-8'))+1
        return ConstraintResult(path=self.path,function=self.name,line=line,col=col,
            end_line=end_line,end_col=end_col,expression=self.text(node),
            source_sha256=self.sha,input_types=dict(self.input_types),**kw)

    def ctype(self,text):
        text=' '.join(text.split())
        types={'int':(32,True),'signed':(32,True),'signed int':(32,True),
            'unsigned':(32,False),'unsigned int':(32,False),
            'short':(16,True),'short int':(16,True),'signed short':(16,True),
            'signed short int':(16,True),'unsigned short':(16,False),'unsigned short int':(16,False),
            'signed char':(8,True),'unsigned char':(8,False)}
        for bits in (8,16,32):
            types[f'int{bits}_t']=(bits,True); types[f'uint{bits}_t']=(bits,False)
        if text not in types: raise _Unsupported(f'Unsupported or target-dependent integer type: {text}')
        return _Type(*types[text])

    def truth(self,value):
        return value.bv!=self.z.BitVecVal(0,value.type.bits)

    def convert(self,v,t,assignment=False):
        z=self.z
        if assignment and t.signed and (t.bits<v.type.bits or (not v.type.signed and t.bits<=v.type.bits)):
            raise _Unsupported('Potential implementation-defined signed conversion')
        if t.bits>v.type.bits:
            bv=(z.SignExt if v.type.signed else z.ZeroExt)(t.bits-v.type.bits,v.bv)
        elif t.bits<v.type.bits:
            bv=z.Extract(t.bits-1,0,v.bv)
        else: bv=v.bv
        return _Value(bv,t,v.defined)

    def promote(self,v):
        return self.convert(v,_Type(32,True)) if v.type.bits<32 else v

    def literal(self,text):
        m=re.fullmatch(r'(0[xX][0-9a-fA-F]+|[0-9]+)([uU]?)',text)
        if not m: raise _Unsupported(f'Unsupported integer literal: {text}')
        digits=m[1]
        try:
            if len(digits)>1 and digits[0]=='0' and not digits.lower().startswith('0x'):
                value=int(digits,8)
            else: value=int(digits,16 if digits.lower().startswith('0x') else 10)
        except ValueError as exc:
            raise _Unsupported('Invalid C integer literal') from exc
        unsigned=bool(m[2]) or (digits.lower().startswith('0x') and value>0x7fffffff)
        if value>0xffffffff or (value>0x7fffffff and not unsigned):
            raise _Unsupported('Integer literal requires unsupported long type')
        return _Value(self.z.BitVecVal(value,32),_Type(32,not unsigned),self.z.BoolVal(True))

    def expr(self,node,state):
        z=self.z; kind=node.type
        if kind=='parenthesized_expression':return self.expr(node.named_children[0],state)
        if kind=='identifier':
            name=self.text(node)
            if name not in state.env:raise _Unsupported(f'Unknown/uninitialized scalar: {name}')
            return state.env[name]
        if kind=='number_literal':return self.literal(self.text(node))
        if kind=='unary_expression':
            op=self.text(node.child_by_field_name('operator')); a=self.promote(self.expr(node.child_by_field_name('argument'),state))
            if op=='!':return _Value(z.If(self.truth(a),z.BitVecVal(0,32),z.BitVecVal(1,32)),_Type(32,True),a.defined)
            if op=='+':return a
            if op=='~':return _Value(~a.bv,a.type,a.defined)
            if op=='-':
                defined=z.And(a.defined,a.bv!=z.BitVecVal(1<<31,32)) if a.type.signed else a.defined
                return _Value(-a.bv,a.type,defined)
            raise _Unsupported(f'Unsupported unary operator: {op}')
        if kind=='binary_expression':
            op=self.text(node.child_by_field_name('operator'))
            a=self.promote(self.expr(node.child_by_field_name('left'),state))
            b=self.promote(self.expr(node.child_by_field_name('right'),state))
            defined=z.And(a.defined,b.defined)
            if op in {'&&','||'}:
                # Expressions have no side effects; model short-circuit definedness.
                right_used=self.truth(a) if op=='&&' else z.Not(self.truth(a))
                defined=z.And(a.defined,z.Implies(right_used,b.defined))
                test=(z.And if op=='&&' else z.Or)(self.truth(a),self.truth(b))
                return _Value(z.If(test,z.BitVecVal(1,32),z.BitVecVal(0,32)),_Type(32,True),defined)
            t=_Type(32,a.type.signed and b.type.signed)
            a=self.convert(a,t); b=self.convert(b,t)
            if op in {'==','!=','<','<=','>','>='}:
                if op=='==':test=a.bv==b.bv
                elif op=='!=':test=a.bv!=b.bv
                elif t.signed:test={'<':lambda:a.bv<b.bv,'<=':lambda:a.bv<=b.bv,'>':lambda:a.bv>b.bv,'>=':lambda:a.bv>=b.bv}[op]()
                else:test={'<':z.ULT,'<=':z.ULE,'>':z.UGT,'>=':z.UGE}[op](a.bv,b.bv)
                return _Value(z.If(test,z.BitVecVal(1,32),z.BitVecVal(0,32)),_Type(32,True),defined)
            operations={'+':lambda:a.bv+b.bv,'-':lambda:a.bv-b.bv,'*':lambda:a.bv*b.bv,
                        '&':lambda:a.bv&b.bv,'|':lambda:a.bv|b.bv,'^':lambda:a.bv^b.bv}
            if op not in operations:raise _Unsupported(f'Unsupported operator (including division/shift): {op}')
            value=operations[op]()
            if t.signed and op in {'+','-','*'}:
                wide_a=z.SignExt(32,a.bv);wide_b=z.SignExt(32,b.bv)
                wide={'+':lambda:wide_a+wide_b,'-':lambda:wide_a-wide_b,'*':lambda:wide_a*wide_b}[op]()
                defined=z.And(defined,wide==z.SignExt(32,value))
            return _Value(value,t,defined)
        raise _Unsupported(f'Unsupported value expression: {kind}')

    def access(self,node,state):
        array=self.text(node.child_by_field_name('argument'))
        if array not in state.arrays:raise _Unsupported('Only local fixed-size one-dimensional arrays are supported')
        index=self.promote(self.expr(node.child_by_field_name('index'),state))
        capacity=state.arrays[array]
        invalid=zbad=self.z.UGE(index.bv,self.z.BitVecVal(capacity,32))
        if index.type.signed:invalid=self.z.Or(index.bv<0,zbad)
        defined=self.z.And(state.defined,index.defined)
        self.queries.setdefault(node.start_byte,[]).append((node,array,capacity,state.guard,defined,invalid))
        # After this access, later behavior is defined only if it was in range.
        state.defined=self.z.And(defined,self.z.Not(invalid))

    def declaration(self,node,state):
        z=self.z
        if any(c.type in {'storage_class_specifier','type_qualifier'} for c in node.named_children):
            raise _Unsupported('Static, volatile, const, or other qualified locals are unsupported')
        typ=self.ctype(self.text(node.child_by_field_name('type')))
        for item in node.children_by_field_name('declarator'):
            value=None;decl=item
            if item.type=='init_declarator':
                decl=item.child_by_field_name('declarator');value=item.child_by_field_name('value')
            if decl.type=='array_declarator':
                name=self.text(decl.child_by_field_name('declarator'))
                size=decl.child_by_field_name('size')
                if not size or size.type!='number_literal':raise _Unsupported('Variable length array is unsupported')
                count=self.literal(self.text(size)).bv.as_long()
                if not 0<count<=1048576:raise _Unsupported('Array capacity outside supported bound')
                if value and self.text(value).replace(' ','')!='{0}':raise _Unsupported('Only zero array initialization is supported')
                if name in state.env or name in state.arrays:raise _Unsupported('Shadowed local names unsupported')
                state.arrays[name]=count
            elif decl.type=='identifier':
                name=self.text(decl)
                if name in state.env or name in state.arrays:raise _Unsupported('Shadowed local names unsupported')
                if value:
                    v=self.convert(self.expr(value,state),typ,assignment=True)
                    state.defined=z.And(state.defined,v.defined);state.env[name]=v
                else:raise _Unsupported('Uninitialized scalar locals unsupported')
            else:raise _Unsupported('Pointer or complex local declarator unsupported')

    def statement(self,node,state):
        z=self.z;kind=node.type
        if kind=='comment':return [state]
        if kind=='compound_statement':
            outer_env=set(state.env);outer_arrays=set(state.arrays)
            states=[state]
            for child in node.named_children:
                states=[s2 for s in states for s2 in self.statement(child,s)]
                if len(states)>64:raise _Unsupported('Path budget exceeded (64)')
            for s in states:
                s.env={name:value for name,value in s.env.items() if name in outer_env}
                s.arrays={name:capacity for name,capacity in s.arrays.items() if name in outer_arrays}
            return states
        if kind=='declaration':self.declaration(node,state);return [state]
        if kind=='if_statement':
            c=self.expr(node.child_by_field_name('condition'),state)
            yes=state.copy();no=state.copy()
            yes.guard=z.And(state.guard,self.truth(c));no.guard=z.And(state.guard,z.Not(self.truth(c)))
            yes.defined=z.And(state.defined,c.defined);no.defined=yes.defined
            alternative=node.child_by_field_name('alternative')
            if alternative and alternative.type=='else_clause':alternative=alternative.named_children[0]
            return self.statement(node.child_by_field_name('consequence'),yes)+(self.statement(alternative,no) if alternative else [no])
        if kind=='return_statement':
            if node.named_children:
                expr=node.named_children[0]
                if expr.type=='subscript_expression':self.access(expr,state)
                else:self.expr(expr,state)
            return []
        if kind=='expression_statement':
            if not node.named_children:return [state]
            expr=node.named_children[0]
            if expr.type=='subscript_expression':self.access(expr,state);return [state]
            if expr.type!='assignment_expression':raise _Unsupported('Only plain assignments are supported')
            op=self.text(expr.child_by_field_name('operator'))
            if op!='=':raise _Unsupported('Compound assignment unsupported')
            lhs=expr.child_by_field_name('left');rhs=expr.child_by_field_name('right')
            value=self.expr(rhs,state)
            if lhs.type=='subscript_expression':
                state.defined=z.And(state.defined,value.defined);self.access(lhs,state)
            elif lhs.type=='identifier' and self.text(lhs) in state.env:
                name=self.text(lhs);value=self.convert(value,state.env[name].type,assignment=True)
                state.defined=z.And(state.defined,value.defined);state.env[name]=value
            else:raise _Unsupported('Assignment to unknown scalar unsupported')
            return [state]
        raise _Unsupported(f'Unsupported statement: {kind}')

    def solve(self,formula):
        solver=self.z.Solver();solver.set(timeout=self.timeout)
        if self.resource:solver.set(rlimit=self.resource)
        solver.add(formula);status=solver.check()
        return solver,status

    def run(self):
        z=self.z
        decl=self.node.child_by_field_name('declarator')
        if decl.type!='function_declarator':raise _Unsupported('Complex function declarator unsupported')
        self.name=self.text(decl.child_by_field_name('declarator'))
        params=decl.child_by_field_name('parameters')
        env={}
        for param in params.named_children:
            if self.text(param)=='void':continue
            if any(c.type=='type_qualifier' for c in param.named_children):
                raise _Unsupported('Qualified parameters unsupported')
            typ=self.ctype(self.text(param.child_by_field_name('type')))
            name_node=param.child_by_field_name('declarator')
            if not name_node or name_node.type!='identifier':raise _Unsupported('Only scalar named integer parameters supported')
            name=self.text(name_node)
            if name in self.inputs:raise _Unsupported('Duplicate parameter identity')
            self.inputs[name]=z.BitVec(name,typ.bits);self.input_types[name]={'bits':typ.bits,'signed':typ.signed}
            env[name]=_Value(self.inputs[name],typ,z.BoolVal(True))
        body=self.node.child_by_field_name('body')
        self.statement(body,_State(env,{},z.BoolVal(True),z.BoolVal(True)))
        results=[]
        for queries in self.queries.values():
            node,array,cap=queries[0][:3]
            formula=z.Or(*[z.And(guard,defined,bad) for _,_,_,guard,defined,bad in queries])
            solver,status=self.solve(formula)
            base=dict(array=array,capacity=cap,constraints=solver.to_smt2())
            if status==z.sat:
                model=solver.model();witness={}
                for name,bv in self.inputs.items():
                    value=model.eval(bv,model_completion=True).as_long();typ=self.input_types[name]
                    if typ['signed'] and value>=(1<<(typ['bits']-1)):value-=1<<typ['bits']
                    witness[name]=value
                results.append(self.result(node,status='SAT',witness=witness,
                    reason='Model has a defined path to this out-of-bounds access; execution replay required.',**base))
            elif status==z.unknown:
                results.append(self.result(node,status='UNKNOWN',reason=solver.reason_unknown(),**base))
            else:
                # A locally unsatisfiable query is not a safety claim when prior
                # signed overflow / invalid access could affect path semantics.
                ub=z.Or(*[z.And(guard,z.Not(defined)) for _,_,_,guard,defined,_ in queries])
                prior,prior_status=self.solve(ub)
                if prior_status==z.sat:
                    state='UNSUPPORTED';reason='A path may have prior signed overflow or undefined memory access.'
                elif prior_status==z.unknown:
                    state='UNKNOWN';reason='Prior definedness check: '+prior.reason_unknown()
                else:
                    state='UNSAT';reason='No out-of-bounds input for this access in the supported local model.'
                results.append(self.result(node,status=state,reason=reason,**base))
        return results


def analyze_constraints(source: str,path: str='<memory>',*,function: str | None=None,
                        timeout_ms: int=1000,resource_limit: int=0) -> ConstraintReport:
    """Extract local array-access queries from source, without changing old alerts.

    Missing dependencies, macros, calls, loops, pointers, casts, division,
    implementation-defined conversions, and unsupported types stay explicit.
    ``resource_limit`` is a Z3 resource budget (0 means its default).
    """
    if not isinstance(source,str):raise TypeError('source must be a string')
    if type(timeout_ms) is not int or timeout_ms<=0:raise ValueError('timeout_ms must be a positive integer')
    if type(resource_limit) is not int or resource_limit<0:raise ValueError('resource_limit must be a nonnegative integer')
    path=str(path).replace('\\','/');raw=source.encode('utf-8');sha=hashlib.sha256(raw).hexdigest()
    report=ConstraintReport('COMPLETED',path,sha)
    if len(raw)>2*1024*1024:
        report.status='UNSUPPORTED';report.diagnostics=['Source exceeds the 2 MiB analysis budget'];return report
    try:
        import z3
        from tree_sitter import Language,Parser
        import tree_sitter_c
    except ImportError as exc:
        report.status='UNAVAILABLE';report.diagnostics=[f'Optional dependency missing: {exc.name}; install ecdet[constraints]'];return report
    report.solver_version=z3.get_version_string()
    tree=Parser(Language(tree_sitter_c.language())).parse(raw)
    if tree.root_node.has_error:
        report.status='UNSUPPORTED';report.diagnostics=['C syntax recovery tree is unsupported'];return report
    # Only stdint.h inclusion is interpreted. Other preprocessing can alter C
    # types, paths, constants or identifiers and therefore requires a real TU.
    prep=[n for n in _walk(tree.root_node) if n.type.startswith('preproc_')]
    if any(n.type!='preproc_include' or raw[n.start_byte:n.end_byte].decode().strip() not in
           {'#include <stdint.h>','#include "stdint.h"'} for n in prep):
        report.status='UNSUPPORTED';report.diagnostics=['Preprocessor configuration or unknown includes unsupported'];return report
    if any(n.type not in {'function_definition','comment','preproc_include'}
           for n in tree.root_node.named_children):
        report.status='UNSUPPORTED';report.diagnostics=['Global declarations, typedef overrides, or other translation-unit constructs unsupported'];return report
    funcs=[n for n in tree.root_node.named_children if n.type=='function_definition']
    if len(funcs)>64:
        report.status='UNSUPPORTED';report.diagnostics=['Function count exceeds the 64-function analysis budget'];return report
    names=[]
    for node in funcs:
        decl=node.child_by_field_name('declarator');name=decl.child_by_field_name('declarator')
        names.append(raw[name.start_byte:name.end_byte].decode() if name else '')
    if len(set(names))!=len(names):
        report.status='UNSUPPORTED';report.diagnostics=['Duplicate function identities unsupported'];return report
    if function is not None and function not in names:
        report.status='UNSUPPORTED';report.diagnostics=['Requested function not found'];return report
    for node,name in zip(funcs,names):
        if function is not None and name!=function:continue
        analyzer=_Function(z3,raw,path,node,sha,timeout_ms,resource_limit);analyzer.name=name
        try:
            if sum(n.type=='subscript_expression' for n in _walk(node))>128:
                raise _Unsupported('Function exceeds the 128-access analysis budget')
            report.results.extend(analyzer.run())
        except (_Unsupported,RecursionError) as exc:
            accesses=[n for n in _walk(node) if n.type=='subscript_expression']
            report.results.extend(analyzer.result(n,status='UNSUPPORTED',reason=str(exc)) for n in accesses)
            report.diagnostics.append(f'{name}: {exc}')
        except z3.Z3Exception as exc:
            report.diagnostics.append(f'{name}: solver error: {type(exc).__name__}');report.status='ERROR'
    if not funcs:report.diagnostics.append('No function definitions found')
    return report
