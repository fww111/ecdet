"""Optional C syntax based boundary/lifetime checks with explicit Suspected evidence.

The integer model uses ILP32 scalar widths. Intervals overapproximate inputs;
they identify missing/insufficient guards, not reachable-path proofs. No ABI
layout is guessed for structs: typed copies compare element counts instead.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import ast
import logging
import re

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity
from ecdet.l3_analysis.syntax import _walk, _decl_name, _function_declarator


def text(node):
    return node.text.decode('utf-8') if node is not None else ''


def child(node, name):
    return node.child_by_field_name(name) if node is not None else None


def unwrap(node):
    while node is not None and node.type == 'parenthesized_expression':
        node = node.named_children[0]
    return node


def key(node):
    node = unwrap(node)
    # Casts are retained: narrowing must not transfer a guard to the wide sum.
    return re.sub(r'\s+', '', text(node))


@dataclass(frozen=True)
class CType:
    base: str = ''
    pointer: int = 0
    count: int | None = None

    @property
    def bounds(self):
        if self.pointer or self.count is not None:
            return None
        name = self.base
        bits = {'char':8,'short':16,'int':32,'unsigned':32,'unsigned int':32,
                'unsigned char':8,'unsigned short':16,'long':32,'unsigned long':32,
                'long long':64,'unsigned long long':64,'size_t':32}.get(name)
        match = re.fullmatch(r'(u?)int(8|16|32|64)_t', name)
        if match:
            bits=int(match.group(2))
        if bits is None:
            return None
        unsigned = name.startswith(('unsigned','uint')) or name == 'size_t'
        return (0,2**bits-1) if unsigned else (-2**(bits-1),2**(bits-1)-1)

    @property
    def size(self):
        bounds = replace(self,count=None).bounds
        base = (bounds[1]-bounds[0]+1).bit_length()-1 if bounds else 0
        size = base//8 if base else {'float':4,'double':8,'bool':1,'_Bool':1}.get(self.base)
        return size*(self.count if self.count is not None else 1) if size and not self.pointer else None


@dataclass
class State:
    types: dict = field(default_factory=dict)
    values: dict = field(default_factory=dict)
    aliases: dict = field(default_factory=dict)
    relations: set = field(default_factory=set)
    formatted: dict = field(default_factory=dict)
    bounded: set = field(default_factory=set)

    def copy(self):
        return State(dict(self.types),dict(self.values),dict(self.aliases),set(self.relations),dict(self.formatted),set(self.bounded))


class Model:
    def __init__(self, facts):
        from tree_sitter import Language, Parser
        import tree_sitter_c
        parser=Parser(Language(tree_sitter_c.language()))
        self.roots={}
        self.records={}
        self.macros={}
        self.count_macros=set()
        for f in facts:
            root=parser.parse(f.source.encode('utf-8')).root_node
            if root.has_error:
                logging.getLogger(__name__).warning('Boundary analysis skipped: syntax error in %s',f.path)
                continue
            self.roots[f.path]=root
            for n in _walk(root):
                if n.type=='preproc_def':
                    self.macros[text(child(n,'name'))]=text(child(n,'value')).strip()
                if n.type=='preproc_function_def' and text(n).count('sizeof') == 2:
                    self.count_macros.add(text(child(n,'name')))
        for root in self.roots.values():
            for n in _walk(root):
                if n.type!='struct_specifier' or child(n,'body') is None:
                    continue
                names=[text(child(n,'name'))]
                if n.parent.type=='type_definition':
                    names += [text(_decl_name(d) or d) for d in n.parent.children_by_field_name('declarator')]
                fields={}
                for declaration in child(n,'body').named_children:
                    if declaration.type=='field_declaration':
                        for d in declaration.children_by_field_name('declarator'):
                            name,typ=self.declaration(declaration,d)
                            if name:
                                fields[name]=typ
                for name in filter(None,names):
                    self.records[name]=fields

    def constant(self, expression, seen=None):
        expression=expression.strip()
        seen=seen or set()
        if expression in self.macros and expression not in seen:
            return self.constant(self.macros[expression],seen|{expression})
        expression=re.sub(r'(?<=\d)[uUlL]+\b','',expression)
        for name in set(re.findall(r'\b[A-Za-z_]\w*\b',expression)):
            if name in self.macros and name not in seen:
                value=self.constant(name,seen)
                if value is not None:
                    expression=re.sub(r'\b'+re.escape(name)+r'\b',str(value),expression)
        if not re.fullmatch(r'[\da-fA-FxX\s()+*/%<>&|~^-]+',expression):
            return None
        if len(expression)>512:return None
        try:
            def fold(node):
                if isinstance(node,ast.Constant) and type(node.value) is int:value=node.value
                elif isinstance(node,ast.UnaryOp):
                    operand=fold(node.operand)
                    if isinstance(node.op,ast.USub):value=-operand
                    elif isinstance(node.op,ast.UAdd):value=operand
                    elif isinstance(node.op,ast.Invert):value=~operand
                    else:raise ValueError('Unsupported unary operator')
                elif isinstance(node,ast.BinOp):
                    left=fold(node.left);right=fold(node.right)
                    if isinstance(node.op,ast.Add):value=left+right
                    elif isinstance(node.op,ast.Sub):value=left-right
                    elif isinstance(node.op,ast.Mult):value=left*right
                    elif isinstance(node.op,(ast.Div,ast.FloorDiv,ast.Mod)):
                        quotient=(abs(left)//abs(right))*(-1 if (left<0)!=(right<0) else 1)
                        value=left-quotient*right if isinstance(node.op,ast.Mod) else quotient
                    elif isinstance(node.op,(ast.LShift,ast.RShift)) and 0<=right<128:
                        value=left<<right if isinstance(node.op,ast.LShift) else left>>right
                    elif isinstance(node.op,ast.BitAnd):value=left&right
                    elif isinstance(node.op,ast.BitOr):value=left|right
                    elif isinstance(node.op,ast.BitXor):value=left^right
                    else:raise ValueError('Unsupported binary operator')
                else:raise ValueError('Non-constant expression')
                if abs(value)>=2**128:raise ValueError('Constant exceeds analysis limit')
                return value
            return fold(ast.parse(expression,mode='eval').body)
        except (SyntaxError,ValueError,TypeError,ArithmeticError,RecursionError):
            return None

    def declaration(self, node, declarator):
        name=text(_decl_name(declarator))
        base_node=child(node,'type')
        base=text(base_node)
        if base_node is not None and base_node.type=='struct_specifier':
            base=text(child(base_node,'name'))
        base=re.sub(r'\b(const|volatile|restrict|struct)\b','',base)
        base=' '.join(base.split())
        pointer=0;count=None
        n=declarator
        while n is not None:
            if n.type in {'pointer_declarator','abstract_pointer_declarator'}:
                pointer+=1
            if n.type=='array_declarator':
                count=self.constant(text(child(n,'size')))
            n=child(n,'declarator')
        return name,CType(base,pointer,count)

    def type_of(self,node,state):
        node=unwrap(node)
        if node is None:return CType()
        if node.type=='identifier':return state.types.get(text(node),CType())
        if node.type=='field_expression':
            owner=self.type_of(child(node,'argument'),state)
            return self.records.get(owner.base,{}).get(text(child(node,'field')),CType())
        if node.type=='subscript_expression':
            owner=self.type_of(child(node,'argument'),state)
            return replace(owner,count=None,pointer=max(0,owner.pointer-1))
        if node.type=='pointer_expression':
            owner=self.type_of(child(node,'argument'),state)
            op=text(child(node,'operator'))
            return replace(owner,pointer=owner.pointer+1 if op=='&' else max(0,owner.pointer-1))
        if node.type=='cast_expression':
            return self.declaration(child(node,'type'),child(child(node,'type'),'declarator'))[1]
        return CType()

    def interval(self,node,state):
        node=unwrap(node)
        if node is None:return None
        if key(node) in state.values:return state.values[key(node)]
        val=self.constant(text(node))
        if val is not None:return val,val
        if node.type in {'identifier','field_expression','subscript_expression'}:
            return self.type_of(node,state).bounds
        if node.type=='sizeof_expression':
            typ=self.type_of(child(node,'value'),state)
            if typ.size is not None:return typ.size,typ.size
        if node.type=='call_expression':
            args=child(node,'arguments').named_children
            if text(child(node,'function')) in self.count_macros and len(args)==1:
                count=self.type_of(args[0],state).count
                if count is not None:return count,count
        if node.type=='cast_expression':
            value=self.interval(child(node,'value'),state)
            bounds=self.type_of(node,state).bounds
            if bounds and value:
                return value if bounds[0]<=value[0]<=value[1]<=bounds[1] else bounds
            return value
        if node.type=='unary_expression':
            val=self.interval(child(node,'argument'),state)
            if val and text(child(node,'operator'))=='-':return -val[1],-val[0]
        if node.type=='binary_expression':
            left=self.interval(child(node,'left'),state);right=self.interval(child(node,'right'),state)
            op=text(child(node,'operator'))
            if left and right:
                a,b=left;c,d=right
                if op=='+':
                    upper=b+d
                    for offset,index in [(child(node,'left'),child(node,'right')),(child(node,'right'),child(node,'left'))]:
                        offset_range=self.interval(offset,state)
                        if not offset_range or offset_range[0]<0:continue
                        for variable,relation,limit in state.relations:
                            suffix='-'+key(offset)
                            if relation not in {'<','<='} or not limit.endswith(suffix):continue
                            cap=self.constant(limit[:-len(suffix)])
                            if cap is None or offset_range[1]>cap:continue
                            if key(index)==variable:upper=min(upper,cap-(relation=='<'))
                            if (key(index),'<',variable) in state.relations:upper=min(upper,cap-1-(relation=='<'))
                    return a+c,upper
                if op=='-':return a-d,b-c
                if op=='*':return min(a*c,a*d,b*c,b*d),max(a*c,a*d,b*c,b*d)
                if op=='%' and c==d and c>0:return 0,c-1
                if op=='/' and c==d and c>0:return a//c,b//c
        return None


class Analyzer:
    def __init__(self,model,path,active):
        self.model=model;self.path=path;self.active=active
        self.alerts=[];self.seen=set();self.function=''

    def bounded(self,node,state):
        node=unwrap(node)
        if node is None:return False
        if key(node) in state.bounded or self.model.constant(text(node)) is not None:return True
        if node.type=='sizeof_expression':return self.model.interval(node,state) is not None
        if node.type=='binary_expression':
            return self.bounded(child(node,'left'),state) and self.bounded(child(node,'right'),state)
        return False

    def emit(self,rule,node,message,cwe):
        if rule not in self.active:return
        identity=(rule,node.start_byte)
        if identity in self.seen:return
        self.seen.add(identity)
        location=Location(self.path,node.start_point.row+1,node.start_point.column+1)
        self.alerts.append(Alert(rule_id=rule,engine='builtin-flow',severity=Severity.WARNING,
            message=message,location=location,cwe=cwe,provenance=Provenance.SUSPECTED,
            evidence=[Evidence(kind='code',message=f'{self.function}: {text(node)}',location=location)],
            properties={'analysis_model':'ILP32 ranges; potential path; no alias/ABI proof'}))

    def constrain(self,condition,state,truth):
        condition=unwrap(condition)
        if condition is None:return
        if condition.type=='unary_expression' and text(child(condition,'operator'))=='!':
            self.constrain(child(condition,'argument'),state,not truth);return
        if condition.type!='binary_expression':return
        op=text(child(condition,'operator'));left=child(condition,'left');right=child(condition,'right')
        if (op=='&&' and truth) or (op=='||' and not truth):
            self.constrain(left,state,truth);self.constrain(right,state,truth);return
        if not truth:op={'<':'>=','<=':'>','>':'<=','>=':'<','==':'!=','!=':'=='}.get(op,op)
        if op not in {'<','<=','>','>=','=='}:return
        left=unwrap(left)
        if left.type=='cast_expression':
            source=child(left,'value');before=self.model.interval(source,state);after=self.model.type_of(left,state).bounds
            if before and after and after[0]<=before[0]<=before[1]<=after[1]:left=unwrap(source)
        state.relations.add((key(left),op,key(right)))
        a=self.model.interval(left,state);b=self.model.interval(right,state)
        if not a or not b:return
        if (unwrap(right).type in {'identifier','field_expression'} and key(right) not in state.values
                and b == self.model.type_of(right,state).bounds):
            return  # Type width alone does not bound an object's occupancy invariant.
        lo,hi=a
        if op=='<':hi=min(hi,b[1]-1)
        if op=='<=':hi=min(hi,b[1])
        if op=='>':lo=max(lo,b[0]+1)
        if op=='>=':lo=max(lo,b[0])
        if op=='==':lo,hi=max(lo,b[0]),min(hi,b[1])
        state.values[key(left)]=(lo,hi)
        if self.bounded(right,state) or b[0]==b[1]:state.bounded.add(key(left))
        if key(left) in state.aliases:
            state.values[state.aliases[key(left)]]=(lo,hi)
        # Refine the symmetric side too, without recursion through relations.
        rlo,rhi=b
        if op in {'>','>='}:rhi=min(rhi,a[1]-(op=='>'))
        if op in {'<','<='}:rlo=max(rlo,a[0]+(op=='<'))
        state.values[key(right)]=(rlo,rhi)

    def assign(self,target,value,state):
        name=key(target)
        state.relations={r for r in state.relations if r[0]!=name and r[2]!=name}
        state.aliases.pop(name,None);state.formatted.pop(name,None)
        if self.bounded(value,state):state.bounded.add(name)
        else:state.bounded.discard(name)
        interval=self.model.interval(value,state)
        if interval:state.values[name]=interval
        else:state.values.pop(name,None)
        val=unwrap(value)
        if val is not None and val.type=='cast_expression':
            inner=unwrap(child(val,'value'))
            bounds=self.model.type_of(val,state).bounds
            inner_range=self.model.interval(inner,state)
            if bounds and inner_range and bounds[0]<=inner_range[0]<=inner_range[1]<=bounds[1]:val=inner
        bounds=self.model.type_of(target,state).bounds
        if val is not None and val.type=='binary_expression' and interval and (
                bounds is None or bounds[0]<=interval[0]<=interval[1]<=bounds[1]):
            def value_key(expr):
                expr=unwrap(expr)
                if expr.type=='cast_expression':
                    inner=child(expr,'value');source_range=self.model.interval(inner,state)
                    target_range=self.model.type_of(expr,state).bounds
                    if source_range and target_range and target_range[0]<=source_range[0]<=source_range[1]<=target_range[1]:
                        return value_key(inner)
                if expr.type=='binary_expression':
                    return value_key(child(expr,'left'))+text(child(expr,'operator'))+value_key(child(expr,'right'))
                return key(expr)
            state.aliases[name]=value_key(val)
        if value is not None and value.type=='call_expression' and text(child(value,'function')) in {'snprintf','vsnprintf'}:
            args=child(value,'arguments').named_children
            if len(args)>=2:state.formatted[name]=(key(args[0]),self.model.interval(args[1],state))

    def inspect(self,node,state):
        if node is None:return
        if node.type=='binary_expression' and text(child(node,'operator')) in {'&&','||'}:
            left=child(node,'left');self.inspect(left,state)
            right_state=state.copy()
            self.constrain(left,right_state,text(child(node,'operator'))=='&&')
            self.inspect(child(node,'right'),right_state)
            return
        if node.type=='subscript_expression':
            array=self.model.type_of(child(node,'argument'),state)
            index=child(node,'index');interval=self.model.interval(index,state)
            if array.count is not None and interval and interval[0]<=interval[1]:
                original_bounds=self.model.type_of(index,state).bounds
                locally_bounded = self.bounded(index,state) and interval != original_bounds
                literal = self.model.constant(text(index)) is not None
                if (locally_bounded or literal) and (interval[0]<0 or interval[1]>=array.count):
                    self.emit('CERT C ARR30-C',node,
                        f'数组{text(child(node,"argument"))}容量{array.count}，下标{text(index)}的当前范围{interval}未被限制在合法区间', 'CWE-787')
        if node.type=='cast_expression':
            target=self.model.type_of(node,state);source=child(node,'value')
            interval=self.model.interval(source,state)
            if target.bounds and target.bounds[0]==0 and interval and interval[0]<0 and unwrap(source).type=='identifier':
                source_bounds=self.model.type_of(source,state).bounds
                # Explicit narrowing often encodes modulo/truncation. This rule
                # covers sign reinterpretation at the same or a wider width;
                # narrowing needs its own value-loss/consumer evidence.
                if source_bounds and target.bounds[1] >= source_bounds[1]:
                    self.emit('ECDET-CWE-195',node,'有符号输入可能为负，转为无符号数前未排除负值','CWE-195')
        if node.type=='binary_expression' and text(child(node,'operator')) in {'>','>=','<','<='}:
            for operand in (child(node,'left'),child(node,'right')):
                operand=unwrap(operand)
                if operand is not None and operand.type=='binary_expression' and text(child(operand,'operator'))=='+':
                    left=child(operand,'left');right=child(operand,'right')
                    typ=self.model.type_of(left,state);interval=self.model.interval(operand,state)
                    if typ.bounds and typ.bounds[0]==0 and typ.bounds[1]>=2**32-1 and interval and interval[1]>typ.bounds[1]:
                        self.emit('CERT C INT30-C',operand,'比较表达式中的无符号加法可能回绕，改变超时或边界判断结果','CWE-190')
        if node.type=='assignment_expression':
            target=child(node,'left');value=child(node,'right');op=text(child(node,'operator'))
            typ=self.model.type_of(target,state)
            if op=='-=' and target.type=='field_expression' and typ.bounds and typ.bounds[0]==0:
                safe=((key(value),'<=',key(target)) in state.relations or (key(target),'>=',key(value)) in state.relations)
                a=self.model.interval(target,state);b=self.model.interval(value,state)
                if not safe and a and b and b[1]>a[0]:
                    self.emit('CERT C INT30-C',node,'无符号字段扣减前未检查余额，可能下溢回绕','CWE-190')
        if node.type=='call_expression':self.call(node,state)
        # sizeof operands are not evaluated, including increments and subscripts.
        if node.type=='sizeof_expression':return
        for sub in node.named_children:self.inspect(sub,state)

    def call(self,node,state):
        name=text(child(node,'function'));args=child(node,'arguments').named_children
        # A bounded offset into an explicitly indexed partition has a smaller
        # contract than the backing allocation. Check offset + transfer length.
        for i,address in enumerate(args[:-2]):
            address=unwrap(address)
            if address.type!='binary_expression' or text(child(address,'operator'))!='+':continue
            partition=unwrap(child(address,'left'));offset=child(address,'right')
            if partition.type!='binary_expression' or text(child(partition,'operator'))!='*':continue
            stride=self.model.interval(child(partition,'right'),state)
            offset_range=self.model.interval(offset,state)
            buffer_type=self.model.type_of(args[i+1],state)
            length=self.model.interval(args[i+2],state)
            if not (stride and stride[0]==stride[1]>0 and offset_range and
                    0<=offset_range[0]<=offset_range[1]<stride[0] and
                    (buffer_type.pointer or buffer_type.count is not None) and length):continue
            limit=key(child(partition,'right'))+'-'+key(offset)
            guarded=(key(args[i+2]),'<=',limit) in state.relations
            if not guarded and offset_range[1]+length[1]>stride[0]:
                self.emit('ECDET-CWE-119',node,
                    f'分区步长为{stride[0]}，仅检查分区内偏移；偏移加传输长度可能越过分区边界', 'CWE-119')
        if name in {'memcpy','memmove'} and len(args)==3:
            target=unwrap(args[0]);offset=None
            if target.type=='binary_expression' and text(child(target,'operator'))=='+':
                offset=child(target,'right');target=unwrap(child(target,'left'))
            typ=self.model.type_of(target,state)
            amount=self.model.interval(args[2],state)
            capacity=typ.size
            # Compare typed element counts even for struct arrays with unknown ABI size.
            amount_node=unwrap(args[2])
            if typ.count is not None and amount_node.type=='binary_expression' and text(child(amount_node,'operator'))=='*':
                size_node=unwrap(child(amount_node,'right'))
                if size_node.type=='sizeof_expression':
                    element=self.model.type_of(child(size_node,'value'),state)
                    if element.base==typ.base and element.count is None:
                        amount=self.model.interval(child(amount_node,'left'),state);capacity=typ.count
            if offset is not None:
                total=key(offset)+'+'+key(args[2])
                amount=state.values.get(total) or state.values.get(key(args[2])+'+'+key(offset))
                if amount is None:
                    a=self.model.interval(offset,state);b=self.model.interval(args[2],state)
                    amount=(a[0]+b[0],a[1]+b[1]) if a and b else None
            if capacity is not None and amount and amount[0]<=amount[1] and amount[1]>capacity:
                self.emit('CERT C STR31-C',node,
                    f'复制目标{text(target)}容量{capacity}，长度及偏移的当前上界{amount[1]}超出容量；需校验目标边界', 'CWE-787')
        if name not in {'snprintf','vsnprintf'}:
            for length,(buffer,capacity) in state.formatted.items():
                clean_args=[key(unwrap(child(a,'value')) if a.type=='cast_expression' else a) for a in args]
                if buffer in clean_args and length in clean_args and capacity:
                    bounds=state.values.get(length)
                    if bounds is None or bounds[1]>=capacity[0]:
                        self.emit('CERT C ARR30-C',node,'snprintf返回所需长度；截断后直接将其作为缓冲区有效长度传递，可能越界读取','CWE-125')

    def statement(self,node,state):
        if node is None:return False
        kind=node.type
        if kind=='compound_statement':
            for sub in node.named_children:
                if self.statement(sub,state):return True
            return False
        if kind=='case_statement':
            for sub in node.named_children:
                if sub==child(node,'value'):continue
                if self.statement(sub,state):return True
            return False
        if kind=='if_statement':
            condition=child(node,'condition');self.inspect(condition,state)
            yes=state.copy();no=state.copy()
            self.constrain(condition,yes,True);self.constrain(condition,no,False)
            exits_yes=self.statement(child(node,'consequence'),yes)
            alternate=child(node,'alternative')
            if alternate is not None and alternate.type=='else_clause':alternate=alternate.named_children[-1]
            exits_no=self.statement(alternate,no)
            if exits_yes and exits_no:return True
            if exits_yes:result=no
            elif exits_no:result=yes
            else:
                result=state.copy()
                result.values={k:(min(yes.values[k][0],no.values[k][0]),max(yes.values[k][1],no.values[k][1]))
                               for k in yes.values.keys() & no.values.keys()}
                result.relations=yes.relations & no.relations
                result.bounded=yes.bounded & no.bounded
                result.aliases={k:v for k,v in yes.aliases.items() if no.aliases.get(k)==v}
            state.values=result.values;state.relations=result.relations;state.aliases=result.aliases
            state.bounded=result.bounded
            return False
        if kind=='for_statement':
            loop=state.copy();self.statement(child(node,'initializer'),loop)
            condition=child(node,'condition')
            # Widen induction variables before refining by the loop condition.
            update=child(node,'update')
            if update:
                for part in _walk(update):
                    if part.type=='identifier':
                        initial=loop.values.get(key(part));bounds=self.model.type_of(part,loop).bounds
                        if initial and bounds:loop.values[key(part)]=(initial[0],bounds[1])
                        loop.bounded.discard(key(part))
            self.constrain(condition,loop,True)
            self.statement(child(node,'body'),loop)
            for part in _walk(child(node,'body')):
                if part.type=='assignment_expression':state.values.pop(key(child(part,'left')),None)
            return False
        if kind=='switch_statement':
            body=child(node,'body')
            for case in body.named_children if body else []:
                if case.type=='case_statement':self.statement(case,state.copy())
            state.values={};state.relations=set();return False
        if kind in {'while_statement','do_statement'}:
            # No fixed-point model: inspect with type bounds and do not export guards.
            loop=state.copy();loop.values={};loop.relations=set()
            self.statement(child(node,'body'),loop)
            state.values={};state.relations=set();return False
        if kind=='declaration':
            for d in node.children_by_field_name('declarator'):
                name,typ=self.model.declaration(node,d)
                if not name:continue
                state.types[name]=typ
                value=child(d,'value')
                if value is not None:
                    self.inspect(value,state);self.assign(_decl_name(d),value,state)
            return False
        self.inspect(node,state)
        for sub in _walk(node):
            if sub.type=='assignment_expression' and text(child(sub,'operator'))=='=':
                self.assign(child(sub,'left'),child(sub,'right'),state)
        return kind in {'return_statement','goto_statement','break_statement','continue_statement'}

    def run(self,root):
        globals_=State()
        for n in root.named_children:
            if n.type=='declaration':
                for d in n.children_by_field_name('declarator'):
                    name,typ=self.model.declaration(n,d)
                    globals_.types[name]=typ
        for function in (n for n in _walk(root) if n.type=='function_definition'):
            state=globals_.copy();decl=child(function,'declarator')
            self.function=text(_decl_name(decl))
            params=child(_function_declarator(decl),'parameters')
            for p in params.named_children if params else []:
                name,typ=self.model.declaration(p,child(p,'declarator'))
                if name:state.types[name]=typ
            self.statement(child(function,'body'),state)
            self.lifetime(function,state)
        return self.alerts

    def lifetime(self,function,state):
        body=child(function,'body')
        for n in _walk(body):
            if n.type!='call_expression' or text(child(n,'function'))!='free':continue
            args=child(n,'arguments').named_children
            if len(args)!=1 or args[0].type!='field_expression':continue
            pointer=args[0];name=key(pointer)
            # A direct following reset, not a reset in an optional branch.
            reset=False
            for statement in body.named_children:
                if statement.start_byte<=n.end_byte or statement.type!='expression_statement':continue
                for assignment in statement.named_children:
                    if assignment.type=='assignment_expression' and key(child(assignment,'left'))==name:
                        reset=True
            if not reset:
                self.emit('ECDET-CWE-416',n,'释放共享对象字段后未清除或更新该指针，后续调用可能沿悬空字段再次访问','CWE-416')


def check_value_flow(facts,active):
    try:
        model=Model(facts)
    except ImportError:
        logging.getLogger(__name__).warning('Boundary analysis unavailable: install ecdet[syntax]')
        return []
    out=[]
    for path,root in model.roots.items():
        if path.endswith(('.c','.cc','.cpp')):
            out.extend(Analyzer(model,path,active).run(root))
    return out
