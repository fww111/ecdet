"""Optional Tree-sitter C structure index with explicit reliability states.

This module extracts syntax, not pointer targets, type semantics or reachable
preprocessor branches. Byte ranges are UTF-8 offsets with an exclusive end;
line and character-column coordinates are one-based, also with exclusive ends.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SyntaxSpan:
    path: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    start_byte: int
    end_byte: int
    text: str

    @property
    def line(self) -> int:
        return self.start_line


@dataclass(frozen=True)
class SyntaxCall(SyntaxSpan):
    name: str
    expression: str
    kind: str
    conditional: bool = False


@dataclass(frozen=True)
class SyntaxCondition(SyntaxSpan):
    kind: str


@dataclass(frozen=True)
class SyntaxAssignment(SyntaxSpan):
    target: str
    operator: str
    value: str
    kind: str


@dataclass(frozen=True)
class SyntaxFunction(SyntaxSpan):
    name: str
    signature: str
    is_static: bool
    params: tuple[str, ...]
    local_names: tuple[str, ...]
    calls: tuple[SyntaxCall, ...]
    def_line: int
    body_open_line: int
    body_close_line: int
    body_start_byte: int
    body_end_byte: int
    conditional: bool = False


@dataclass(frozen=True)
class SyntaxIndex:
    path: str
    backend: str
    status: str
    diagnostics: tuple[dict, ...] = ()
    functions: tuple[SyntaxFunction, ...] = ()
    conditions: tuple[SyntaxCondition, ...] = ()
    assignments: tuple[SyntaxAssignment, ...] = ()

    @property
    def reliable(self) -> bool:
        return self.status == 'PASS'


def _walk(node):
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _conditional(node) -> bool:
    owner = node.parent
    while owner is not None:
        if owner.type in {'preproc_if', 'preproc_ifdef', 'preproc_elif',
                          'preproc_else', 'preproc_elifdef'}:
            return True
        owner = owner.parent
    return False


def _declarator_chain(node):
    while node is not None:
        yield node
        child = node.child_by_field_name('declarator')
        if child is None and node.type == 'parenthesized_declarator' and node.named_children:
            child = node.named_children[0]
        node = child


def _decl_name(node):
    return next((part for part in _declarator_chain(node)
                 if part.type in {'identifier', 'field_identifier'}), None)


def _function_declarator(node):
    # A function returning a function pointer can contain two declarators;
    # the innermost function declarator adjacent to the name owns its params.
    parts = [part for part in _declarator_chain(node) if part.type == 'function_declarator']
    return parts[-1] if parts else None


def _is_function_prototype(node) -> bool:
    function = _function_declarator(node)
    if function is None:
        return False
    return not any(part.type in {'pointer_declarator', 'array_declarator'}
                   for part in _declarator_chain(function.child_by_field_name('declarator')))


def _extract(source: str, path: str, root) -> SyntaxIndex:
    raw = source.encode('utf-8')
    lines = raw.splitlines(keepends=True) or [b'']

    def text(node) -> str:
        return raw[node.start_byte:node.end_byte].decode('utf-8') if node is not None else ''

    def character_col(point) -> int:
        row, column = point
        return len(lines[row][:column].decode('utf-8')) + 1 if row < len(lines) else 1

    def span(node) -> dict:
        return dict(path=path, start_line=node.start_point.row + 1,
                    end_line=node.end_point.row + 1,
                    start_col=character_col(node.start_point), end_col=character_col(node.end_point),
                    start_byte=node.start_byte, end_byte=node.end_byte, text=text(node))

    nodes = list(_walk(root))
    diagnostics = tuple({'kind': 'MISSING' if node.is_missing else 'ERROR',
                         'message': f'C syntax {"missing " + node.type if node.is_missing else "error"}',
                         **span(node)}
                        for node in nodes if node.type == 'ERROR' or node.is_missing)
    if root.has_error:
        if not diagnostics:
            diagnostics = ({'kind': 'ERROR', 'message': 'C syntax tree contains a recovery error'},)
        return SyntaxIndex(path, 'tree-sitter', 'PARSE_ERROR', diagnostics)

    for node in nodes:
        if node.type != 'function_definition':
            continue
        owner = node.parent
        while owner is not None and owner.type != 'function_definition':
            owner = owner.parent
        if owner is not None:
            return SyntaxIndex(path, 'tree-sitter', 'ERROR',
                ({'kind': 'UNSUPPORTED_NESTED_FUNCTION',
                  'message': 'GNU nested function scope is not supported by this index', **span(node)},))

    macros = {text(node.child_by_field_name('name')) for node in nodes
              if node.type in {'preproc_function_def', 'preproc_def'}}
    file_values = set()
    for declaration in nodes:
        if declaration.type != 'declaration':
            continue
        owner = declaration.parent
        while owner is not None and owner.type != 'function_definition':
            owner = owner.parent
        if owner is not None:
            continue
        for item in declaration.children_by_field_name('declarator'):
            name = _decl_name(item)
            if name is not None and not _is_function_prototype(item):
                file_values.add(text(name))
    functions = []
    conditions = []
    assignments = []
    for node in nodes:
        if node.type in {'if_statement', 'while_statement', 'do_statement', 'for_statement',
                         'switch_statement', 'conditional_expression'}:
            condition = node.child_by_field_name('condition')
            if condition is not None:
                conditions.append(SyntaxCondition(**span(condition), kind=node.type))
        if node.type == 'assignment_expression':
            left, right = node.child_by_field_name('left'), node.child_by_field_name('right')
            operator = node.child_by_field_name('operator')
            assignments.append(SyntaxAssignment(**span(node), target=text(left),
                                                 operator=text(operator), value=text(right), kind='assignment'))
        if node.type != 'function_definition':
            continue
        declarator, body = node.child_by_field_name('declarator'), node.child_by_field_name('body')
        name_node = _decl_name(declarator)
        function_declarator = _function_declarator(declarator)
        if name_node is None or body is None or function_declarator is None:
            return SyntaxIndex(path, 'tree-sitter', 'ERROR',
                               ({'kind': 'UNSUPPORTED_DECLARATOR', 'message': 'Function declarator could not be indexed', **span(node)},))
        parameter_list = function_declarator.child_by_field_name('parameters')
        params = []
        for parameter in parameter_list.named_children if parameter_list is not None else ():
            name = _decl_name(parameter.child_by_field_name('declarator'))
            if name is not None:
                params.append(text(name))
        locals_ = list(params)
        body_nodes = list(_walk(body))
        for declaration in body_nodes:
            if declaration.type != 'declaration':
                continue
            for item in declaration.children_by_field_name('declarator'):
                if _is_function_prototype(item):
                    continue
                local_name = _decl_name(item)
                if local_name is not None:
                    locals_.append(text(local_name))
        calls = []
        for call in body_nodes:
            if call.type != 'call_expression':
                continue
            callee = call.child_by_field_name('function')
            expression = text(callee)
            kind, name = 'indirect', ''
            if callee is not None and callee.type == 'identifier':
                if expression in macros:
                    kind, name = 'macro', expression
                elif expression not in locals_ and expression not in file_values:
                    kind, name = 'direct', expression
            calls.append(SyntaxCall(**span(call), name=name, expression=expression, kind=kind,
                                    conditional=_conditional(call)))
        functions.append(SyntaxFunction(**span(node), name=text(name_node),
            signature=raw[node.start_byte:body.start_byte].decode('utf-8').rstrip(),
            is_static=any(part.type == 'storage_class_specifier' and text(part) == 'static'
                          for part in node.named_children),
            params=tuple(params), local_names=tuple(dict.fromkeys(locals_)), calls=tuple(calls),
            def_line=name_node.start_point.row + 1, body_open_line=body.start_point.row + 1,
            body_close_line=body.end_point.row + 1, body_start_byte=body.start_byte, body_end_byte=body.end_byte,
            conditional=_conditional(node)))
    return SyntaxIndex(path, 'tree-sitter', 'PASS', functions=tuple(functions),
                       conditions=tuple(conditions), assignments=tuple(assignments))


def parse_c_syntax(source: str, path: str = '<memory>', *, backend: str = 'auto') -> SyntaxIndex:
    """Return trustworthy syntax or an explicit disabled/unavailable/error state.

    No recovered tree is published as a complete function index. Callers may
    choose their basic parser on non-PASS states and must retain that status.
    """
    if backend not in {'auto', 'tree-sitter', 'builtin'}:
        raise ValueError(f'Unknown C syntax backend: {backend}')
    if not isinstance(source, str):
        raise TypeError('source must be a string')
    path = str(path).replace('\\', '/')
    if backend == 'builtin':
        return SyntaxIndex(path, 'builtin', 'DISABLED')
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_c
    except ImportError:
        return SyntaxIndex(path, 'tree-sitter', 'UNAVAILABLE',
                           ({'kind': 'DEPENDENCY_MISSING', 'message': 'Install ecdet[syntax] for the C syntax backend'},))
    try:
        parser = Parser(Language(tree_sitter_c.language()))
        tree = parser.parse(source.encode('utf-8'))
        return _extract(source, path, tree.root_node)
    except Exception as exc:
        return SyntaxIndex(path, 'tree-sitter', 'ERROR',
                           ({'kind': 'BACKEND_ERROR', 'message': f'C syntax backend failed: {type(exc).__name__}'},))
