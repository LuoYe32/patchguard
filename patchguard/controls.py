import ast
import os


def read_source(repo_dir, file_rel):
    with open(os.path.join(repo_dir, file_rel), encoding='utf-8') as f:
        return f.read()


def write_source(repo_dir, file_rel, text):
    with open(os.path.join(repo_dir, file_rel), 'w', encoding='utf-8') as f:
        f.write(text)


def function_sites(tree):
    """(qualname, node) for module- and class-level functions, nested functions excluded."""
    sites = []

    def walk(node, stack):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                walk(child, stack + [child.name])
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sites.append(('.'.join(stack + [child.name]), child))

    walk(tree, [])
    return sites


def body_anchor(node):
    """(0-based line index to insert before, indent) for a statement at the top of a function body,
    placed after the docstring."""
    first = node.body[0]
    has_doc = isinstance(first, ast.Expr) and isinstance(getattr(first, 'value', None), ast.Constant) \
        and isinstance(first.value.value, str)
    if has_doc and len(node.body) > 1:
        return node.body[1].lineno - 1, ' ' * node.body[1].col_offset
    if has_doc:
        return first.end_lineno, ' ' * first.col_offset
    return first.lineno - 1, ' ' * first.col_offset


def insert_statement(repo_dir, file_rel, lineno, text):
    """Insert one statement at the top of the function defined at lineno; returns the function node."""
    content = read_source(repo_dir, file_rel)
    node = next(n for n in ast.walk(ast.parse(content))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno == lineno)
    idx, indent = body_anchor(node)
    lines = content.splitlines(keepends=True)
    lines.insert(idx, f"{indent}{text}\n")
    write_source(repo_dir, file_rel, ''.join(lines))
    return node


def _signature_end(node):
    """(line, byte column) just after the last parameter or default of a function signature."""
    ends = []
    args = node.args
    for a in args.posonlyargs + args.args + args.kwonlyargs + [x for x in (args.vararg, args.kwarg) if x]:
        ends.append((a.end_lineno, a.end_col_offset))
    for d in args.defaults + [d for d in args.kw_defaults if d is not None]:
        ends.append((d.end_lineno, d.end_col_offset))
    return max(ends)


def append_optional_param(repo_dir, file_rel, lineno, name='synthetic_optional_param'):
    """Append `name=None` after the last parameter (a backward-compatible signature change)."""
    content = read_source(repo_dir, file_rel)
    node = next(n for n in ast.walk(ast.parse(content))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno == lineno)
    end_line, end_col = _signature_end(node)
    lines = content.splitlines(keepends=True)
    raw = lines[end_line - 1].encode('utf-8')
    lines[end_line - 1] = (raw[:end_col] + f", {name}=None".encode() + raw[end_col:]).decode('utf-8')
    write_source(repo_dir, file_rel, ''.join(lines))


def pick_decoy_site(src, excluded, module_dotted, known, need_read=False, need_signature=False):
    """First deterministic out-of-scope function usable for a decoy.

    known: pre-patch read sets (need_read) or signatures (need_signature) keyed by module::qualname.
    Returns (qualname, lineno, param, attr) with param/attr set when need_read."""
    for qualname, node in function_sites(ast.parse(src)):
        if qualname in excluded or node.name.startswith('__') or not node.body:
            continue
        key = f"{module_dotted}::{qualname}"
        if need_signature:
            if key not in known or node.args.kwarg is not None or not (node.args.args or node.args.kwonlyargs):
                continue
            return qualname, node.lineno, None, None
        if need_read:
            reads = [r for r in known.get(key, []) if r.partition('.')[0] in {a.arg for a in node.args.args}]
            if reads:
                param, _, attr = reads[0].partition('.')
                return qualname, node.lineno, param, attr
            continue
        return qualname, node.lineno, None, None
    return None, None, None, None
