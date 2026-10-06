import ast
import json
import os
import sys
from collections import defaultdict


def iter_py_files(root, top_package):
    base = os.path.join(root, top_package)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in ('tests', '.git', '__pycache__', 'extern', 'cextern')]
        for fn in filenames:
            if fn.endswith('.py'):
                yield os.path.join(dirpath, fn)


def module_name(root, path, top_package):
    rel = os.path.relpath(path, root)
    rel = rel[:-3] if rel.endswith('.py') else rel
    parts = rel.split(os.sep)
    if parts[-1] == '__init__':
        parts = parts[:-1]
    return '.'.join(parts)


def collect_known_packages(root, top_package):
    """Dotted names of directories that are packages (contain __init__.py)."""
    known = set()
    base = os.path.join(root, top_package)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in ('tests', '.git', '__pycache__', 'extern', 'cextern')]
        if '__init__.py' in filenames:
            rel = os.path.relpath(dirpath, root)
            known.add('.'.join(rel.split(os.sep)))
    return known


def package_of(mod, known_packages):
    """Package of a dotted module name: its containing directory, unless it is itself a package."""
    if mod in known_packages:
        return mod
    parts = mod.split('.')
    return '.'.join(parts[:-1]) if len(parts) > 1 else parts[0]


def resolve_import(node, current_mod, top_package, known_modules=None, is_package=False):
    """Resolve an import node to dotted in-repo module names.

    known_modules (modules and packages of the repo) lets `from X import name` resolve to X.name when
    name is itself a module or package; is_package marks an __init__ file, whose relative imports start
    at the package itself."""
    targets = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            targets.append(alias.name)
    elif isinstance(node, ast.ImportFrom):
        if node.level and node.level > 0:
            cur_parts = current_mod.split('.')
            pkg_parts = cur_parts if is_package else cur_parts[:-1]
            up = node.level - 1
            if up > 0:
                pkg_parts = pkg_parts[:-up] if up <= len(pkg_parts) else []
            base = '.'.join(pkg_parts)
            if node.module:
                full = f"{base}.{node.module}" if base else node.module
            else:
                full = base
        else:
            full = node.module
        if full:
            for alias in node.names:
                candidate = f"{full}.{alias.name}"
                targets.append(candidate if known_modules and candidate in known_modules else full)
    return sorted({t for t in targets if t.startswith(top_package)})


class FuncReadSetVisitor(ast.NodeVisitor):
    """Collect, per function, the attributes read on its own parameters."""

    def __init__(self):
        self.results = {}
        self._stack = []

    def visit_FunctionDef(self, node):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_func(node)

    def _visit_func(self, node):
        qualname = '.'.join(self._stack + [node.name])
        param_names = set()
        args = node.args
        for a in (args.posonlyargs + args.args + args.kwonlyargs):
            param_names.add(a.arg)
        if args.vararg:
            param_names.add(args.vararg.arg)
        if args.kwarg:
            param_names.add(args.kwarg.arg)

        reads = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                if sub.value.id in param_names:
                    reads.add(f"{sub.value.id}.{sub.attr}")
        self.results[qualname] = sorted(reads | set(self.results.get(qualname, [])))

        self._stack.append(node.name)
        for child in ast.iter_child_nodes(node):
            self.visit(child)
        self._stack.pop()

    def visit_ClassDef(self, node):
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()


class SignatureVisitor(ast.NodeVisitor):
    """Collect a normalized signature per module- or class-level function; nested functions are not API."""

    def __init__(self):
        self.results = {}
        self._stack = []
        self._in_function = 0

    def visit_FunctionDef(self, node):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_func(node)

    def _visit_func(self, node):
        qualname = '.'.join(self._stack + [node.name])
        args = node.args
        n_defaults = len(args.defaults)
        positional = args.posonlyargs + args.args
        n_pos = len(positional)
        sig = {
            'positional': [
                {'name': a.arg, 'has_default': i >= n_pos - n_defaults}
                for i, a in enumerate(positional)
            ],
            'vararg': args.vararg.arg if args.vararg else None,
            'kwonly': [
                {'name': a.arg, 'has_default': d is not None}
                for a, d in zip(args.kwonlyargs, args.kw_defaults)
            ],
            'kwarg': args.kwarg.arg if args.kwarg else None,
        }
        if not self._in_function:
            self.results.setdefault(qualname, sig)

        self._stack.append(node.name)
        self._in_function += 1
        for child in ast.iter_child_nodes(node):
            self.visit(child)
        self._in_function -= 1
        self._stack.pop()

    def visit_ClassDef(self, node):
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()


def classify_signature_change(pre_sig, post_sig):
    """Changes between two signatures, each tagged 'breaking' or 'compatible'."""
    changes = []
    pre_pos = {p['name']: p for p in pre_sig['positional']}
    post_pos = {p['name']: p for p in post_sig['positional']}
    pre_names_ordered = [p['name'] for p in pre_sig['positional']]
    post_names_ordered = [p['name'] for p in post_sig['positional']]

    for name in pre_names_ordered:
        if name not in post_pos:
            changes.append({'kind': 'removed_param', 'param': name, 'severity': 'breaking'})
        elif pre_pos[name]['has_default'] and not post_pos[name]['has_default']:
            changes.append({'kind': 'param_now_required', 'param': name, 'severity': 'breaking'})

    for i, name in enumerate(post_names_ordered):
        if name not in pre_pos:
            sev = 'compatible' if post_pos[name]['has_default'] else 'breaking'
            kind = 'added_optional_param' if sev == 'compatible' else 'added_required_param'
            changes.append({'kind': kind, 'param': name, 'severity': sev})

    common = [n for n in pre_names_ordered if n in post_pos]
    common_post_order = [n for n in post_names_ordered if n in pre_pos]
    if common != common_post_order:
        changes.append({'kind': 'reordered_params', 'param': None, 'severity': 'breaking'})

    pre_kw = {p['name']: p for p in pre_sig['kwonly']}
    post_kw = {p['name']: p for p in post_sig['kwonly']}
    for name, p in pre_kw.items():
        if name not in post_kw and name not in post_pos:
            changes.append({'kind': 'removed_param', 'param': name, 'severity': 'breaking'})
        elif name in post_kw and p['has_default'] and not post_kw[name]['has_default']:
            changes.append({'kind': 'param_now_required', 'param': name, 'severity': 'breaking'})
    for name, p in post_kw.items():
        if name not in pre_kw and name not in pre_pos:
            kind = 'added_optional_param' if p['has_default'] else 'added_required_param'
            changes.append({'kind': kind, 'param': name,
                            'severity': 'compatible' if p['has_default'] else 'breaking'})

    if pre_sig['vararg'] and not post_sig['vararg']:
        changes.append({'kind': 'removed_vararg', 'param': pre_sig['vararg'], 'severity': 'breaking'})
    if pre_sig['kwarg'] and not post_sig['kwarg']:
        changes.append({'kind': 'removed_kwarg', 'param': pre_sig['kwarg'], 'severity': 'breaking'})

    return changes


def mine(root, top_package):
    edges = defaultdict(int)
    readsets = {}
    known_packages = collect_known_packages(root, top_package)
    known_modules = {module_name(root, p, top_package) for p in iter_py_files(root, top_package)} | known_packages

    for path in iter_py_files(root, top_package):
        mod = module_name(root, path, top_package)
        is_package = os.path.basename(path) == '__init__.py'
        try:
            src = open(path, encoding='utf-8').read()
            tree = ast.parse(src, filename=path)
        except (SyntaxError, UnicodeDecodeError):
            continue

        cur_pkg = package_of(mod, known_packages)

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for target_mod in resolve_import(node, mod, top_package, known_modules, is_package):
                    target_pkg = package_of(target_mod, known_packages)
                    if target_pkg != cur_pkg:
                        edges[(cur_pkg, target_pkg)] += 1

        visitor = FuncReadSetVisitor()
        visitor.visit(tree)
        rel_mod = mod
        for qn, reads in visitor.results.items():
            full_qn = f"{rel_mod}::{qn}"
            readsets[full_qn] = reads

    return edges, readsets


def mine_signatures(root, top_package):
    """Signatures of all functions in a package, keyed by module::qualname."""
    signatures = {}
    for path in iter_py_files(root, top_package):
        mod = module_name(root, path, top_package)
        try:
            tree = ast.parse(open(path, encoding='utf-8').read(), filename=path)
        except (SyntaxError, UnicodeDecodeError):
            continue
        visitor = SignatureVisitor()
        visitor.visit(tree)
        for qn, sig in visitor.results.items():
            signatures[f"{mod}::{qn}"] = sig
    return signatures


def harvest_known_attrs(readsets, scope_prefix=None, min_count=2):
    """Attribute names read at least min_count times, most frequent first."""
    from collections import Counter
    counts = Counter()
    for qn, reads in readsets.items():
        if scope_prefix and not qn.startswith(scope_prefix):
            continue
        for r in reads:
            attr = r.split('.', 1)[1] if '.' in r else r
            counts[attr] += 1
    return [attr for attr, c in counts.most_common() if c >= min_count]


if __name__ == '__main__':
    root, top_package, out_prefix = sys.argv[1], sys.argv[2], sys.argv[3]
    edges, readsets = mine(root, top_package)
    edges_json = {f"{a}=>{b}": c for (a, b), c in sorted(edges.items())}
    with open(f"{out_prefix}_graph.json", 'w') as f:
        json.dump(edges_json, f, indent=1, sort_keys=True)
    with open(f"{out_prefix}_readsets.json", 'w') as f:
        json.dump(readsets, f, indent=1, sort_keys=True)
    print(f"packages seen: {len(set(a for a,_ in edges) | set(b for _,b in edges))}")
    print(f"edges: {len(edges)}")
    print(f"functions with read-sets: {len(readsets)}")
