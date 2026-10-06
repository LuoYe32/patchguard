"""Static caller-compatibility check for signature changes: a call site that fitted the old signature
but no longer fits the new one (or calls a removed function) is a concrete breakage, found without
running tests."""
import ast
import os
from collections import defaultdict

from .hygiene import is_test_path
from .mine import module_name, resolve_import

SKIP_DIRS = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', 'build', 'dist', '.tox'}
MAX_REPORTED = 10


def iter_repo_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith('.')]
        for fn in filenames:
            if fn.endswith('.py'):
                yield os.path.join(dirpath, fn)


class FileScan(ast.NodeVisitor):
    def __init__(self, module, is_package, rel_path):
        self.module, self.is_package, self.rel_path = module, is_package, rel_path
        self.aliases, self.calls, self.classes, self._cls = {}, [], [], []

    def visit_Import(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]

    def visit_ImportFrom(self, node):
        bases = resolve_import(node, self.module, '', None, self.is_package)
        base = bases[0] if bases else ''
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{base}.{a.name}" if base else a.name

    def visit_ClassDef(self, node):
        bases = [b.id if isinstance(b, ast.Name) else b.attr for b in node.bases if isinstance(b, (ast.Name, ast.Attribute))]
        self.classes.append((node.name, self.module, bases))
        self._cls.append(node.name)
        self.generic_visit(node)
        self._cls.pop()

    def visit_Call(self, node):
        func, receiver = node.func, None
        if isinstance(func, ast.Name):
            name, kind = func.id, 'name'
        elif isinstance(func, ast.Attribute):
            name, value = func.attr, func.value
            if isinstance(value, ast.Name) and value.id in ('self', 'cls'):
                kind = 'self'
            elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == 'super':
                kind = 'super'
            else:
                kind, receiver = 'attr', value.id if isinstance(value, ast.Name) else None
        else:
            self.generic_visit(node)
            return
        self.calls.append({
            'name': name, 'kind': kind, 'receiver': receiver, 'file': self.rel_path, 'line': node.lineno,
            'module': self.module, 'aliases': self.aliases, 'cls': self._cls[-1] if self._cls else None,
            'n_pos': len(node.args), 'kws': [k.arg for k in node.keywords if k.arg],
            'star': any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords)})
        self.generic_visit(node)


def scan_repo(root):
    """Call sites by callee name and the class hierarchy of the whole repository."""
    calls, classes = defaultdict(list), defaultdict(list)
    for path in iter_repo_files(root):
        try:
            tree = ast.parse(open(path, encoding='utf-8').read())
        except (SyntaxError, UnicodeDecodeError, ValueError):
            continue
        rel = os.path.relpath(path, root)
        scan = FileScan(module_name(root, path, ''), os.path.basename(path) == '__init__.py', rel)
        scan.visit(tree)
        for c in scan.calls:
            calls[c['name']].append(c)
        for name, module, bases in scan.classes:
            classes[name].append((module, bases))
    return {'calls': calls, 'classes': classes}


def descendants(index, class_name):
    """Names of classes that inherit (by simple name) from class_name, including itself."""
    children = defaultdict(set)
    for name, entries in index['classes'].items():
        for _, bases in entries:
            for b in bases:
                children[b].add(name)
    seen, stack = {class_name}, [class_name]
    while stack:
        for child in children[stack.pop()] - seen:
            seen.add(child)
            stack.append(child)
    return seen


def ancestors(index, class_name):
    """Names of classes class_name inherits from (by simple name), including itself."""
    seen, stack = {class_name}, [class_name]
    while stack:
        for _, bases in index['classes'].get(stack.pop(), []):
            for b in bases:
                if b not in seen:
                    seen.add(b)
                    stack.append(b)
    return seen


def candidate_sites(index, qualname_full, method_owners):
    module, qual = qualname_full.split('::')
    parts = qual.split('.')
    name, owner = parts[-1], parts[-2] if len(parts) > 1 else None
    sites = index['calls'].get(name, [])
    if owner is None:
        return [s for s in sites if
                (s['kind'] == 'name' and (s['module'] == module or s['aliases'].get(name) == f"{module}.{name}"
                                          or s['aliases'].get(name, '').rsplit('.', 1)[0] == module and name in s['aliases']))
                or (s['kind'] == 'attr' and s['receiver'] and s['aliases'].get(s['receiver']) == module)]
    family = descendants(index, owner)
    related = family | ancestors(index, owner)
    unique = method_owners.get(name, set()) <= related
    return [s for s in sites if (s['kind'] in ('self', 'super') and s['cls'] in family) or (s['kind'] == 'attr' and unique)]


def compatible(sig, site, bound):
    """Whether the call fits the signature; unknown (star arguments) counts as compatible."""
    if site['star']:
        return True
    positional = list(sig['positional'])
    if bound:
        first = next((i for i, p in enumerate(positional) if p['name'] in ('self', 'cls')), None)
        if first is not None:
            positional.pop(first)
    names = [p['name'] for p in positional]
    allowed = set(names) | {k['name'] for k in sig['kwonly']}
    if site['n_pos'] > len(names) and not sig['vararg']:
        return False
    for kw in site['kws']:
        if (kw not in allowed and not sig['kwarg']) or kw in names[:site['n_pos']]:
            return False
    supplied = set(names[:site['n_pos']]) | set(site['kws'])
    required = [p['name'] for p in positional if not p['has_default']] + [k['name'] for k in sig['kwonly'] if not k['has_default']]
    return all(r in supplied for r in required)


def inherited_after_removal(qualname_full, index, post_sigs):
    """True when a removed method is still defined by an ancestor class, so its calls keep working."""
    module, qual = qualname_full.split('::')
    parts = qual.split('.')
    if len(parts) < 2:
        return False
    owner, name = parts[-2], parts[-1]
    for anc in ancestors(index, owner) - {owner}:
        if any(q.split('::')[1].split('.')[-2:] == [anc, name] for q in post_sigs):
            return True
    return False


def broken_callers(qualname_full, pre_sig, post_sig, index, method_owners):
    """Call sites that fitted pre_sig but do not fit post_sig (post_sig None: function removed)."""
    bound_default = bool(pre_sig['positional']) and pre_sig['positional'][0]['name'] in ('self', 'cls')
    broken, checked = [], 0
    for site in candidate_sites(index, qualname_full, method_owners):
        bound = bound_default and site['kind'] in ('self', 'super', 'attr')
        if not compatible(pre_sig, site, bound):
            continue
        checked += 1
        if post_sig is None or not compatible(post_sig, site, bound):
            broken.append({'file': site['file'], 'line': site['line']})
    return broken, checked


def annotate_callers(sig_changes, pre_sigs, post_sigs, repo_root):
    """Add 'broken_callers' (up to MAX_REPORTED sites), 'broken_total' and 'callers_checked' to each signature finding."""
    if not sig_changes:
        return sig_changes
    index = scan_repo(repo_root)
    method_owners = defaultdict(set)
    for qn in set(pre_sigs) | set(post_sigs):
        parts = qn.split('::')[1].split('.')
        method_owners[parts[-1]].add(parts[-2] if len(parts) > 1 else None)
    out = []
    for item in sig_changes:
        qn = item['function']
        post_sig = post_sigs.get(qn)
        if post_sig is None and inherited_after_removal(qn, index, post_sigs):
            out.append({**item, 'broken_callers': [], 'broken_total': 0, 'callers_checked': 0, 'inherited': True})
            continue
        broken, checked = broken_callers(qn, pre_sigs[qn], post_sig, index, method_owners)
        source = [b for b in broken if not is_test_path(b['file'])]
        out.append({**item, 'broken_callers': source[:MAX_REPORTED], 'broken_total': len(source),
                    'broken_in_tests': len(broken) - len(source), 'callers_checked': checked})
    return out
