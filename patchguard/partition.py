import ast
import os
import re
from collections import deque, defaultdict

from .mine import module_name, package_of, collect_known_packages


def compute_t_module(touched_files, issue_text, known_packages, top_package):
    """Packages touched by the diff plus packages named in the issue."""
    t_module = set()
    for f in touched_files:
        rel = f[len(top_package) + 1:] if f.startswith(top_package + '/') else f
        mod = module_name('', f, '')
        pkg = package_of(mod, known_packages)
        t_module.add(pkg)

    issue_lower = (issue_text or '').lower()
    for pkg in known_packages:
        if pkg == top_package:
            continue
        leaf = pkg.split('.')[-1]
        if len(leaf) >= 4 and re.search(r'\b' + re.escape(leaf) + r'\b', issue_lower):
            t_module.add(pkg)
    return t_module


def compute_t_symbol(pre_reads, post_reads, issue_text, touched_modules=None):
    """New functions plus functions in touched modules that the issue names."""
    t_symbol = set()
    new_qualnames = set(post_reads) - set(pre_reads)
    t_symbol |= new_qualnames

    issue_lower = (issue_text or '').lower()
    candidates = post_reads
    if touched_modules:
        candidates = {qn: v for qn, v in post_reads.items() if qn.split('::')[0] in touched_modules}
    for qn in candidates:
        func_name = qn.split('::')[-1].split('.')[-1]
        if len(func_name) >= 4 and re.search(r'\b' + re.escape(func_name) + r'\b', issue_lower):
            t_symbol.add(qn)
    return t_symbol


def classify_intent(issue_text):
    """Keyword heuristic returning (intent, boundary, k); placeholder for an LLM classifier."""
    text = (issue_text or '').lower()
    title = text.splitlines()[0] if text else ''
    if 'refactor' in title:
        m = re.search(r'refactor\s+(\w+)', title)
        boundary = m.group(1) if m else None
        return 'refactor', boundary, 2
    bug_kw = ('bug', 'error', 'exception', 'incorrect', 'fails', 'crash', 'traceback',
              'raises', "doesn't work", 'does not work', 'misleading', 'wrong')
    if any(k in text for k in bug_kw):
        return 'bugfix', None, 1
    feature_kw = ('feature', 'would like', 'support', 'add ', 'enhancement')
    if any(k in title for k in feature_kw) or 'description' in text[:200].lower():
        return 'feature', None, 1
    return 'bugfix', None, 1


def build_call_graph(repo_root, top_package):
    """Intra-file call graph covering direct calls and self.method() calls."""
    from .mine import iter_py_files
    calls = defaultdict(set)

    for path in iter_py_files(repo_root, top_package):
        mod = module_name(repo_root, path, top_package)
        try:
            tree = ast.parse(open(path, encoding='utf-8').read())
        except (SyntaxError, UnicodeDecodeError):
            continue

        local_funcs = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                local_funcs.add(node.name)

        classes = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes[node.name] = ([b.id for b in node.bases if isinstance(b, ast.Name)],
                                      {n.name for n in node.body if isinstance(n, ast.FunctionDef)})

        def owner_of(stack, attr):
            cls = next((c for c in reversed(stack) if c in classes), None)
            queue, seen = deque([cls] if cls else []), set()
            while queue:
                c = queue.popleft()
                if c in seen or c not in classes:
                    continue
                seen.add(c)
                if attr in classes[c][1]:
                    return c
                queue.extend(classes[c][0])
            return cls

        def visit(node, stack):
            if isinstance(node, ast.ClassDef):
                stack = stack + [node.name]
                for child in ast.iter_child_nodes(node):
                    visit(child, stack)
                return
            if isinstance(node, ast.FunctionDef):
                qualname = '.'.join(stack + [node.name])
                full_qn = f"{mod}::{qualname}"
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        f = sub.func
                        if isinstance(f, ast.Name) and f.id in local_funcs and f.id != node.name:
                            calls[full_qn].add(f"{mod}::{f.id}")
                        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == 'self':
                            owner = owner_of(stack, f.attr)
                            target = f"{mod}::{owner}.{f.attr}" if owner else f"{mod}::{f.attr}"
                            calls[full_qn].add(target)
                stack = stack + [node.name]
            for child in ast.iter_child_nodes(node):
                visit(child, stack)

        visit(tree, [])

    return calls


def n_hop_call_graph(seed_set, call_graph, k):
    """Nodes within k hops over call edges, in both directions."""
    reverse = defaultdict(set)
    for a, targets in call_graph.items():
        for b in targets:
            reverse[b].add(a)

    visited = set(seed_set)
    frontier = deque((s, 0) for s in seed_set)
    while frontier:
        node, dist = frontier.popleft()
        if dist >= k:
            continue
        neighbors = call_graph.get(node, set()) | reverse.get(node, set())
        for nb in neighbors:
            if nb not in visited:
                visited.add(nb)
                frontier.append((nb, dist + 1))
    return visited


def n_hop_import_graph(seed_pkgs, import_edges, k):
    """Packages within k hops over import edges, in both directions."""
    fwd = defaultdict(set)
    rev = defaultdict(set)
    for key in import_edges:
        a, b = key.split('=>')
        fwd[a].add(b)
        rev[b].add(a)

    visited = set(seed_pkgs)
    frontier = deque((s, 0) for s in seed_pkgs)
    while frontier:
        node, dist = frontier.popleft()
        if dist >= k:
            continue
        for nb in fwd.get(node, set()) | rev.get(node, set()):
            if nb not in visited:
                visited.add(nb)
                frontier.append((nb, dist + 1))
    return visited


def partition_e_findings(new_pairs, t_module, b_pkgs, import_edges, k):
    """Classify new package edges by whether the target is within the declared scope."""
    licensed = t_module | b_pkgs | n_hop_import_graph(t_module | b_pkgs, import_edges, k)
    results = []
    for item in new_pairs:
        pair = item['pair']
        src, tgt = pair.split('=>')
        verdict = 'scope' if tgt in licensed else 'frame'
        reason = (f"target package '{tgt}' is in T_module/B or within {k}-hop import-graph "
                  f"neighborhood of declared scope" if verdict == 'scope'
                  else f"target package '{tgt}' is outside declared scope (not in T_module/B, "
                       f"not within {k}-hop import-graph neighborhood)")
        results.append({**item, 'verdict': verdict, 'reason': reason})
    return results


def partition_readset_findings(read_changes, t_symbol, call_graph, k):
    licensed = t_symbol | n_hop_call_graph(t_symbol, call_graph, k)
    results = []
    for item in read_changes:
        qn = item['function']
        verdict = 'scope' if qn in licensed else 'frame'
        reason = (f"'{qn.split('::')[-1]}' is in T_symbol or within {k}-hop CALL-GRAPH "
                  f"neighborhood of declared scope" if verdict == 'scope'
                  else f"'{qn.split('::')[-1]}' is outside declared scope (not in T_symbol, "
                       f"not within {k}-hop call-graph neighborhood)")
        results.append({**item, 'verdict': verdict, 'reason': reason})
    return results


PROTOCOL_METHODS = {
    '__get__', '__set__', '__delete__', '__getattr__', '__getattribute__', '__setattr__', '__delattr__',
    '__eq__', '__hash__', '__bool__', '__len__', '__iter__', '__contains__', '__call__', '__new__',
    '__init_subclass__', '__instancecheck__', '__subclasscheck__'}


def protocol_findings(pre_sigs, post_sigs, intent_text=''):
    """New protocol methods added to existing classes; out of scope unless the intent names the class."""
    pre_owners = {(q.split('::')[0], q.split('::')[1].rsplit('.', 1)[0]) for q in pre_sigs if '.' in q.split('::')[1]}
    text = (intent_text or '').lower()
    out = []
    for qn in sorted(set(post_sigs) - set(pre_sigs)):
        module, qual = qn.split('::')
        if '.' not in qual:
            continue
        owner, method = qual.rsplit('.', 1)
        if method not in PROTOCOL_METHODS or (module, owner) not in pre_owners:
            continue
        named = owner.split('.')[-1].lower() in text
        out.append({'function': qn, 'owner': owner, 'method': method, 'verdict': 'scope' if named else 'frame',
                    'reason': f"'{owner}' gains the protocol method {method}, which changes how all its instances behave"
                              + (" (the class is named in the intent)" if named else '')})
    return out


def is_private(qualname):
    name = qualname.split('::')[-1].split('.')[-1]
    return name.startswith('_') and not (name.startswith('__') and name.endswith('__'))


def diff_signatures(pre_sigs, post_sigs, skip_modules=()):
    """Breaking signature changes and removals (with a rename hint); skip_modules are not compared."""
    from .mine import classify_signature_change
    findings = []
    for qn in sorted(set(pre_sigs) & set(post_sigs)):
        changes = classify_signature_change(pre_sigs[qn], post_sigs[qn])
        breaking = [c for c in changes if c['severity'] == 'breaking']
        if breaking:
            findings.append({'function': qn, 'changes': breaking, 'private': is_private(qn)})
    added = {qn: sig for qn, sig in post_sigs.items() if qn not in pre_sigs}
    for qn in sorted(set(pre_sigs) - set(post_sigs)):
        module = qn.split('::')[0]
        if module in skip_modules:
            continue
        change = {'kind': 'removed_function', 'param': None, 'severity': 'breaking'}
        same_shape = [a for a, sig in added.items()
                      if a.split('::')[0] == module and sig == pre_sigs[qn]]
        if same_shape:
            change['possibly_renamed_to'] = same_shape[0].split('::')[-1]
        findings.append({'function': qn, 'changes': [change], 'private': is_private(qn)})
    return findings


def partition_signature_findings(sig_changes, t_symbol, call_graph, k):
    """Classify breaking signature changes by whether the function is within scope."""
    licensed = t_symbol | n_hop_call_graph(t_symbol, call_graph, k)
    results = []
    for item in sig_changes:
        qn = item['function']
        renamed = next((c['possibly_renamed_to'] for c in item['changes'] if c.get('possibly_renamed_to')), None)
        renamed_qn = f"{qn.split('::')[0]}::{renamed}" if renamed else None
        verdict = 'scope' if qn in licensed or (renamed_qn and renamed_qn in licensed) else 'frame'
        kinds = ', '.join(c['kind'] for c in item['changes'])
        reason = (f"'{qn.split('::')[-1]}' signature changed ({kinds}) but is in T_symbol "
                  f"or within {k}-hop call-graph neighborhood of declared scope" if verdict == 'scope'
                  else f"'{qn.split('::')[-1]}' signature changed ({kinds}) outside declared "
                       f"scope - existing callers elsewhere may break silently")
        results.append({**item, 'verdict': verdict, 'reason': reason})
    return results
