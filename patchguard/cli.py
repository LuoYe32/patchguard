import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import time

from .mine import mine, collect_known_packages, package_of, harvest_known_attrs, module_name, mine_signatures
from .partition import (compute_t_module, compute_t_symbol, classify_intent,
                        build_call_graph, partition_e_findings, partition_readset_findings, protocol_findings,
                        diff_signatures, partition_signature_findings)
from .baseline import setup_venv, run_baseline
from .report import generate_report
from .controls import insert_statement, append_optional_param, pick_decoy_site, read_source
from .oracle import verify_injection
from .hygiene import hygiene_findings
from .callers import annotate_callers


def run(cmd, cwd=None, check=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"cmd failed: {cmd}\nstdout={r.stdout}\nstderr={r.stderr}")
    return r


def prepare_repo(repo_url, base_commit, work_dir, tag):
    repo_dir = os.path.join(work_dir, f"repo_{tag}")
    if not os.path.isdir(repo_dir):
        for attempt in range(4):
            try:
                run(["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, repo_dir])
                break
            except RuntimeError:
                shutil.rmtree(repo_dir, ignore_errors=True)
                if attempt == 3:
                    raise
                time.sleep(20 * (attempt + 1))
    for attempt in range(4):
        try:
            run(["git", "checkout", "--force", base_commit], cwd=repo_dir)
            break
        except RuntimeError:
            if attempt == 3:
                raise
            time.sleep(20 * (attempt + 1))
    run(["git", "clean", "-fdx", "."], cwd=repo_dir, check=False)
    return repo_dir


def extend_call_graph(pre_graph, post_graph, new_funcs):
    """Pre-patch call graph plus post-patch edges into functions the patch introduces."""
    graph = {caller: set(callees) for caller, callees in pre_graph.items()}
    for caller, callees in post_graph.items():
        added = callees & new_funcs
        if added:
            graph.setdefault(caller, set()).update(added)
    return graph


def syntax_findings(repo_dir, touched_files):
    """Touched .py files of the patched repo that no longer parse."""
    broken = []
    for f in touched_files:
        path = os.path.join(repo_dir, f)
        if not f.endswith('.py') or not os.path.exists(path):
            continue
        try:
            ast.parse(open(path, encoding='utf-8').read())
        except (SyntaxError, ValueError, UnicodeDecodeError) as e:
            broken.append({'file': f, 'error': f"{type(e).__name__}: {e}"[:200], 'verdict': 'frame',
                           'reason': f"'{f}' no longer parses; the patch breaks the module"})
    return broken


def scope_names(t_symbol_names, call_graph, module_dotted, k):
    """Bare qualnames of T_symbol and its k-hop call-graph neighborhood."""
    from .partition import n_hop_call_graph
    seeds = {qn for qn in t_symbol_names if '::' in qn and qn.split('::')[0] == module_dotted} | \
            {f"{module_dotted}::{n}" for n in t_symbol_names if '::' not in n}
    return set(t_symbol_names) | {qn.split('::', 1)[-1] for qn in n_hop_call_graph(seeds, call_graph, k)}


def mine_and_save(repo_dir, top_package, out_dir, prefix):
    edges, reads = mine(repo_dir, top_package)
    edges_json = {f"{a}=>{b}": c for (a, b), c in sorted(edges.items())}
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, f"{prefix}_graph.json"), 'w') as f:
        json.dump(edges_json, f, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, f"{prefix}_readsets.json"), 'w') as f:
        json.dump(reads, f, indent=1, sort_keys=True)
    return edges_json, reads


def diff_and_save(pre_edges, pre_reads, post_edges, post_reads, out_path):
    new_pairs = sorted(set(post_edges.keys()) - set(pre_edges.keys()))
    common = set(pre_reads) & set(post_reads)
    moved = {r for qn in set(post_reads) - set(pre_reads) for r in post_reads[qn]}
    read_changes = []
    for qn in sorted(common):
        added = sorted(set(post_reads[qn]) - set(pre_reads[qn]))
        removed = sorted(set(pre_reads[qn]) - set(post_reads[qn]) - moved)
        if added or removed:
            read_changes.append({'function': qn, 'added': added, 'removed': removed})
    report = {
        'new_package_pairs': [{'pair': p, 'count': post_edges[p]} for p in new_pairs],
        'read_set_changes': read_changes,
    }
    json.dump(report, open(out_path, 'w'), indent=1, sort_keys=True)
    return report


def siblings_of(pkg, all_pkgs):
    parent = '.'.join(pkg.split('.')[:-1])
    if not parent:
        return set()
    return {p for p in all_pkgs if p != pkg and '.'.join(p.split('.')[:-1]) == parent}


def find_e_injection_target(pre_edges_raw, touched_pkgs, t_module, k=1, known_pkgs=None):
    """Pick an isolated package pair outside the scope and its k-hop neighborhood."""
    from .partition import n_hop_import_graph
    fwd = {}
    for kk, v in pre_edges_raw.items():
        a, b = kk.split('=>')
        fwd[(a, b)] = v
    all_pkgs = set(a for a, _ in fwd) | set(b for _, b in fwd)
    reachable_within_k = n_hop_import_graph(t_module, pre_edges_raw, k)
    for p_i in touched_pkgs:
        sibs = siblings_of(p_i, all_pkgs)
        for p_j in sorted(all_pkgs):
            if p_j == p_i or p_j in t_module or p_j in reachable_within_k:
                continue
            if known_pkgs is not None and p_j not in known_pkgs:
                continue
            if fwd.get((p_i, p_j), 0) != 0 or fwd.get((p_j, p_i), 0) != 0:
                continue
            if any(fwd.get((s, p_j), 0) > 0 for s in sibs):
                continue
            return p_i, p_j
    return None, None


def pick_injection_files(repo_dir, touched_files):
    """Touched .py files that define a function, non-test files first."""
    candidates = [f for f in touched_files if f.endswith('.py')]
    non_test = [f for f in candidates
                if '/tests/' not in f and not os.path.basename(f).startswith('test_')]
    usable = []
    for f in non_test + [c for c in candidates if c not in non_test]:
        path = os.path.join(repo_dir, f)
        if not os.path.exists(path):
            continue
        try:
            tree = ast.parse(open(path, encoding='utf-8').read())
        except (SyntaxError, UnicodeDecodeError):
            continue
        if any(isinstance(n, ast.FunctionDef) and n.body for n in ast.walk(tree)):
            usable.append(f)
    return usable


def pick_injection_file(repo_dir, touched_files):
    """First touched .py file that defines a function, preferring non-test files."""
    usable = pick_injection_files(repo_dir, touched_files)
    return usable[0] if usable else None


def inject_e_violation(repo_dir, source_pkg, target_pkg, touched_file_rel):
    """Insert a function-scoped import of target_pkg into the first function of a file."""
    full_path = os.path.join(repo_dir, touched_file_rel)
    content = open(full_path, encoding='utf-8').read()
    lines = content.splitlines(keepends=True)
    tree = ast.parse(content)
    first_func = next((n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.body), None)
    if first_func is None:
        return None
    body_start_line = first_func.body[0].lineno
    insert_idx = body_start_line - 1
    first_body_line = lines[insert_idx]
    indent = ' ' * (len(first_body_line) - len(first_body_line.lstrip()))
    probe_name = "_synthetic_e_injection_probe"
    injected = (f"{indent}import {target_pkg}  # SYNTHETIC INJECTION (class E, Part B)\n"
                f"{indent}{probe_name} = dir({target_pkg.split('.')[0]})  # inert\n")
    lines.insert(insert_idx, injected)
    open(full_path, 'w', encoding='utf-8').write(''.join(lines))
    return {'type': 'E', 'source_pkg': source_pkg, 'target_pkg': target_pkg, 'file': touched_file_rel}


def find_readset_injection_target(repo_dir, touched_file_rel, t_symbol_names, known_attrs, pre_reads,
                                   call_graph=None, module_dotted_for_calls=None, k=1, inside=False):
    """Find a non-dunder method outside the scope (inside, if inside=True) and an unread self/cls attribute."""
    excluded = set(t_symbol_names)
    if call_graph is not None and module_dotted_for_calls:
        from .partition import n_hop_call_graph
        seeds = {qn for qn in t_symbol_names if qn.split('::')[0] == module_dotted_for_calls} | \
                {f"{module_dotted_for_calls}::{n}" for n in t_symbol_names if '::' not in n}
        reachable = n_hop_call_graph(seeds, call_graph, k)
        excluded |= {qn.split('::', 1)[-1] for qn in reachable}
    full_path = os.path.join(repo_dir, touched_file_rel)
    src = open(full_path, encoding='utf-8').read()
    tree = ast.parse(src)
    from .mine import FuncReadSetVisitor, module_name as _module_name
    visitor = FuncReadSetVisitor()
    visitor.visit(tree)
    file_module_dotted = _module_name('', touched_file_rel, '')
    prefix = f"{file_module_dotted}::"
    pre_existing_names = {qn[len(prefix):] for qn in pre_reads if qn.startswith(prefix)}

    def class_self_attrs_of(stack_with_class):
        """Attributes already read via self/cls in the given class."""
        class_prefix = f"{file_module_dotted}::{'.'.join(stack_with_class)}."
        attrs = set()
        for qn, reads in pre_reads.items():
            if qn.startswith(class_prefix):
                for r in reads:
                    p, _, a = r.partition('.')
                    if p in ('self', 'cls') and a:
                        attrs.add(a)
        return attrs

    def walk(node, stack, class_attrs):
        if isinstance(node, ast.ClassDef):
            new_stack = stack + [node.name]
            new_class_attrs = class_self_attrs_of(new_stack)
            for child in ast.iter_child_nodes(node):
                result = walk(child, new_stack, new_class_attrs)
                if result:
                    return result
            return None
        if isinstance(node, ast.FunctionDef):
            qualname = '.'.join(stack + [node.name])
            if (qualname in excluded) == inside and qualname in pre_existing_names:
                reads = set(visitor.results.get(qualname, []))
                params = [a.arg for a in node.args.args]
                for p in params:
                    if p not in ('self', 'cls') or not class_attrs or node.name.startswith('__'):
                        continue
                    for attr in sorted(class_attrs):
                        cand = f"{p}.{attr}"
                        if cand not in reads:
                            return qualname, p, attr, node.lineno
        for child in ast.iter_child_nodes(node):
            result = walk(child, stack, class_attrs)
            if result:
                return result
        return None

    result = walk(tree, [], set())
    return result if result else (None, None, None, None)


def inject_readset_violation(repo_dir, touched_file_rel, qualname, lineno, param, attr):
    """Insert an inert read of param.attr at the top of the function defined at lineno."""
    node = insert_statement(repo_dir, touched_file_rel, lineno, f"_synthetic_readset_probe = {param}.{attr}")
    return {'type': 'read-set', 'function': node.name, 'param': param, 'attr': attr,
            'file': touched_file_rel, 'qualname': qualname}


def find_d_injection_target(repo_dir, touched_file_rel, t_symbol_names, pre_sigs,
                             call_graph=None, module_dotted_for_calls=None, k=1, inside=False):
    """Find an existing function outside the scope (inside, if inside=True)."""
    excluded = set(t_symbol_names)
    if call_graph is not None and module_dotted_for_calls:
        from .partition import n_hop_call_graph
        seeds = {f"{module_dotted_for_calls}::{n}" for n in t_symbol_names if '::' not in n}
        reachable = n_hop_call_graph(seeds, call_graph, k)
        excluded |= {qn.split('::', 1)[-1] for qn in reachable}

    full_path = os.path.join(repo_dir, touched_file_rel)
    tree = ast.parse(open(full_path, encoding='utf-8').read())
    from .mine import module_name as _module_name
    prefix = f"{_module_name('', touched_file_rel, '')}::"
    pre_existing = {qn[len(prefix):] for qn in pre_sigs if qn.startswith(prefix)}

    def walk(node, stack):
        if isinstance(node, ast.ClassDef):
            for child in ast.iter_child_nodes(node):
                r = walk(child, stack + [node.name])
                if r:
                    return r
            return None
        if isinstance(node, ast.FunctionDef):
            qn = '.'.join(stack + [node.name])
            if (qn in excluded) == inside and qn in pre_existing:
                return qn, node.lineno
        for child in ast.iter_child_nodes(node):
            r = walk(child, stack)
            if r:
                return r
        return None

    result = walk(tree, [])
    return result if result else (None, None)


def inject_d_violation(repo_dir, touched_file_rel, func_name, lineno):
    """Add a required parameter to the function defined at lineno (a breaking signature change)."""
    full_path = os.path.join(repo_dir, touched_file_rel)
    lines = open(full_path, encoding='utf-8').read().splitlines(keepends=True)
    marker = f"def {func_name.split('.')[-1]}("
    line = lines[lineno - 1]
    idx = line.find(marker)
    assert idx != -1, f"could not find {marker!r} at {full_path}:{lineno}"
    cut = idx + len(marker)
    lines[lineno - 1] = line[:cut] + 'synthetic_required_param, ' + line[cut:]
    open(full_path, 'w', encoding='utf-8').write(''.join(lines))
    return {'type': 'D-signature', 'function': func_name, 'change': 'added_required_param',
            'param': 'synthetic_required_param', 'file': touched_file_rel}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'check':
        from .check import main as check_main
        return check_main(sys.argv[2:])
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-url', required=True)
    ap.add_argument('--base-commit', required=True)
    ap.add_argument('--patch-file', required=True)
    ap.add_argument('--top-package', required=True)
    ap.add_argument('--touched-packages', required=True, help='comma-separated, for T_module(P)')
    ap.add_argument('--known-attrs', default=None, help='comma-separated attributes to try for read-set injection (default: harvested from the repo)')
    ap.add_argument('--issue-text-file', default=None, help='path to a text file with the issue/problem_statement, for stage-4 T_module/T_symbol/intent extraction')
    ap.add_argument('--pass-to-pass-file', default=None, help='JSON file of PASS_TO_PASS test IDs; enables the baseline test run on every branch')
    ap.add_argument('--baseline-venv-dir', default=None, help='venv dir for stage 5 (reused/created); defaults to <work-dir>/baseline_venv')
    ap.add_argument('--baseline-test-file', default=None, help='test file for pytest-style repos whose PASS_TO_PASS names are bare (no "::")')
    ap.add_argument('--work-dir', required=True)
    ap.add_argument('--out-dir', required=True)
    ap.add_argument('--no-callers', action='store_true', help='skip the repository-wide caller-compatibility check of signature changes')
    ap.add_argument('--negative-only', action='store_true', help='analyze the given patch only; skip injected and control variants')
    args = ap.parse_args()

    issue_text = open(args.issue_text_file, encoding='utf-8').read() if args.issue_text_file else ''

    os.makedirs(args.work_dir, exist_ok=True)
    os.makedirs(args.out_dir, exist_ok=True)
    t_module = set(args.touched_packages.split(','))
    patch_abspath = os.path.abspath(args.patch_file)

    pre_repo = prepare_repo(args.repo_url, args.base_commit, args.work_dir, 'pre')
    pre_edges_raw, pre_reads = mine_and_save(pre_repo, args.top_package, args.out_dir, 'pre')
    pre_sigs = mine_signatures(pre_repo, args.top_package)

    if args.known_attrs:
        known_attrs = args.known_attrs.split(',')
        print(f"[known-attrs] manual: {known_attrs}")
    else:
        harvested = harvest_known_attrs(pre_reads, scope_prefix=None, min_count=2)
        known_attrs = harvested[:30]
        print(f"[known-attrs] auto-harvested top-{len(known_attrs)}: {known_attrs[:10]}{'...' if len(known_attrs) > 10 else ''}")

    touched_files = []
    for line in open(patch_abspath):
        if line.startswith('diff --git'):
            touched_files.append(line.split(' ')[2][2:])

    known_pkgs = collect_known_packages(pre_repo, args.top_package)
    t_module_computed = compute_t_module(touched_files, issue_text, known_pkgs, args.top_package) | t_module
    intent_class, boundary_name, k = classify_intent(issue_text)
    b_pkgs = {p for p in known_pkgs if boundary_name and boundary_name in p} if boundary_name else set()
    print(f"[stage4] intent={intent_class} k={k} B={b_pkgs or '{}'} T_module={t_module_computed}")
    call_graph = build_call_graph(pre_repo, args.top_package)
    touched_modules = {module_name('', f, '') for f in touched_files}

    def run_stage4(post_reads, diff_report, out_path, post_repo=None):
        t_symbol = compute_t_symbol(pre_reads, post_reads, issue_text, touched_modules)
        e_classified = partition_e_findings(diff_report['new_package_pairs'], t_module_computed, b_pkgs, pre_edges_raw, k)
        rs_classified = partition_readset_findings(diff_report['read_set_changes'], t_symbol, call_graph, k)
        d_classified, protocol_classified = [], []
        if post_repo is not None:
            post_sigs = mine_signatures(post_repo, args.top_package)
            protocol_classified = protocol_findings(pre_sigs, post_sigs, issue_text)
            sig_changes = diff_signatures(pre_sigs, post_sigs, broken_modules)
            if sig_changes and not args.no_callers:
                try:
                    sig_changes = annotate_callers(sig_changes, pre_sigs, post_sigs, post_repo)
                except Exception as e:
                    print(f"    [callers] skipped: {type(e).__name__}: {str(e)[:100]}")
            d_classified = partition_signature_findings(sig_changes, t_symbol, call_graph, k)
        result = {'e_findings': e_classified, 'readset_findings': rs_classified, 'd_findings': d_classified,
                  'syntax_findings': syntax_broken, 'hygiene_findings': patch_hygiene,
                  'protocol_findings': protocol_classified}
        json.dump(result, open(out_path, 'w'), indent=1, sort_keys=True)
        all_findings = e_classified + rs_classified + d_classified + syntax_broken + patch_hygiene + protocol_classified
        n_frame = sum(1 for x in all_findings if x['verdict'] == 'frame')
        n_scope = sum(1 for x in all_findings if x['verdict'] == 'scope')
        print(f"    stage4: {n_frame} FRAME (real findings), {n_scope} scope (expected effects) [D: {len(d_classified)}]")
        return result

    neg_repo = prepare_repo(args.repo_url, args.base_commit, args.work_dir, 'neg')
    run(["git", "apply", patch_abspath], cwd=neg_repo)
    patch_hygiene = hygiene_findings(open(patch_abspath, encoding='utf-8', errors='replace').read())
    if patch_hygiene:
        print(f"[hygiene] {len(patch_hygiene)} finding(s): {sorted({x['kind'] for x in patch_hygiene})}")
    syntax_broken = syntax_findings(neg_repo, touched_files)
    broken_modules = {module_name('', x['file'], '') for x in syntax_broken}
    if syntax_broken:
        print(f"[syntax] {len(syntax_broken)} touched file(s) no longer parse: {[x['file'] for x in syntax_broken]}")
    inj_file = pick_injection_file(neg_repo, touched_files)
    if inj_file is None:
        print("[inject] no touched .py file with a function to inject into - positive_* branches skipped")
    neg_dir = os.path.join(args.out_dir, 'negative')
    neg_edges_raw, neg_reads = mine_and_save(neg_repo, args.top_package, neg_dir, 'post')
    neg_report = diff_and_save(pre_edges_raw, pre_reads, neg_edges_raw, neg_reads,
                                os.path.join(neg_dir, 'diff_report.json'))
    call_graph = extend_call_graph(call_graph, build_call_graph(neg_repo, args.top_package),
                                   set(neg_reads) - set(pre_reads))
    print(f"[negative] new_pairs={len(neg_report['new_package_pairs'])} read_changes={len(neg_report['read_set_changes'])}")

    stage5_enabled = False
    baseline_python = None
    pass_to_pass_ids = None
    if args.pass_to_pass_file:
        baseline_venv = args.baseline_venv_dir or os.path.join(args.work_dir, 'baseline_venv')
        baseline_python, ok, err = setup_venv(baseline_venv, neg_repo)
        if ok:
            stage5_enabled = True
            pass_to_pass_ids = json.load(open(args.pass_to_pass_file))
            print(f"[stage5] venv ready, {len(pass_to_pass_ids)} PASS_TO_PASS tests to run per branch")
        else:
            print(f"[stage5] SKIPPED - venv/install failed: {err[:500]}")

    def run_stage5(repo_dir, out_path):
        if not stage5_enabled:
            return None
        result = run_baseline(repo_dir, baseline_python, pass_to_pass_ids,
                               test_file=args.baseline_test_file)
        json.dump(result, open(out_path, 'w'), indent=1)
        status = 'OK' if result.get('ok') else ('FAILED' if result.get('ok') is False else 'SKIPPED')
        print(f"    stage5: {status} ({result.get('runner')}, total={result.get('total') or result.get('passed')})")
        return result

    def run_stage6(classified, baseline, out_dir, label):
        """Write the human-readable report."""
        report = generate_report(classified, baseline, label)
        out_path = os.path.join(out_dir, 'report.md')
        open(out_path, 'w').write(report)
        return report

    neg_classified = run_stage4(neg_reads, neg_report, os.path.join(neg_dir, 'classified_report.json'), post_repo=neg_repo)
    neg_baseline = run_stage5(neg_repo, os.path.join(neg_dir, 'baseline_report.json'))
    run_stage6(neg_classified, neg_baseline, neg_dir, f"{args.top_package} / negative")

    if inj_file is None:
        return

    t_symbol_bare = {qn.split('::', 1)[-1] for qn in compute_t_symbol(pre_reads, neg_reads, issue_text, touched_modules)}
    cand_files = pick_injection_files(neg_repo, touched_files)

    def file_context(f):
        module = module_name('', f, '')
        return {'module': module, 'pkg': package_of(module, known_pkgs),
                'scope': scope_names(t_symbol_bare, call_graph, module, k),
                'graph': dict(call_graph=call_graph, module_dotted_for_calls=module, k=k)}

    def run_variant(tag, dirname, mutate, full=False):
        repo = prepare_repo(args.repo_url, args.base_commit, args.work_dir, tag)
        run(["git", "apply", patch_abspath], cwd=repo)
        out = os.path.join(args.out_dir, dirname)
        os.makedirs(out, exist_ok=True)
        snapshots = {f: read_source(repo, f) for f in cand_files}
        info = None
        for f in cand_files:
            info = mutate(repo, f, file_context(f))
            if info is not None:
                info['file'] = f
                break
        if info is None:
            print(f"[{dirname}] no valid site found - skipped")
            return
        if info.get('type') in ('E', 'read-set', 'D-signature'):
            info['oracle'] = verify_injection(info, snapshots[info['file']], read_source(repo, info['file']))
        json.dump(info, open(os.path.join(out, 'injection.json'), 'w'), indent=1)
        edges_raw, reads = mine_and_save(repo, args.top_package, out, 'post')
        report = diff_and_save(pre_edges_raw, pre_reads, edges_raw, reads, os.path.join(out, 'diff_report.json'))
        classified = run_stage4(reads, report, os.path.join(out, 'classified_report.json'), post_repo=repo)
        print(f"[{dirname}] {info['file']}: {info.get('qualname') or info.get('function') or info.get('pair') or info.get('target_pkg')}; "
              f"oracle={info.get('oracle', {}).get('verified')}")
        if full:
            baseline = run_stage5(repo, os.path.join(out, 'baseline_report.json'))
            run_stage6(classified, baseline, out, f"{args.top_package} / {dirname}")

    def mutate_e(repo, f, ctx):
        src_pkg, tgt_pkg = find_e_injection_target(pre_edges_raw, [ctx['pkg']], t_module_computed | b_pkgs, k, known_pkgs)
        return inject_e_violation(repo, src_pkg, tgt_pkg, f) if src_pkg is not None else None

    def mutate_readset(inside):
        def run_it(repo, f, ctx):
            fn, param, attr, lineno = find_readset_injection_target(
                repo, f, t_symbol_bare, known_attrs, pre_reads, inside=inside, **ctx['graph'])
            return inject_readset_violation(repo, f, fn, lineno, param, attr) if fn else None
        return run_it

    def mutate_d(inside):
        def run_it(repo, f, ctx):
            fn, lineno = find_d_injection_target(repo, f, t_symbol_bare, pre_sigs, inside=inside, **ctx['graph'])
            return inject_d_violation(repo, f, fn, lineno) if fn else None
        return run_it

    def mutate_decoy_optional(repo, f, ctx):
        qual, lineno, _, _ = pick_decoy_site(read_source(repo, f), ctx['scope'], ctx['module'],
                                             pre_sigs, need_signature=True)
        if qual is None:
            return None
        append_optional_param(repo, f, lineno)
        return {'type': 'decoy', 'decoy': 'optional-param', 'qualname': qual}

    def mutate_decoy_reread(repo, f, ctx):
        qual, lineno, param, attr = pick_decoy_site(read_source(repo, f), ctx['scope'], ctx['module'],
                                                    pre_reads, need_read=True)
        if qual is None:
            return None
        insert_statement(repo, f, lineno, f"_synthetic_decoy_probe = {param}.{attr}")
        return {'type': 'decoy', 'decoy': 'reread', 'qualname': qual, 'param': param, 'attr': attr}

    def mutate_decoy_noop(repo, f, ctx):
        qual, lineno, _, _ = pick_decoy_site(read_source(repo, f), ctx['scope'], ctx['module'], pre_reads)
        if qual is None:
            return None
        insert_statement(repo, f, lineno, "_synthetic_noop = None")
        return {'type': 'decoy', 'decoy': 'noop', 'qualname': qual}

    def mutate_decoy_edge(repo, f, ctx):
        existing = sorted(b for kk in pre_edges_raw for a, b in [kk.split('=>')] if a == ctx['pkg'] and b in known_pkgs)
        if not existing or inject_e_violation(repo, ctx['pkg'], existing[0], f) is None:
            return None
        return {'type': 'decoy', 'decoy': 'existing-edge', 'pair': f"{ctx['pkg']}=>{existing[0]}"}

    if args.negative_only or not cand_files:
        return
    run_variant('pos_e', 'positive_e', mutate_e, full=True)
    run_variant('pos_rs', 'positive_readset', mutate_readset(False), full=True)
    run_variant('pos_d', 'positive_d', mutate_d(False), full=True)
    run_variant('twin_rs', 'twin_readset', mutate_readset(True))
    run_variant('twin_d', 'twin_d', mutate_d(True))
    run_variant('decoy_opt', 'decoy_optional_param', mutate_decoy_optional)
    run_variant('decoy_rr', 'decoy_reread', mutate_decoy_reread)
    run_variant('decoy_noop', 'decoy_noop', mutate_decoy_noop)
    run_variant('decoy_edge', 'decoy_existing_edge', mutate_decoy_edge)


if __name__ == '__main__':
    main()
