import json
import os
import textwrap

from patchguard.mine import (classify_signature_change, collect_known_packages, mine,
                             mine_signatures, package_of)
from patchguard.partition import (compute_t_module, compute_t_symbol, n_hop_import_graph,
                                  partition_e_findings)
from patchguard.cli import (find_readset_injection_target, inject_e_violation,
                            pick_injection_file)


def write(root, rel, body=""):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(body))


def test_package_of_uses_containing_directory_not_fixed_depth():
    assert package_of("pkg.sub.mod", set()) == "pkg.sub"
    assert package_of("pkg.top_level_mod", set()) == "pkg"


def test_import_from_package_init_is_not_collapsed_to_parent(tmp_path):
    root = str(tmp_path)
    write(root, "pkg/__init__.py")
    write(root, "pkg/cosmology/__init__.py", "X = 1\n")
    write(root, "pkg/frames/__init__.py")
    write(root, "pkg/frames/f.py", "from pkg.cosmology import X\n")
    edges, _ = mine(root, "pkg")
    assert ("pkg.frames", "pkg.cosmology") in edges
    assert ("pkg.frames", "pkg") not in edges


def test_e_partition_checks_target_not_source():
    graph = {"a=>b": 1}
    out = partition_e_findings([{"pair": "a=>unrelated", "count": 1}],
                               t_module={"a"}, b_pkgs=set(), import_edges=graph, k=1)
    assert out[0]["verdict"] == "frame"
    out = partition_e_findings([{"pair": "a=>b", "count": 1}],
                               t_module={"a", "b"}, b_pkgs=set(), import_edges=graph, k=1)
    assert out[0]["verdict"] == "scope"


def test_t_module_ignores_the_projects_own_name_in_issue_text():
    known = {"proj", "proj.coords", "proj.io"}
    t = compute_t_module(["proj/coords/x.py"], "proj is broken when using proj", known, "proj")
    assert "proj" not in t and "proj.coords" in t


def test_t_symbol_name_matching_is_limited_to_touched_modules():
    post = {"m1::A.get_context_data": [], "m2::B.get_context_data": []}
    t = compute_t_symbol(dict(post), post, "overrides get_context_data()", touched_modules={"m1"})
    assert "m1::A.get_context_data" in t and "m2::B.get_context_data" not in t


def test_n_hop_propagation_uses_the_graph_it_is_given():
    pre = {"a=>b": 1}
    assert "c" not in n_hop_import_graph({"a"}, pre, 1)
    assert "c" in n_hop_import_graph({"a"}, {**pre, "a=>c": 1}, 1)


def sig(code, tmp_path, name):
    write(str(tmp_path), f"{name}/__init__.py")
    write(str(tmp_path), f"{name}/m.py", code)
    return next(iter(mine_signatures(str(tmp_path), name).values()))


def test_added_required_param_is_breaking_but_optional_is_compatible(tmp_path):
    old = sig("def f(a): pass\n", tmp_path, "old")
    req = sig("def f(a, b): pass\n", tmp_path, "req")
    opt = sig("def f(a, b=1): pass\n", tmp_path, "opt")
    assert [c["severity"] for c in classify_signature_change(old, req)] == ["breaking"]
    assert [c["severity"] for c in classify_signature_change(old, opt)] == ["compatible"]


def test_pick_injection_file_skips_docs_and_function_less_files(tmp_path):
    root = str(tmp_path)
    write(root, "docs/x.txt", "hi")
    write(root, "pkg/consts.py", "X = 1\n")
    write(root, "pkg/tests/test_a.py", "def test_a():\n    pass\n")
    write(root, "pkg/real.py", "def f():\n    return 1\n")
    files = ["docs/x.txt", "pkg/consts.py", "pkg/tests/test_a.py", "pkg/real.py"]
    assert pick_injection_file(root, files) == "pkg/real.py"
    assert pick_injection_file(root, files[:2]) is None


def test_e_injection_is_function_scoped_to_avoid_circular_imports(tmp_path):
    root = str(tmp_path)
    write(root, "pkg/__init__.py")
    write(root, "pkg/core.py", "import os\n\ndef f(a,\n      b):\n    return a\n")
    inject_e_violation(root, "pkg", "pkg.other", "pkg/core.py")
    text = open(os.path.join(root, "pkg/core.py")).read()
    compile(text, "core.py", "exec")
    assert text.index("import pkg.other") > text.index("def f(")


def test_readset_injection_uses_attributes_valid_for_the_same_class(tmp_path):
    root = str(tmp_path)
    write(root, "pkg/__init__.py")
    write(root, "pkg/view.py", """
        class View:
            def a(self):
                return self.term

            def b(self):
                return 1
    """)
    pre_reads = {k: v for k, v in mine(root, "pkg")[1].items()}
    fn, param, attr, _ = find_readset_injection_target(
        root, "pkg/view.py", set(), ["connection"], pre_reads)
    assert (fn, param, attr) == ("View.b", "self", "term")


def test_e_injection_source_is_the_edited_files_package_and_target_is_a_real_package():
    from patchguard.cli import find_e_injection_target
    edges = {"pkg.a=>pkg": 1, "pkg.b=>pkg": 1, "pkg.c=>pkg": 1, "pkg.bin=>pkg": 1}
    src, tgt = find_e_injection_target(edges, ["pkg.a"], {"pkg.a"}, 1,
                                       known_pkgs={"pkg", "pkg.a", "pkg.b", "pkg.c"})
    assert src == "pkg.a" and tgt in {"pkg.b", "pkg.c"}


def test_extend_call_graph_adds_edges_into_new_functions_only():
    from patchguard.cli import extend_call_graph
    pre = {'m::A.f': {'m::A.g'}}
    post = {'m::A.f': {'m::A.g', 'm::A.helper'}, 'm::A.h': {'m::A.helper', 'm::A.g'}}
    graph = extend_call_graph(pre, post, {'m::A.helper'})
    assert graph['m::A.f'] == {'m::A.g', 'm::A.helper'}
    assert graph['m::A.h'] == {'m::A.helper'}


def test_call_graph_resolves_self_calls_to_local_base_class(tmp_path):
    from patchguard.partition import build_call_graph
    pkg = tmp_path / 'proj'
    pkg.mkdir()
    (pkg / '__init__.py').write_text('')
    (pkg / 'm.py').write_text(
        'class Base:\n    def helper(self):\n        pass\n\n'
        'class Child(Base):\n    def run(self):\n        self.helper()\n')
    graph = build_call_graph(str(tmp_path), 'proj')
    assert graph['proj.m::Child.run'] == {'proj.m::Base.helper'}


def test_diff_signatures_reports_removed_and_renamed_functions():
    from patchguard.partition import diff_signatures, partition_signature_findings
    sig = {'positional': [{'name': 'self', 'has_default': False}], 'vararg': None, 'kwonly': [], 'kwarg': None}
    pre = {'m::A._old': sig, 'm::A.keep': sig, 'm::A.gone': {**sig, 'vararg': 'a'}}
    post = {'m::A._new': sig, 'm::A.keep': sig}
    findings = {f['function']: f for f in diff_signatures(pre, post)}
    assert set(findings) == {'m::A._old', 'm::A.gone'}
    assert findings['m::A._old']['changes'][0]['possibly_renamed_to'] == 'A._new'
    assert findings['m::A._old']['private'] and not findings['m::A.gone']['private']
    verdicts = {r['function']: r['verdict']
                for r in partition_signature_findings(list(findings.values()), {'m::A._new'}, {}, 1)}
    assert verdicts == {'m::A._old': 'scope', 'm::A.gone': 'frame'}


def test_readset_visitor_merges_property_getter_and_setter():
    import ast
    from patchguard.mine import FuncReadSetVisitor
    src = ('class C:\n    @property\n    def p(self):\n        return self.a\n'
           '    @p.setter\n    def p(self, v):\n        self.b = v\n        return v.x\n')
    visitor = FuncReadSetVisitor()
    visitor.visit(ast.parse(src))
    assert visitor.results['C.p'] == ['self.a', 'self.b', 'v.x']


def test_inject_readset_after_docstring_on_multiline_def(tmp_path):
    from patchguard.cli import inject_readset_violation
    f = tmp_path / 'm.py'
    f.write_text('class C:\n    def other(self):\n        pass\n\n    def run(\n            self,\n            x,\n    ):\n        """Doc."""\n        return 1\n')
    inject_readset_violation(str(tmp_path), 'm.py', 'C.run', 5, 'self', 'attr')
    import ast
    ast.parse(f.read_text())
    assert '        _synthetic_readset_probe = self.attr\n        return 1' in f.read_text()


def test_inject_d_uses_given_line_not_first_name_match(tmp_path):
    from patchguard.cli import inject_d_violation
    f = tmp_path / 'm.py'
    f.write_text('class A:\n    def run(self):\n        pass\n\nclass B:\n    def run(self):\n        pass\n')
    inject_d_violation(str(tmp_path), 'm.py', 'B.run', 6)
    assert 'def run(synthetic_required_param, self)' in f.read_text().splitlines()[5]
    assert f.read_text().splitlines()[1] == '    def run(self):'


def test_extract_method_moves_reads_not_counted_as_removed():
    from patchguard.cli import diff_and_save
    pre_reads = {'m::A.f': ['self.x', 'self.y']}
    post_reads = {'m::A.f': ['self.y'], 'm::A.helper': ['self.x']}
    report = diff_and_save({}, pre_reads, {}, post_reads, '/dev/null')
    assert report['read_set_changes'] == []


def test_signature_visitor_skips_nested_functions_but_keeps_methods():
    import ast
    from patchguard.mine import SignatureVisitor
    src = ('def outer():\n    def inner(a):\n        pass\n\nclass C:\n    def m(self):\n        def local():\n            pass\n')
    visitor = SignatureVisitor()
    visitor.visit(ast.parse(src))
    assert set(visitor.results) == {'outer', 'C.m'}


ORACLE_SRC = 'class C:\n    def run(self, x):\n        return self.a + x.b\n\ndef top(y):\n    return y\n'


def test_oracle_verifies_read_set_injection_from_bytecode(tmp_path):
    from patchguard.cli import inject_readset_violation
    from patchguard.oracle import verify_injection
    f = tmp_path / 'm.py'
    f.write_text(ORACLE_SRC)
    info = inject_readset_violation(str(tmp_path), 'm.py', 'C.run', 2, 'self', 'extra')
    assert verify_injection(info, ORACLE_SRC, f.read_text())['verified']
    assert not verify_injection(info, ORACLE_SRC, ORACLE_SRC)['verified']


def test_oracle_verifies_d_and_e_injections(tmp_path):
    from patchguard.cli import inject_d_violation, inject_e_violation
    from patchguard.oracle import verify_injection
    f = tmp_path / 'm.py'
    f.write_text(ORACLE_SRC)
    d_info = inject_d_violation(str(tmp_path), 'm.py', 'top', 5)
    assert verify_injection(d_info, ORACLE_SRC, f.read_text())['verified']
    f.write_text(ORACLE_SRC)
    e_info = inject_e_violation(str(tmp_path), 'proj.a', 'os.path', 'm.py')
    assert verify_injection(e_info, ORACLE_SRC, f.read_text())['verified']
    assert not verify_injection(e_info, ORACLE_SRC, ORACLE_SRC)['verified']


def test_oracle_rejects_injection_that_missed_its_target(tmp_path):
    from patchguard.oracle import verify_injection
    info = {'type': 'read-set', 'qualname': 'C.run', 'param': 'self', 'attr': 'extra'}
    other = ORACLE_SRC.replace('def top(y):\n    return y', 'def top(y):\n    z = y.extra\n    return z')
    assert not verify_injection(info, ORACLE_SRC, other)['verified']


def test_optional_param_decoy_is_a_compatible_signature_change(tmp_path):
    import ast
    from patchguard.controls import append_optional_param
    from patchguard.mine import SignatureVisitor, classify_signature_change
    src = 'def f(a, b=1,\n      *args):\n    pass\n\ndef g(x):\n    pass\n'
    f = tmp_path / 'm.py'
    f.write_text(src)
    append_optional_param(str(tmp_path), 'm.py', 1)
    append_optional_param(str(tmp_path), 'm.py', 5)
    before, after = SignatureVisitor(), SignatureVisitor()
    before.visit(ast.parse(src))
    after.visit(ast.parse(f.read_text()))
    for name in ('f', 'g'):
        changes = classify_signature_change(before.results[name], after.results[name])
        assert changes and all(c['severity'] == 'compatible' for c in changes)


def test_reread_and_noop_decoys_do_not_change_read_sets(tmp_path):
    import ast
    from patchguard.controls import insert_statement
    from patchguard.mine import FuncReadSetVisitor
    src = 'class C:\n    def run(self):\n        """Doc."""\n        return self.a\n'
    f = tmp_path / 'm.py'
    f.write_text(src)
    insert_statement(str(tmp_path), 'm.py', 2, '_probe = self.a')
    insert_statement(str(tmp_path), 'm.py', 2, '_noop = None')
    v1, v2 = FuncReadSetVisitor(), FuncReadSetVisitor()
    v1.visit(ast.parse(src))
    v2.visit(ast.parse(f.read_text()))
    assert v1.results == v2.results


def test_keyword_only_parameter_changes_are_classified():
    from patchguard.mine import classify_signature_change
    def sig(kwonly):
        return {'positional': [], 'vararg': None, 'kwarg': None,
                'kwonly': [{'name': n, 'has_default': d} for n, d in kwonly]}
    kinds = lambda a, b: {(c['kind'], c['severity']) for c in classify_signature_change(sig(a), sig(b))}
    assert kinds([], [('x', False)]) == {('added_required_param', 'breaking')}
    assert kinds([], [('x', True)]) == {('added_optional_param', 'compatible')}
    assert kinds([('x', True)], []) == {('removed_param', 'breaking')}
    assert kinds([('x', True)], [('x', False)]) == {('param_now_required', 'breaking')}


def test_agent_patch_loader_collects_patch_and_verdict(tmp_path, monkeypatch):
    import json
    from patchguard import agent_patches as ap
    responses = {
        'logs/a__a-1/patch.diff': b'diff --git a/x.py b/x.py\n',
        'logs/a__a-1/report.json': json.dumps({'resolved': True, 'patch_successfully_applied': True}).encode(),
        'logs/a__a-2/patch.diff': b'',
        'logs/a__a-2/report.json': json.dumps({'resolved': False, 'patch_successfully_applied': False}).encode(),
    }
    monkeypatch.setattr(ap, 'http_get', lambda url, retries=3: next(
        (v for k, v in responses.items() if url.endswith(k)), None))
    monkeypatch.setattr(ap, 'CACHE_DIR', str(tmp_path))
    instances = [{'instance_id': f'a__a-{i}', 'repo': 'a/a'} for i in (1, 2, 3)]
    got = ap.collect('sub', instances, workers=1)
    assert [(r['instance_id'], r['resolved'], r['applied']) for r in got] == [('a__a-1', True, True)]


def test_agent_patch_submission_listing_follows_pagination(monkeypatch):
    from patchguard import agent_patches as ap
    pages = [
        '<Prefix>bash-only/s1/</Prefix><Prefix>bash-only/s2/</Prefix><IsTruncated>true</IsTruncated>',
        '<Prefix>bash-only/s3/</Prefix><IsTruncated>false</IsTruncated>',
    ]
    monkeypatch.setattr(ap, 'http_get', lambda url, retries=3: pages.pop(0).encode())
    assert ap.list_submissions() == ['s1', 's2', 's3']


def test_agent_patch_loader_unwraps_report_keyed_by_instance_id(tmp_path, monkeypatch):
    import json
    from patchguard import agent_patches as ap
    nested = json.dumps({'a__a-1': {'resolved': True, 'patch_successfully_applied': True}}).encode()
    monkeypatch.setattr(ap, 'http_get', lambda url, retries=3: b'diff --git a/x.py b/x.py\n' if url.endswith('patch.diff') else nested)
    rec = ap.fetch_instance('sub', 'a__a-1', cache_dir=str(tmp_path))
    assert rec['resolved'] and rec['applied']


def test_syntax_findings_report_touched_files_that_no_longer_parse(tmp_path):
    from patchguard.cli import syntax_findings
    (tmp_path / 'ok.py').write_text('x = 1\n')
    (tmp_path / 'bad.py').write_text('def f(:\n    pass\n')
    (tmp_path / 'notes.txt').write_text('def f(:')
    found = syntax_findings(str(tmp_path), ['ok.py', 'bad.py', 'notes.txt', 'missing.py'])
    assert [x['file'] for x in found] == ['bad.py'] and found[0]['verdict'] == 'frame'


def test_unparseable_module_is_not_reported_as_removed_functions():
    from patchguard.partition import diff_signatures
    sig = {'positional': [], 'vararg': None, 'kwonly': [], 'kwarg': None}
    pre = {'m::f': sig, 'n::g': sig}
    assert [x['function'] for x in diff_signatures(pre, {}, skip_modules={'m'})] == ['n::g']


def test_fulltest_parses_failures_and_detects_crashed_runs():
    from patchguard.fulltest import parse_failures
    out = ('======\nFAIL: test_a (pkg.mod.Case)\n------\n======\nERROR: test_b (pkg.mod.Case) (i=1)\n'
           '------\nRan 120 tests in 3.2s\n\nFAILED (failures=1, errors=1)\n')
    failures, ran = parse_failures(out)
    assert failures == {'test_a (pkg.mod.Case)', 'test_b (pkg.mod.Case) (i=1)'} and ran == 120
    assert parse_failures('Traceback ...\nImportError: boom\n') == (set(), None)


def test_fulltest_analyze_patch_subtracts_base_failures(tmp_path, monkeypatch):
    import subprocess
    from patchguard import fulltest
    repo = tmp_path / 'repo'
    repo.mkdir()
    subprocess.run(['git', 'init', '-q'], cwd=repo, check=True)
    (repo / 'a.py').write_text('x = 1\n')
    subprocess.run(['git', '-c', 'user.email=a@b', '-c', 'user.name=n', 'add', '.'], cwd=repo, check=True)
    subprocess.run(['git', '-c', 'user.email=a@b', '-c', 'user.name=n', 'commit', '-qm', 'i'], cwd=repo, check=True)
    patch = 'diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n'
    calls = []
    def fake_suite(python, repo_dir, labels=(), timeout=0):
        calls.append(list(labels))
        failures = {'test_old (m.C)', 'test_new (m.C)'} if not labels else {'test_new (m.C)'}
        return {'failures': failures, 'tests_run': 5, 'crashed': False, 'timeout': False, 'elapsed_s': 0, 'tail': ''}
    monkeypatch.setattr(fulltest, 'run_suite', fake_suite)
    result = fulltest.analyze_patch('python', str(repo), patch, {'test_old (m.C)'})
    assert result['regressions'] == ['test_new (m.C)'] and result['confirmed_regressions'] == ['test_new (m.C)']
    assert calls[1] == ['m.C.test_new']
    assert fulltest.analyze_patch('python', str(repo), 'garbage', set())['status'] == 'not_applied'


def test_link_regressions_cross_tabulates_flags_and_regressions(tmp_path):
    import json
    from patchguard.link_regressions import build_cases, summarize, wilson

    def write(path, obj):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj))

    frame = {'e_findings': [], 'd_findings': [], 'readset_findings': [
        {'verdict': 'frame', 'function': 'm::f', 'added': ['self.x'], 'removed': []}]}
    clean = {'e_findings': [], 'd_findings': [], 'readset_findings': []}
    for iid, regs, cls in (('i1', ['t (m.C)'], frame), ('i2', [], frame), ('i3', ['t (m.C)'], clean), ('i4', [], clean)):
        write(tmp_path / 'ft' / iid / 'gold.json', {'status': 'ok', 'confirmed_regressions': regs})
        write(tmp_path / 'ref' / iid / 'negative' / 'classified_report.json', cls)
    cases = build_cases(str(tmp_path / 'ft'), str(tmp_path / 'ref'), str(tmp_path / 'agents'))
    counts = summarize(cases)['overall']['counts']
    assert counts == {'regressed_flagged': 1, 'regressed_unflagged': 1, 'clean_flagged': 1, 'clean_unflagged': 1}
    assert wilson(0, 0) is None and wilson(5, 10)[0] < 0.5 < wilson(5, 10)[1]


def test_hook_log_records_calls_and_summarizes_flags(tmp_path):
    from patchguard.hook import log_event, summarize_log
    log_event(str(tmp_path), {'ts': 't1', 'tool': 'Edit', 'file': 'a.md', 'outcome': 'not_python', 'n_frame': 0,
                              'latency_ms': 5, 'error': None, 'findings': []})
    log_event(str(tmp_path), {'ts': 't2', 'tool': 'Edit', 'file': 'pkg/a.py', 'outcome': 'flagged', 'n_frame': 1,
                              'latency_ms': 90, 'error': None, 'findings': ['pkg.a=>pkg.b: outside scope']})
    summary = summarize_log(str(tmp_path))
    assert '2 hook calls, 1 on .py files, 1 flagged (0 repeats suppressed), 0 errors' in summary
    assert 'pkg/a.py' in summary and 'pkg.a=>pkg.b' in summary
    assert summarize_log(str(tmp_path / 'empty')) == 'no usage log yet'


def test_hook_baseline_snapshot_is_refreshed_when_head_changes(tmp_path):
    import subprocess
    from patchguard.hook import get_or_create_pre_snapshot
    def git(*a):
        subprocess.run(['git', '-c', 'user.email=a@b', '-c', 'user.name=n', *a], cwd=tmp_path, check=True, capture_output=True)
    pkg = tmp_path / 'proj'
    pkg.mkdir()
    (pkg / '__init__.py').write_text('')
    (pkg / 'm.py').write_text('def f(x):\n    return x.a\n')
    git('init', '-q')
    git('add', '.')
    git('commit', '-qm', 'one')
    first = get_or_create_pre_snapshot(str(tmp_path), 'proj')
    (pkg / 'm.py').write_text('def f(x):\n    return x.a + x.b\n')
    git('commit', '-qam', 'two')
    second = get_or_create_pre_snapshot(str(tmp_path), 'proj')
    assert first['reads']['proj.m::f'] == ['x.a'] and second['reads']['proj.m::f'] == ['x.a', 'x.b']


def test_from_import_of_submodule_resolves_to_the_submodule():
    import ast
    from patchguard.mine import resolve_import
    known = {'p', 'p.sub', 'p.other', 'p.other.mod'}
    resolve = lambda src, mod, **kw: resolve_import(ast.parse(src).body[0], mod, 'p', known, **kw)
    assert resolve('from p import sub', 'p.other.mod') == ['p.sub']
    assert resolve('from p import helper', 'p.other.mod') == ['p']
    assert resolve('from .. import sub', 'p.other.mod') == ['p.sub']
    assert resolve('from p.sub import f', 'p.other.mod') == ['p.sub']
    assert resolve('from p import sub, helper', 'p.other.mod') == ['p', 'p.sub']


def test_relative_imports_in_init_files_start_at_their_own_package():
    import ast
    from patchguard.mine import resolve_import
    known = {'p', 'p.a', 'p.a.b'}
    node = ast.parse('from .b import f').body[0]
    assert resolve_import(node, 'p.a', 'p', known, is_package=True) == ['p.a.b']
    assert resolve_import(node, 'p.a', 'p', known, is_package=False) == ['p.b']


def test_hook_reports_each_finding_once_per_session(tmp_path):
    from patchguard.hook import select_new
    f1 = {'pair': 'a=>b', 'reason': 'r'}
    f2 = {'function': 'm::f', 'added': ['self.x'], 'reason': 'r'}
    assert select_new(str(tmp_path), 's1', [f1]) == [f1]
    assert select_new(str(tmp_path), 's1', [f1, f2]) == [f2]
    assert select_new(str(tmp_path), 's1', [f1, f2]) == []
    assert select_new(str(tmp_path), 's2', [f1]) == [f1]
    assert select_new(str(tmp_path), 's1', []) == []
    assert select_new(str(tmp_path), 's1', [f1]) == [f1]


def _file_diff(path, removed, added, new=False, old_len=None):
    head = f"diff --git a/{path} b/{path}\n" + ("new file mode 100644\n" if new else "") + f"--- a/{path}\n+++ b/{path}\n"
    old_len = removed if old_len is None else old_len
    body = ''.join(f"-old{i}\n" for i in range(removed)) + ''.join(f"+new{i}\n" for i in range(added))
    return head + f"@@ -1,{old_len} +1,{added} @@\n" + body


def test_hygiene_flags_removed_test_content_and_stray_files():
    from patchguard.hygiene import hygiene_findings
    patch = (_file_diff('tests/postgres_tests/__init__.py', 22, 4)
             + _file_diff('reproduce_issue.py', 0, 12, new=True)
             + _file_diff('testapp/models.py', 0, 8, new=True)
             + _file_diff('db.sqlite3', 0, 1, new=True)
             + _file_diff('django/db/models/query.py', 3, 5, old_len=900)
             + _file_diff('tests/queries/tests.py', 2, 30))
    kinds = {(f['kind'], f['file']) for f in hygiene_findings(patch)}
    assert kinds == {('test_content_removed', 'tests/postgres_tests/__init__.py'),
                     ('stray_file', 'reproduce_issue.py'), ('stray_directory', 'testapp'),
                     ('stray_artifact', 'db.sqlite3')}


def test_hygiene_flags_whole_file_rewrites_but_not_small_edits():
    from patchguard.hygiene import hygiene_findings
    rewrite = _file_diff('django/db/models/sql/query.py', 1953, 1988)
    assert [f['kind'] for f in hygiene_findings(rewrite)] == ['file_rewritten']
    small = _file_diff('django/db/models/sql/query.py', 12, 14, old_len=2000)
    assert hygiene_findings(small) == []
    assert hygiene_findings(_file_diff('tests/queries/tests.py', 3, 40)) == []


def _write_repo(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _sigs(root, top):
    from patchguard.mine import mine_signatures
    return mine_signatures(str(root), top)


def test_callers_flags_call_sites_broken_by_a_new_required_parameter(tmp_path):
    from patchguard.callers import annotate_callers
    from patchguard.partition import diff_signatures
    pre = {'pkg/__init__.py': '', 'pkg/util.py': 'def f(a):\n    return a\n',
           'pkg/use.py': 'from pkg.util import f\nfrom pkg import util\n\ndef g():\n    f(1)\n    util.f(2)\n    f(*[3])\n',
           'tests/test_u.py': 'from pkg.util import f\n\ndef test():\n    f(1)\n'}
    post = dict(pre, **{'pkg/util.py': 'def f(a, b):\n    return a\n'})
    pre_dir, post_dir = tmp_path / 'pre', tmp_path / 'post'
    _write_repo(pre_dir, pre)
    _write_repo(post_dir, post)
    pre_sigs, post_sigs = _sigs(pre_dir, 'pkg'), _sigs(post_dir, 'pkg')
    items = annotate_callers(diff_signatures(pre_sigs, post_sigs), pre_sigs, post_sigs, str(post_dir))
    assert sorted((c['file'], c['line']) for c in items[0]['broken_callers']) == [('pkg/use.py', 5), ('pkg/use.py', 6)]
    assert items[0]['broken_total'] == 2 and items[0]['broken_in_tests'] == 1


def test_callers_ignores_call_sites_the_patch_updated_and_flags_removed_functions(tmp_path):
    from patchguard.callers import annotate_callers
    from patchguard.partition import diff_signatures
    pre = {'pkg/__init__.py': '', 'pkg/util.py': 'def f(a):\n    return a\n\ndef gone():\n    pass\n',
           'pkg/use.py': 'from pkg.util import f, gone\n\ndef g():\n    f(1)\n    gone()\n'}
    post = {'pkg/__init__.py': '', 'pkg/util.py': 'def f(a, b=None):\n    return a\n',
            'pkg/use.py': 'from pkg.util import f, gone\n\ndef g():\n    f(1)\n    gone()\n'}
    pre_dir, post_dir = tmp_path / 'pre', tmp_path / 'post'
    _write_repo(pre_dir, pre)
    _write_repo(post_dir, post)
    pre_sigs, post_sigs = _sigs(pre_dir, 'pkg'), _sigs(post_dir, 'pkg')
    items = annotate_callers(diff_signatures(pre_sigs, post_sigs), pre_sigs, post_sigs, str(post_dir))
    assert [i['function'] for i in items] == ['pkg.util::gone']
    assert [(c['file'], c['line']) for c in items[0]['broken_callers']] == [('pkg/use.py', 5)]


def test_callers_resolves_methods_through_self_and_subclasses(tmp_path):
    from patchguard.callers import annotate_callers
    from patchguard.partition import diff_signatures
    pre = {'pkg/__init__.py': '', 'pkg/m.py': (
        'class Base:\n    def run(self, x):\n        return x\n\n    def go(self):\n        return self.run(1)\n\n'
        'class Child(Base):\n    def other(self):\n        return self.run(2)\n\n'
        'class Unrelated:\n    def other(self):\n        return self.run(3)\n\n    def run(self, a, b):\n        pass\n')}
    post = {'pkg/__init__.py': '', 'pkg/m.py': pre['pkg/m.py'].replace('def run(self, x):', 'def run(self, x, extra):')}
    pre_dir, post_dir = tmp_path / 'pre', tmp_path / 'post'
    _write_repo(pre_dir, pre)
    _write_repo(post_dir, post)
    pre_sigs, post_sigs = _sigs(pre_dir, 'pkg'), _sigs(post_dir, 'pkg')
    items = annotate_callers(diff_signatures(pre_sigs, post_sigs), pre_sigs, post_sigs, str(post_dir))
    assert sorted(c['line'] for c in items[0]['broken_callers']) == [6, 10]


def test_callers_removed_override_with_inherited_fallback_is_not_broken(tmp_path):
    from patchguard.callers import annotate_callers
    from patchguard.partition import diff_signatures
    pre = {'pkg/__init__.py': '', 'pkg/m.py': (
        'class Base:\n    def prep(self, v):\n        return v\n\n'
        'class Child(Base):\n    def prep(self, v):\n        return super().prep(v)\n\n'
        'class User(Child):\n    def go(self):\n        return self.prep(1)\n')}
    post = {'pkg/__init__.py': '', 'pkg/m.py': pre['pkg/m.py'].replace(
        'class Child(Base):\n    def prep(self, v):\n        return super().prep(v)\n', 'class Child(Base):\n    pass\n')}
    pre_dir, post_dir = tmp_path / 'pre', tmp_path / 'post'
    _write_repo(pre_dir, pre)
    _write_repo(post_dir, post)
    pre_sigs, post_sigs = _sigs(pre_dir, 'pkg'), _sigs(post_dir, 'pkg')
    items = annotate_callers(diff_signatures(pre_sigs, post_sigs), pre_sigs, post_sigs, str(post_dir))
    assert [(i['function'], i['broken_total'], i.get('inherited')) for i in items] == [('pkg.m::Child.prep', 0, True)]


def test_callers_unknown_receiver_calls_count_when_all_definitions_share_a_family(tmp_path):
    from patchguard.callers import annotate_callers
    from patchguard.partition import diff_signatures
    pre = {'pkg/__init__.py': '', 'pkg/m.py': (
        'class Base:\n    def fetch(self, a):\n        pass\n\nclass Child(Base):\n    def fetch(self, a):\n        pass\n'),
        'pkg/use.py': 'def go(obj):\n    obj.fetch(1)\n'}
    post = dict(pre, **{'pkg/m.py': pre['pkg/m.py'].replace('class Base:\n    def fetch(self, a):', 'class Base:\n    def fetch(self, a, b):')})
    pre_dir, post_dir = tmp_path / 'pre', tmp_path / 'post'
    _write_repo(pre_dir, pre)
    _write_repo(post_dir, post)
    pre_sigs, post_sigs = _sigs(pre_dir, 'pkg'), _sigs(post_dir, 'pkg')
    items = annotate_callers(diff_signatures(pre_sigs, post_sigs), pre_sigs, post_sigs, str(post_dir))
    assert [(c['file'], c['line']) for c in items[0]['broken_callers']] == [('pkg/use.py', 2)]


def test_evaluate_benchmark_scores_recall_false_alarms_and_noise():
    from patchguard.evaluate_benchmark import score
    examples = [
        {'example_id': 'a::E', 'instance_id': 'a', 'family': 'positive', 'kind': 'E', 'target': {'class': 'E', 'id': 'p.a=>p.b'}},
        {'example_id': 'b::E', 'family': 'positive', 'kind': 'E', 'target': {'class': 'E', 'id': 'p.a=>p.c'}},
        {'example_id': 'a::rs', 'family': 'positive', 'kind': 'read-set',
         'target': {'class': 'read-set', 'id': 'C.run', 'attr': 'self.x'}},
        {'example_id': 'a::twin', 'family': 'twin', 'kind': 'D', 'target': {'class': 'D', 'id': 'C.run'}},
        {'example_id': 'b::twin', 'family': 'twin', 'kind': 'D', 'target': {'class': 'D', 'id': 'C.go'}},
        {'example_id': 'a::decoy', 'family': 'decoy', 'kind': 'noop', 'target': {'class': 'read-set', 'id': 'C.run'}},
        {'example_id': 'a::ref', 'family': 'reference', 'kind': 'reference', 'target': None},
        {'example_id': 'b::ref', 'family': 'reference', 'kind': 'reference', 'target': None},
    ]
    predictions = [
        {'example_id': 'a::E', 'findings': [{'class': 'E', 'id': 'p.a=>p.b', 'verdict': 'frame'}]},
        {'example_id': 'b::E', 'findings': [{'class': 'E', 'id': 'p.a=>p.c', 'verdict': 'scope'}]},
        {'example_id': 'a::rs', 'findings': [{'class': 'read-set', 'id': 'm::C.run', 'verdict': 'frame', 'detail': ['self.x']}]},
        {'example_id': 'a::twin', 'findings': [{'class': 'D', 'id': 'm::C.run', 'verdict': 'frame'}]},
        {'example_id': 'b::twin', 'findings': [{'class': 'D', 'id': 'm::C.go', 'verdict': 'scope'}]},
        {'example_id': 'a::decoy', 'findings': []},
        {'example_id': 'a::ref', 'findings': [{'class': 'D', 'id': 'm::C.other', 'verdict': 'frame'}]},
        {'example_id': 'b::ref', 'findings': []},
    ]
    result = score(examples, predictions)['summary']
    assert result['positive'] == {'n': 3, 'count': 2, 'rate': 0.667}
    assert result['twin'] == {'n': 2, 'count': 1, 'rate': 0.5}
    assert result['decoy'] == {'n': 1, 'count': 0, 'rate': 0.0}
    assert result['reference'] == {'n': 2, 'count': 1, 'rate': 0.5}


def test_export_reapplies_variants_and_builds_targets():
    from patchguard.export_benchmark import predictions_from_report, target_of
    assert target_of('positive', 'E', {'source_pkg': 'p.a', 'target_pkg': 'p.b'}) == {'class': 'E', 'id': 'p.a=>p.b'}
    assert target_of('positive', 'read-set', {'qualname': 'C.f', 'param': 'self', 'attr': 'x'}) == \
        {'class': 'read-set', 'id': 'C.f', 'attr': 'self.x'}
    report = {'e_findings': [{'pair': 'a=>b', 'verdict': 'frame'}],
              'readset_findings': [{'function': 'm::C.f', 'added': ['self.x'], 'verdict': 'scope'}],
              'd_findings': [{'function': 'm::g', 'changes': [{'kind': 'removed_function'}], 'verdict': 'frame'}]}
    got = predictions_from_report(report)
    assert [(g['class'], g['verdict']) for g in got] == [('E', 'frame'), ('read-set', 'scope'), ('D', 'frame')]


def test_history_model_recovers_a_planted_effect_and_chi2_tail():
    import random
    from patchguard.history_model import auc, chi2_sf, fit, sigmoid
    rnd = random.Random(0)
    X, y = [], []
    for _ in range(2000):
        flag = float(rnd.random() < 0.3)
        X.append([1.0, flag])
        y.append(int(rnd.random() < sigmoid(-1.0 + 1.5 * flag)))
    beta = fit(X, y)
    assert abs(beta[0] + 1.0) < 0.25 and abs(beta[1] - 1.5) < 0.35
    assert abs(chi2_sf(3.841, 1) - 0.05) < 0.002 and abs(chi2_sf(5.991, 2) - 0.05) < 0.002
    assert auc([0.9, 0.8, 0.3, 0.2], [1, 1, 0, 0]) == 1.0 and auc([0.5, 0.5], [1, 0]) == 0.5


def test_report_shows_caller_breakage_and_hygiene_findings():
    from patchguard.report import generate_report
    classified = {
        'e_findings': [], 'readset_findings': [], 'syntax_findings': [],
        'd_findings': [{'function': 'm::f', 'changes': [{'kind': 'added_required_param'}], 'verdict': 'frame',
                        'reason': 'r', 'broken_total': 3}],
        'hygiene_findings': [{'kind': 'stray_file', 'file': 'reproduce.py', 'verdict': 'frame', 'reason': 'scratch'}]}
    text = generate_report(classified)
    assert '3 вызов' in text and 'reproduce.py' in text and 'stray_file' in text


def test_evaluate_does_not_blame_decoys_for_findings_the_reference_already_has():
    from patchguard.evaluate_benchmark import score
    examples = [
        {'example_id': 'i::reference', 'instance_id': 'i', 'family': 'reference', 'kind': 'reference', 'target': None},
        {'example_id': 'i::decoy-noop', 'instance_id': 'i', 'family': 'decoy', 'kind': 'noop',
         'target': {'class': 'read-set', 'id': 'C.f'}},
        {'example_id': 'j::decoy-noop', 'instance_id': 'j', 'family': 'decoy', 'kind': 'noop',
         'target': {'class': 'read-set', 'id': 'C.f'}},
    ]
    finding = {'class': 'read-set', 'id': 'm::C.f', 'verdict': 'frame', 'detail': ['self.x']}
    predictions = [{'example_id': 'i::reference', 'findings': [dict(finding, id='C.f')]},
                   {'example_id': 'i::decoy-noop', 'findings': [dict(finding, id='C.f')]},
                   {'example_id': 'j::decoy-noop', 'findings': [finding]}]
    assert score(examples, predictions)['summary']['decoy'] == {'n': 2, 'count': 1, 'rate': 0.5}


def test_statement_insertion_respects_decorators_and_refuses_broken_files(tmp_path):
    import ast
    from patchguard.controls import insert_statement
    src = 'def outer(f):\n    @wraps(f)\n    def wrapper(x):\n        return f(x)\n    return wrapper\n'
    path = tmp_path / 'm.py'
    path.write_text(src)
    insert_statement(str(tmp_path), 'm.py', 1, '_noop = None')
    ast.parse(path.read_text())
    assert path.read_text().index('_noop') < path.read_text().index('@wraps')


def test_severity_ranks_concrete_breakage_above_coupling_above_private_changes():
    from patchguard.severity import commit_tier, record_of, severity
    d = lambda name, broken, checked, kind='added_required_param': record_of('D', {
        'function': name, 'changes': [{'kind': kind}], 'broken_total': broken, 'callers_checked': checked})
    assert severity(d('m::C.run', 2, 2)) == 3
    assert severity(d('m::C.run', None, None)) == 2
    assert severity(d('m::C.run', 0, 3)) == 1
    assert severity(d('m::_helper', 0, 0)) == 1
    assert severity(record_of('read-set', {'function': 'm::f', 'added': ['self.a']})) == 2
    assert severity(record_of('read-set', {'function': 'm::f', 'added': ['a.x', 'a.y', 'a.z']})) == 3
    assert severity(record_of('read-set', {'function': 'm::f', 'added': ['self.__class__']})) == 1
    assert severity(record_of('syntax', {'file': 'a.py'})) == 3
    assert severity({'class': 'hygiene', 'kind': 'stray_file'}) == 1
    assert commit_tier([]) == 0 and commit_tier([d('m::_h', 0, 0), record_of('E', {'pair': 'a=>b'})]) == 2


def _git_repo(tmp_path, files):
    import subprocess
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    def git(*a):
        subprocess.run(['git', '-c', 'user.email=a@b', '-c', 'user.name=n', *a], cwd=tmp_path, check=True, capture_output=True)
    git('init', '-q')
    git('add', '.')
    git('commit', '-qm', 'base')
    return git


def test_check_reports_new_dependency_and_stray_file_in_working_tree(tmp_path):
    from patchguard.check import analyze, discover_packages
    base = {'proj/__init__.py': '', 'proj/a/__init__.py': '', 'proj/a/m.py': 'def f(x):\n    return x.v\n',
            'proj/b/__init__.py': '', 'proj/b/n.py': 'def g():\n    return 1\n',
            'proj/c/__init__.py': '', 'proj/c/o.py': 'def h():\n    return 2\n',
            'proj/b/p.py': 'from proj.c import o\n\ndef k():\n    return o.h()\n'}
    _git_repo(tmp_path, base)
    assert discover_packages(str(tmp_path)) == [('', 'proj')]
    (tmp_path / 'proj/a/m.py').write_text('def f(x):\n    from proj.b import n\n    return x.v + n.g()\n')
    (tmp_path / 'reproduce.py').write_text('print(1)\n')
    findings = analyze(str(tmp_path), intent='fix f', callers=False)
    pairs = {(f['class'], f['id']) for f in findings}
    assert ('E', 'proj.a=>proj.b') in pairs and ('hygiene', 'reproduce.py') in pairs


def test_check_flags_a_signature_change_with_broken_callers_and_supports_src_layout(tmp_path):
    from patchguard.check import analyze, discover_packages
    base = {'src/lib/__init__.py': '', 'src/lib/core.py': 'def f(a):\n    return a\n',
            'src/lib/use.py': 'from lib.core import f\n\ndef g():\n    return f(1)\n'}
    _git_repo(tmp_path, base)
    assert discover_packages(str(tmp_path)) == [('src', 'lib')]
    (tmp_path / 'src/lib/core.py').write_text('def f(a, b):\n    return a\n')
    findings = analyze(str(tmp_path), intent='unrelated change')
    d = [f for f in findings if f['class'] == 'D']
    assert d and d[0]['tier'] == 3 and d[0]['detail']['broken'] == 1
    assert analyze(str(tmp_path), intent='unrelated change', callers=False)[0]['class'] == 'D'


def test_protocol_findings_flag_new_semantic_methods_on_existing_classes():
    from patchguard.partition import protocol_findings
    sig = {'positional': [], 'vararg': None, 'kwonly': [], 'kwarg': None}
    pre = {'m::Deferred.get': sig, 'm::Deferred.helper': sig}
    post = dict(pre, **{'m::Deferred.__set__': sig, 'm::Deferred.__repr__': sig, 'm::Brand.__set__': sig, 'm::Deferred.extra': sig})
    found = protocol_findings(pre, post, 'The enum value type differs')
    assert [(f['function'], f['verdict']) for f in found] == [('m::Deferred.__set__', 'frame')]
    named = protocol_findings(pre, post, 'Make Deferred a data descriptor')
    assert [f['verdict'] for f in named] == ['scope']


def test_protocol_findings_reach_severity_and_report():
    from patchguard.report import generate_report
    from patchguard.severity import record_of, severity
    finding = {'function': 'm::C.__set__', 'owner': 'C', 'method': '__set__', 'verdict': 'frame', 'reason': 'r'}
    assert severity(record_of('protocol', finding)) == 2
    text = generate_report({'e_findings': [], 'readset_findings': [], 'd_findings': [], 'protocol_findings': [finding]})
    assert 'C.__set__' in text
