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
    assert '2 hook calls, 1 on .py files, 1 flagged, 0 errors' in summary
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
