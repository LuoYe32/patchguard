"""Export InvarBench: materialize every variant as a patch against the base commit, together with its
ground truth, so any tool can be scored without our pipeline (see evaluate_benchmark)."""
import argparse
import ast
import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

from .batch_invarbench import TOP_PACKAGE, fetch_swebench_verified
from .cli import inject_d_violation, inject_e_violation, inject_readset_violation, prepare_repo, run
from .controls import append_optional_param, function_sites, insert_statement, read_source
from .hygiene import hygiene_findings
from .oracle import verify_injection

VARIANT_DIRS = {
    'positive_e': ('positive', 'E'), 'positive_readset': ('positive', 'read-set'), 'positive_d': ('positive', 'D'),
    'twin_readset': ('twin', 'read-set'), 'twin_d': ('twin', 'D'),
    'decoy_optional_param': ('decoy', 'optional-param'), 'decoy_reread': ('decoy', 'reread'),
    'decoy_noop': ('decoy', 'noop'), 'decoy_existing_edge': ('decoy', 'existing-edge'),
}


def lineno_of(repo, file_rel, qualname):
    for q, node in function_sites(ast.parse(read_source(repo, file_rel))):
        if q == qualname:
            return node.lineno
    return None


def apply_variant(repo, info):
    """Re-apply the recorded mutation on top of the already patched repo; returns False when it cannot be placed."""
    kind, file_rel = info['type'], info['file']
    if kind == 'E':
        return inject_e_violation(repo, info['source_pkg'], info['target_pkg'], file_rel) is not None
    qual = info.get('qualname') or info.get('function')
    lineno = lineno_of(repo, file_rel, qual) if qual else None
    if kind == 'read-set':
        if not lineno:
            return False
        inject_readset_violation(repo, file_rel, qual, lineno, info['param'], info['attr'])
    elif kind == 'D-signature':
        if not lineno:
            return False
        inject_d_violation(repo, file_rel, qual, lineno)
    elif kind == 'decoy':
        decoy = info['decoy']
        if decoy == 'existing-edge':
            src, tgt = info['pair'].split('=>')
            return inject_e_violation(repo, src, tgt, file_rel) is not None
        if not lineno:
            return False
        if decoy == 'optional-param':
            append_optional_param(repo, file_rel, lineno)
        elif decoy == 'reread':
            insert_statement(repo, file_rel, lineno, f"_synthetic_decoy_probe = {info['param']}.{info['attr']}")
        else:
            insert_statement(repo, file_rel, lineno, "_synthetic_noop = None")
    else:
        return False
    return True


def target_of(family, kind, info):
    if kind == 'E':
        return {'class': 'E', 'id': f"{info['source_pkg']}=>{info['target_pkg']}"}
    if kind == 'read-set':
        return {'class': 'read-set', 'id': info['qualname'], 'attr': f"{info['param']}.{info['attr']}"}
    if kind == 'D':
        return {'class': 'D', 'id': info['function']}
    if kind == 'existing-edge':
        return {'class': 'E', 'id': info['pair']}
    if kind in ('optional-param', 'noop'):
        return {'class': 'D' if kind == 'optional-param' else 'read-set', 'id': info['qualname']}
    return {'class': 'read-set', 'id': info['qualname'], 'attr': f"{info['param']}.{info['attr']}"}


def predictions_from_report(classified):
    out = []
    for finding in classified.get('e_findings', []):
        out.append({'class': 'E', 'id': finding['pair'], 'verdict': finding['verdict'], 'detail': ''})
    for finding in classified.get('readset_findings', []):
        out.append({'class': 'read-set', 'id': finding['function'], 'verdict': finding['verdict'], 'detail': finding['added']})
    for finding in classified.get('d_findings', []):
        out.append({'class': 'D', 'id': finding['function'], 'verdict': finding['verdict'],
                    'detail': [c['kind'] for c in finding['changes']]})
    for finding in classified.get('syntax_findings', []):
        out.append({'class': 'syntax', 'id': finding['file'], 'verdict': finding['verdict'], 'detail': finding['error']})
    return out


def export_instance(inst, run_dir, out_dir, work_root):
    iid = inst['instance_id']
    work = os.path.join(work_root, iid)
    rows = []
    try:
        repo = prepare_repo(f"https://github.com/{inst['repo']}.git", inst['base_commit'], work, 'export')
        gold_file = os.path.join(work, 'gold.patch')
        open(gold_file, 'w').write(inst['patch'] if inst['patch'].endswith('\n') else inst['patch'] + '\n')

        def snapshot(name):
            diff = run(['git', 'diff', '--binary'], cwd=repo).stdout
            rel = os.path.join('patches', iid, name + '.diff')
            os.makedirs(os.path.join(out_dir, os.path.dirname(rel)), exist_ok=True)
            open(os.path.join(out_dir, rel), 'w').write(diff)
            return rel

        run(['git', 'apply', gold_file], cwd=repo)
        rows.append(({'family': 'reference', 'kind': 'reference', 'target': None}, snapshot('reference'), 'negative'))
        for dirname, (family, kind) in VARIANT_DIRS.items():
            path = os.path.join(run_dir, iid, dirname, 'injection.json')
            if not os.path.exists(path):
                continue
            info = json.load(open(path))
            if info.get('oracle') and not info['oracle'].get('verified'):
                continue
            run(['git', 'reset', '--hard', '-q'], cwd=repo)
            run(['git', 'clean', '-fdq'], cwd=repo, check=False)
            run(['git', 'apply', gold_file], cwd=repo)
            before = {f: read_source(repo, f) for f in [info['file']]}
            if not apply_variant(repo, info):
                continue
            oracle = None
            if info['type'] in ('E', 'read-set', 'D-signature'):
                oracle = verify_injection(info, before[info['file']], read_source(repo, info['file']))
                if not oracle['verified']:
                    continue
            rows.append(({'family': family, 'kind': kind, 'target': target_of(family, kind, info),
                          'file': info['file']}, snapshot(f"{family}-{kind}"), dirname))
        result = []
        for meta, patch_rel, dirname in rows:
            report = None
            rpath = os.path.join(run_dir, iid, dirname, 'classified_report.json')
            if os.path.exists(rpath):
                report = predictions_from_report(json.load(open(rpath)))
                diff = open(os.path.join(out_dir, patch_rel), encoding='utf-8', errors='replace').read()
                report += [{'class': 'hygiene', 'id': f['file'], 'verdict': 'frame', 'detail': f['kind']}
                           for f in hygiene_findings(diff)]
            name = os.path.splitext(os.path.basename(patch_rel))[0]
            result.append(({'example_id': f"{iid}::{name}", 'instance_id': iid, 'repo': inst['repo'],
                            'base_commit': inst['base_commit'], 'patch': patch_rel, **meta}, report))
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runs', required=True, nargs='+', help='batch directories of PatchGuard runs with controls')
    ap.add_argument('--out', required=True)
    ap.add_argument('--work-root', required=True)
    ap.add_argument('--workers', type=int, default=3)
    ap.add_argument('--ids', default=None)
    ap.add_argument('--data-file', default=None)
    args = ap.parse_args()

    rows = json.load(open(args.data_file)) if args.data_file else fetch_swebench_verified()
    by_id = {r['instance_id']: r for r in rows}
    run_of = {}
    for runs_dir in args.runs:
        for d in os.listdir(runs_dir):
            if os.path.isdir(os.path.join(runs_dir, d)) and d in by_id:
                run_of[d] = runs_dir
    ids = sorted(run_of)
    if args.ids:
        ids = [i for i in ids if i in set(args.ids.split(','))]
    os.makedirs(args.out, exist_ok=True)
    lock, examples, predictions = threading.Lock(), [], []

    def work(iid):
        try:
            result = export_instance(by_id[iid], run_of[iid], args.out, args.work_root)
        except Exception as e:
            print(f"[export] {iid} error: {type(e).__name__}: {str(e)[:150]}", flush=True)
            return
        with lock:
            for ex, findings in result:
                examples.append(ex)
                if findings is not None:
                    predictions.append({'example_id': ex['example_id'], 'findings': findings})
            print(f"[export] {iid} ok ({len(result)} examples)", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        list(pool.map(work, ids))
    examples.sort(key=lambda e: e['example_id'])
    predictions.sort(key=lambda p: p['example_id'])
    with open(os.path.join(args.out, 'examples.jsonl'), 'w', encoding='utf-8') as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + '\n')
    os.makedirs(os.path.join(args.out, 'predictions'), exist_ok=True)
    with open(os.path.join(args.out, 'predictions', 'patchguard.jsonl'), 'w', encoding='utf-8') as f:
        for p in predictions:
            f.write(json.dumps(p, ensure_ascii=False) + '\n')
    with open(os.path.join(args.out, 'predictions', 'no_scope.jsonl'), 'w', encoding='utf-8') as f:
        for p in predictions:
            flipped = [{**x, 'verdict': 'frame'} for x in p['findings']]
            f.write(json.dumps({'example_id': p['example_id'], 'findings': flipped}, ensure_ascii=False) + '\n')
    with open(os.path.join(args.out, 'issues.jsonl'), 'w', encoding='utf-8') as f:
        for iid in sorted({e['instance_id'] for e in examples}):
            f.write(json.dumps({'instance_id': iid, 'problem_statement': by_id[iid].get('problem_statement', '')}, ensure_ascii=False) + '\n')
    print(f"[export] {len(examples)} examples, {len(predictions)} PatchGuard predictions", flush=True)


if __name__ == '__main__':
    main()
