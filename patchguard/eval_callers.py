"""Evaluate the caller-compatibility check on reference patches and on injected breaking signature
changes: how many injected breakages does it find statically, and how many natural signature findings
have a broken call site?"""
import argparse
import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

from .batch_invarbench import TOP_PACKAGE, load_instances
from .callers import annotate_callers
from .cli import inject_d_violation, prepare_repo, run
from .controls import function_sites, read_source
from .mine import mine_signatures
from .partition import diff_signatures


def summarize_item(item):
    return {'function': item['function'], 'kinds': sorted({c['kind'] for c in item['changes']}),
            'private': item.get('private', False), 'broken_total': item['broken_total'],
            'callers_checked': item['callers_checked'], 'sample': item['broken_callers'][:3]}


def evaluate_instance(inst, injection, work_root):
    iid = inst['instance_id']
    top = TOP_PACKAGE[inst['repo']]
    work = os.path.join(work_root, iid)
    try:
        repo = prepare_repo(f"https://github.com/{inst['repo']}.git", inst['base_commit'], work, 'callers')
        pre = mine_signatures(repo, top)
        patch_file = os.path.join(work, 'gold.patch')
        open(patch_file, 'w').write(inst['patch'] if inst['patch'].endswith('\n') else inst['patch'] + '\n')
        run(['git', 'apply', patch_file], cwd=repo)
        if inst.get('test_patch'):
            test_file = os.path.join(work, 'test.patch')
            open(test_file, 'w').write(inst['test_patch'] if inst['test_patch'].endswith('\n') else inst['test_patch'] + '\n')
            run(['git', 'apply', test_file], cwd=repo, check=False)
        post = mine_signatures(repo, top)
        natural = [summarize_item(i) for i in annotate_callers(diff_signatures(pre, post), pre, post, repo)]
        out = {'instance_id': iid, 'natural': natural, 'injected': None}
        if injection:
            lineno = next((n.lineno for q, n in function_sites(__import__('ast').parse(read_source(repo, injection['file'])))
                           if q == injection['function']), None)
            if lineno:
                inject_d_violation(repo, injection['file'], injection['function'], lineno)
                injected_sigs = mine_signatures(repo, top)
                items = [i for i in annotate_callers(diff_signatures(pre, injected_sigs), pre, injected_sigs, repo)
                         if i['function'].endswith('::' + injection['function'])]
                out['injected'] = summarize_item(items[0]) if items else {'function': injection['function'], 'missing': True}
        return out
    except Exception as e:
        return {'instance_id': iid, 'error': f"{type(e).__name__}: {str(e)[:200]}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference-runs', required=True, help='batch directory with positive_d/injection.json per instance')
    ap.add_argument('--limit', type=int, default=60)
    ap.add_argument('--repos', default='django/django')
    ap.add_argument('--work-root', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--workers', type=int, default=3)
    args = ap.parse_args()
    instances = load_instances(limit=args.limit, repos=set(args.repos.split(',')))
    done = set()
    if os.path.exists(args.out):
        done = {json.loads(l)['instance_id'] for l in open(args.out) if '"error"' not in l}
    lock = threading.Lock()

    def work(inst):
        path = os.path.join(args.reference_runs, inst['instance_id'], 'positive_d', 'injection.json')
        injection = json.load(open(path)) if os.path.exists(path) else None
        row = evaluate_instance(inst, injection, args.work_root)
        with lock, open(args.out, 'a') as f:
            f.write(json.dumps(row) + '\n')
        print(f"[callers] {inst['instance_id']} {'error' if 'error' in row else 'ok'}", flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(work, [i for i in instances if i['instance_id'] not in done]))


if __name__ == '__main__':
    main()
