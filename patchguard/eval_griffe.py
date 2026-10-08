import argparse
import ast
import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

from .batch_invarbench import TOP_PACKAGE, load_instances
from .cli import inject_d_violation, prepare_repo, run
from .controls import function_sites, read_source
from .mine import module_name


def breakages(griffe, top, repo, previous):
    new = griffe.load(top, search_paths=[repo], resolve_aliases=False)
    found = {}
    for b in griffe.find_breaking_changes(previous, new):
        found.setdefault(b.obj.path, set()).add(b.kind.value)
    return found


def evaluate_instance(griffe, inst, injection, work_root):
    iid, top = inst['instance_id'], TOP_PACKAGE[inst['repo']]
    work = os.path.join(work_root, iid)
    try:
        repo = prepare_repo(f"https://github.com/{inst['repo']}.git", inst['base_commit'], work, 'griffe')
        old = griffe.load(top, search_paths=[repo], resolve_aliases=False)
        patch_file = os.path.join(work, 'gold.patch')
        open(patch_file, 'w').write(inst['patch'] if inst['patch'].endswith('\n') else inst['patch'] + '\n')
        run(['git', 'apply', patch_file], cwd=repo)
        natural = breakages(griffe, top, repo, old)
        out = {'instance_id': iid, 'natural': {k: sorted(v) for k, v in natural.items()}, 'injected': None}
        if injection:
            lineno = next((n.lineno for q, n in function_sites(ast.parse(read_source(repo, injection['file'])))
                           if q == injection['function']), None)
            if lineno:
                inject_d_violation(repo, injection['file'], injection['function'], lineno)
                after = breakages(griffe, top, repo, old)
                path = f"{module_name('', injection['file'], '')}.{injection['function']}"
                out['injected'] = {'path': path, 'flagged': path in after and path not in natural,
                                   'kinds': sorted(after.get(path, []))}
        return out
    except Exception as e:
        return {'instance_id': iid, 'error': f"{type(e).__name__}: {str(e)[:200]}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    import griffe
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference-runs', required=True)
    ap.add_argument('--limit', type=int, default=60)
    ap.add_argument('--ids', default=None)
    ap.add_argument('--repos', default='django/django')
    ap.add_argument('--work-root', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--workers', type=int, default=2)
    args = ap.parse_args()
    ids = set(args.ids.split(',')) if args.ids else None
    instances = load_instances(limit=None if ids else args.limit, repos=set(args.repos.split(',')), ids=ids)
    lock = threading.Lock()

    def work(inst):
        path = os.path.join(args.reference_runs, inst['instance_id'], 'positive_d', 'injection.json')
        injection = json.load(open(path)) if os.path.exists(path) else None
        row = evaluate_instance(griffe, inst, injection, args.work_root)
        with lock, open(args.out, 'a') as f:
            f.write(json.dumps(row) + '\n')
        print(f"[griffe] {inst['instance_id']} {'error' if 'error' in row else 'ok'}", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        list(pool.map(work, instances))


if __name__ == '__main__':
    main()
