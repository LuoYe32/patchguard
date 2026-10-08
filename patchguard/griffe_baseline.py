import argparse
import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

from .batch_invarbench import TOP_PACKAGE
from .cli import prepare_repo, run

SIGNATURE_KINDS = {'Parameter was added as required', 'Parameter was removed', 'Positional parameter was moved',
                   'Parameter changed kind', 'Parameter changed required', 'Public object was removed'}
DEFAULT_FAMILIES = {('reference', 'reference'), ('positive', 'D'), ('twin', 'D'), ('decoy', 'optional-param')}


def findings_for(griffe, top, repo, old):
    new = griffe.load(top, search_paths=[repo], resolve_aliases=False)
    found = {}
    for b in griffe.find_breaking_changes(old, new):
        found.setdefault(b.obj.path, set()).add(b.kind.value)
    return [{'class': 'D' if kinds & SIGNATURE_KINDS else 'other', 'id': path, 'verdict': 'frame',
             'detail': sorted(kinds)} for path, kinds in found.items()]


def run_instance(griffe, iid, examples, bench, work_root):
    work = os.path.join(work_root, iid)
    out = []
    try:
        first = examples[0]
        repo = prepare_repo(f"https://github.com/{first['repo']}.git", first['base_commit'], work, 'griffe')
        top = TOP_PACKAGE[first['repo']]
        old = griffe.load(top, search_paths=[repo], resolve_aliases=False)
        for ex in examples:
            run(['git', 'reset', '--hard', '-q'], cwd=repo)
            run(['git', 'clean', '-fdq'], cwd=repo, check=False)
            run(['git', 'apply', os.path.abspath(os.path.join(bench, ex['patch']))], cwd=repo)
            out.append({'example_id': ex['example_id'], 'findings': findings_for(griffe, top, repo, old)})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


def main():
    import griffe
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--benchmark', required=True)
    ap.add_argument('--work-root', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--workers', type=int, default=3)
    ap.add_argument('--ids', default=None)
    args = ap.parse_args()
    examples = [json.loads(l) for l in open(os.path.join(args.benchmark, 'examples.jsonl'))]
    examples = [e for e in examples if (e['family'], e['kind']) in DEFAULT_FAMILIES]
    by_instance = {}
    for e in examples:
        by_instance.setdefault(e['instance_id'], []).append(e)
    if args.ids:
        by_instance = {k: v for k, v in by_instance.items() if k in set(args.ids.split(','))}
    lock = threading.Lock()

    def work(item):
        iid, exs = item
        try:
            rows = run_instance(griffe, iid, exs, args.benchmark, args.work_root)
        except Exception as e:
            print(f"[griffe] {iid} error: {type(e).__name__}: {str(e)[:150]}", flush=True)
            return
        with lock, open(args.out, 'a') as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')
        print(f"[griffe] {iid} ok", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        list(pool.map(work, sorted(by_instance.items())))


if __name__ == '__main__':
    main()
