import argparse
import json
import os
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .agent_patches import CACHE_DIR
from .baseline import convert_django_labels, setup_venv
from .batch_invarbench import load_instances
from .cli import prepare_repo, run

FAILURE_RE = re.compile(r'^(?:FAIL|ERROR): (.+)$', re.M)
RAN_RE = re.compile(r'^Ran (\d+) tests? in', re.M)


def parse_failures(output):
    """(set of failing test headers, number of tests run or None when the run crashed)."""
    ran = RAN_RE.search(output)
    return set(FAILURE_RE.findall(output)), int(ran.group(1)) if ran else None


def run_suite(python, repo_dir, labels=(), timeout=3600):
    t0 = time.time()
    try:
        proc = subprocess.run([python, 'tests/runtests.py', '--parallel', '1', '-v0', *labels],
                              cwd=repo_dir, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return {'failures': set(), 'tests_run': None, 'crashed': True, 'timeout': True,
                'elapsed_s': round(time.time() - t0, 1), 'tail': ''}
    failures, ran = parse_failures(output)
    return {'failures': failures, 'tests_run': ran, 'crashed': ran is None, 'timeout': False,
            'elapsed_s': round(time.time() - t0, 1), 'tail': output[-600:] if ran is None else ''}


def confirm(python, repo_dir, regressions):
    """Re-run the regressed tests; only those that fail again are confirmed."""
    labels, _ = convert_django_labels([re.sub(r'\s+\(\w+=.*\)$', '', r) for r in sorted(regressions)])
    if not labels:
        return set(), set(regressions)
    again = run_suite(python, repo_dir, labels, timeout=1800)
    still = {r for r in regressions if r in again['failures']}
    unresolvable = {r for r in regressions if not re.match(r'^\w+ \([\w.]+\)', r)}
    return still | unresolvable, unresolvable


def analyze_patch(python, repo_dir, patch_text, base_failures):
    run(['git', 'reset', '--hard', '-q'], cwd=repo_dir)
    run(['git', 'clean', '-fdq'], cwd=repo_dir, check=False)
    patch_path = os.path.join(repo_dir, '..', 'candidate.patch')
    open(patch_path, 'w').write(patch_text if patch_text.endswith('\n') else patch_text + '\n')
    applied = run(['git', 'apply', os.path.abspath(patch_path)], cwd=repo_dir, check=False)
    if applied.returncode != 0:
        return {'status': 'not_applied'}
    result = run_suite(python, repo_dir)
    regressions = result['failures'] - base_failures
    confirmed, unresolvable = confirm(python, repo_dir, regressions) if regressions and not result['crashed'] else (set(), set())
    return {'status': 'crashed' if result['crashed'] else 'ok', 'tests_run': result['tests_run'],
            'elapsed_s': result['elapsed_s'], 'tail': result['tail'],
            'regressions': sorted(regressions), 'confirmed_regressions': sorted(confirmed),
            'unverifiable': sorted(unresolvable)}


def run_instance(inst, variants, out_root, work_root):
    iid = inst['instance_id']
    out_dir = os.path.join(out_root, iid)
    work_dir = os.path.join(work_root, iid)
    os.makedirs(out_dir, exist_ok=True)
    todo = [v for v in variants if not os.path.exists(os.path.join(out_dir, f"{v['name']}.json"))]
    if not todo:
        return
    try:
        repo = prepare_repo(f"https://github.com/{inst['repo']}.git", inst['base_commit'], work_dir, 'full')
        python, ok, err = setup_venv(os.path.join(work_dir, 'venv'), repo)
        if not ok:
            json.dump({'status': 'venv_failed', 'error': err[-500:]}, open(os.path.join(out_dir, 'base.json'), 'w'))
            return
        base_path = os.path.join(out_dir, 'base.json')
        if os.path.exists(base_path):
            base = json.load(open(base_path))
            base_failures = set(base['failures'])
        else:
            base = run_suite(python, repo)
            base_failures = base['failures']
            json.dump({**base, 'failures': sorted(base['failures'])}, open(base_path, 'w'))
        if base.get('crashed'):
            return
        for variant in todo:
            patch = variant['patches'].get(iid)
            if patch is None:
                continue
            result = analyze_patch(python, repo, patch, base_failures)
            result.update({'instance_id': iid, 'variant': variant['name'], 'base_failures': len(base_failures)})
            json.dump(result, open(os.path.join(out_dir, f"{variant['name']}.json"), 'w'), indent=1)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def load_variants(names, agent_patches, instances):
    variants = []
    for name in names:
        if name == 'gold':
            variants.append({'name': 'gold', 'patches': {i['instance_id']: i['patch'] for i in instances}})
            continue
        patches = {}
        for line in open(agent_patches, encoding='utf-8'):
            rec = json.loads(line)
            if rec['submission'] == name and rec['applied'] and rec['resolved']:
                patches[rec['instance_id']] = rec['patch']
        variants.append({'name': name, 'patches': patches})
    return variants


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--limit', type=int, default=60)
    ap.add_argument('--ids', default=None)
    ap.add_argument('--variants', required=True, help="comma-separated: 'gold' and/or submission names (resolved patches only)")
    ap.add_argument('--agent-patches', default=None)
    ap.add_argument('--out-root', required=True)
    ap.add_argument('--work-root', required=True)
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--data-file', default=None)
    args = ap.parse_args()

    ids = set(args.ids.split(',')) if args.ids else None
    instances = load_instances(limit=None if ids else args.limit, repos={'django/django'},
                               data_file=args.data_file, ids=ids)
    variants = load_variants(args.variants.split(','), args.agent_patches, instances)
    os.makedirs(args.out_root, exist_ok=True)
    lock, done = threading.Lock(), [0]

    def work(inst):
        try:
            run_instance(inst, variants, args.out_root, args.work_root)
            status = 'ok'
        except Exception as e:
            status = f"error: {type(e).__name__}: {str(e)[:200]}"
        with lock:
            done[0] += 1
            print(f"[fulltest] {inst['instance_id']} -> {status} ({done[0]}/{len(instances)})", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        list(pool.map(work, instances))
    print('[fulltest] DONE', flush=True)


if __name__ == '__main__':
    main()
