import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor


TOP_PACKAGE = {
    'django/django': 'django',
    'sympy/sympy': 'sympy',
    'sphinx-doc/sphinx': 'sphinx',
    'pydata/xarray': 'xarray',
    'pylint-dev/pylint': 'pylint',
    'psf/requests': 'requests',
    'mwaskom/seaborn': 'seaborn',
}

C_EXTENSION_REPOS = {'astropy/astropy', 'matplotlib/matplotlib', 'scikit-learn/scikit-learn'}


HF_ROWS_URL = ("https://datasets-server.huggingface.co/rows?dataset=princeton-nlp%2FSWE-bench_Verified"
               "&config=default&split=test&offset={offset}&length=100")


def default_cache_path():
    return os.path.join(os.path.expanduser('~'), '.cache', 'patchguard', 'swebench_verified.json')


def fetch_swebench_verified(cache_path=None):
    """Download SWE-bench Verified once and cache it as JSON."""
    cache_path = cache_path or default_cache_path()
    if os.path.exists(cache_path):
        return json.load(open(cache_path))
    rows = []
    for offset in range(0, 500, 100):
        with urllib.request.urlopen(HF_ROWS_URL.format(offset=offset), timeout=60) as resp:
            rows.extend(r['row'] for r in json.load(resp)['rows'])
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    json.dump(rows, open(cache_path, 'w'))
    return rows


def load_instances(limit=None, repos=None, include_c_ext=False, data_file=None, ids=None):
    rows = json.load(open(data_file)) if data_file else fetch_swebench_verified()
    seen = set()
    out = []
    for row in rows:
        if row['instance_id'] in seen:
            continue
        seen.add(row['instance_id'])
        if row['repo'] in C_EXTENSION_REPOS and not include_c_ext:
            continue
        if repos and row['repo'] not in repos:
            continue
        if ids and row['instance_id'] not in ids:
            continue
        out.append(row)
    if limit:
        out = out[:limit]
    return out


def derive_touched_packages(patch_text, top_package):
    """Packages touched by a patch, derived from its diff paths."""
    touched_files = [l.split(' ')[2][2:] for l in patch_text.splitlines() if l.startswith('diff --git')]
    pkgs = set()
    for f in touched_files:
        parts = f.split('/')
        if top_package in parts:
            idx = parts.index(top_package)
            pkgs.add('.'.join(parts[idx:-1]) if len(parts) > idx + 1 else top_package)
    return sorted(pkgs) or [top_package]


def run_one(instance, out_root, work_root, timeout=900, cleanup=False):
    repo = instance['repo']
    instance_id = instance['instance_id']
    top_package = TOP_PACKAGE.get(repo)
    if not top_package:
        return {'instance_id': instance_id, 'status': 'skipped', 'reason': 'no top_package mapping'}

    patch = instance['patch']
    agent = instance.get('_agent')
    touched_pkgs = derive_touched_packages(patch, top_package)

    inst_dir = os.path.join(out_root, instance_id.replace('/', '_'))
    work_dir = os.path.join(work_root, instance_id.replace('/', '_'))
    os.makedirs(inst_dir, exist_ok=True)
    patch_file = os.path.join(inst_dir, 'patch.diff')
    issue_file = os.path.join(inst_dir, 'issue.txt')
    p2p_file = os.path.join(inst_dir, 'p2p.json')
    open(patch_file, 'w').write(patch if patch.endswith('\n') else patch + '\n')
    if agent:
        json.dump({k: agent[k] for k in ('submission', 'resolved', 'applied')}, open(os.path.join(inst_dir, 'agent.json'), 'w'))
    open(issue_file, 'w').write(instance.get('problem_statement', ''))
    json.dump(json.loads(instance['PASS_TO_PASS']), open(p2p_file, 'w'))

    cmd = [
        sys.executable, '-m', 'patchguard.cli',
        '--repo-url', f'https://github.com/{repo}.git',
        '--base-commit', instance['base_commit'],
        '--patch-file', patch_file,
        '--top-package', top_package,
        '--touched-packages', ','.join(touched_pkgs),
        '--issue-text-file', issue_file,
        '--pass-to-pass-file', p2p_file,
        '--work-dir', work_dir,
        '--out-dir', inst_dir,
    ]
    if agent:
        cmd.append('--negative-only')
    t0 = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        ok = proc.returncode == 0
        result = {'instance_id': instance_id, 'repo': repo, 'status': 'ok' if ok else 'error',
                  'elapsed_s': round(time.time() - t0, 1), 'stdout_tail': stdout[-1500:],
                  'stderr_tail': stderr[-1500:] if not ok else None}
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        result = {'instance_id': instance_id, 'repo': repo, 'status': 'timeout',
                  'elapsed_s': timeout}
    if cleanup:
        shutil.rmtree(work_dir, ignore_errors=True)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=20)
    ap.add_argument('--repos', default=None, help='comma-separated repo filter, e.g. django/django,sympy/sympy')
    ap.add_argument('--ids', default=None, help='comma-separated instance ids (overrides --limit)')
    ap.add_argument('--out-root', required=True)
    ap.add_argument('--work-root', required=True)
    ap.add_argument('--timeout', type=int, default=900)
    ap.add_argument('--workers', type=int, default=1, help='instances processed in parallel')
    ap.add_argument('--resume', action='store_true', help='skip instances already finished with status ok; rerun the rest from scratch')
    ap.add_argument('--cleanup', action='store_true', help='delete each instance work directory (clones, venv) after it finishes')
    ap.add_argument('--include-c-ext', action='store_true', help='also try astropy/matplotlib/scikit-learn (usually fail to build)')
    ap.add_argument('--data-file', default=None, help='local SWE-bench Verified JSON (list of rows); default: download and cache')
    ap.add_argument('--agent-patches', default=None, help='JSONL from patchguard-agent-patches; analyze these patches instead of the reference ones')
    ap.add_argument('--submission', default=None, help='with --agent-patches: the submission whose patches to analyze')
    args = ap.parse_args()

    repos = set(args.repos.split(',')) if args.repos else None
    ids = set(args.ids.split(',')) if args.ids else None
    instances = load_instances(limit=None if ids else args.limit, repos=repos, include_c_ext=args.include_c_ext,
                               data_file=args.data_file, ids=ids)
    if args.agent_patches:
        by_id = {}
        for line in open(args.agent_patches, encoding='utf-8'):
            rec = json.loads(line)
            if rec['submission'] == args.submission and rec['applied']:
                by_id[rec['instance_id']] = rec
        instances = [{**i, 'patch': by_id[i['instance_id']]['patch'], '_agent': by_id[i['instance_id']]}
                     for i in instances if i['instance_id'] in by_id]
    os.makedirs(args.out_root, exist_ok=True)
    summary_path = os.path.join(args.out_root, '_batch_summary.json')
    results = {}
    if args.resume and os.path.exists(summary_path):
        results = {r['instance_id']: r for r in json.load(open(summary_path))}
    todo = [i for i in instances if results.get(i['instance_id'], {}).get('status') != 'ok']
    print(f"[batch] {len(instances)} selected, {len(todo)} to run (C-ext repos excluded by default)", flush=True)

    lock = threading.Lock()

    def work(inst):
        iid = inst['instance_id'].replace('/', '_')
        shutil.rmtree(os.path.join(args.out_root, iid), ignore_errors=True)
        shutil.rmtree(os.path.join(args.work_root, iid), ignore_errors=True)
        res = run_one(inst, args.out_root, args.work_root, timeout=args.timeout, cleanup=args.cleanup)
        with lock:
            results[inst['instance_id']] = res
            json.dump(list(results.values()), open(summary_path, 'w'), indent=1)
            print(f"[batch] {inst['instance_id']} -> {res['status']} ({res.get('elapsed_s', '?')}s)", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        list(pool.map(work, todo))

    by_status = {}
    for r in results.values():
        by_status[r['status']] = by_status.get(r['status'], 0) + 1
    print(f"[batch] DONE. {by_status}", flush=True)


if __name__ == '__main__':
    main()
