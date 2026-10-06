import argparse
import json
import os
import re
import subprocess
import sys
import time


def detect_runner(repo_dir):
    if os.path.exists(os.path.join(repo_dir, 'tests', 'runtests.py')):
        return 'django'
    return 'pytest'


def convert_django_labels(ids):
    """Convert 'test_x (pkg.Class)' IDs to dotted Django labels; returns (labels, skipped). IDs
    that are bare docstrings cannot be resolved and are skipped with a warning."""
    labels, skipped = [], []
    for tid in ids:
        m = re.match(r'^(\w+)\s+\(([\w.]+)\)$', tid.strip())
        if m:
            labels.append(f"{m.group(2)}.{m.group(1)}")
        elif re.match(r'^[\w.]+\.\w+$', tid.strip()):
            labels.append(tid.strip())
        else:
            skipped.append(tid.strip())
    if skipped:
        print(f"[baseline] WARNING: skipped {len(skipped)} PASS_TO_PASS entries that aren't "
              f"resolvable test IDs (likely docstring-derived, a known SWE-bench data quirk): "
              f"{skipped}", file=sys.stderr)
    return labels, skipped


def setup_venv(venv_dir, seed_repo_dir):
    """Create a venv with one editable install to pull in dependencies; returns (python, ok,
    error)."""
    venv_dir = os.path.abspath(venv_dir)
    seed_repo_dir = os.path.abspath(seed_repo_dir)
    python = os.path.join(venv_dir, 'bin', 'python3')
    if not os.path.exists(python):
        subprocess.run([sys.executable, '-m', 'venv', venv_dir], check=True)
        for attempt in range(3):
            if subprocess.run([python, '-m', 'pip', 'install', '--quiet', 'pytest']).returncode == 0:
                break
            if attempt == 2:
                return python, False, 'pip install pytest failed after 3 attempts'
            time.sleep(15 * (attempt + 1))
        r = subprocess.run([python, '-m', 'pip', 'install', '--quiet', '-e', '.'],
                            cwd=seed_repo_dir, capture_output=True, text=True)
        if r.returncode != 0:
            return python, False, r.stderr[-3000:]
        req_file = os.path.join(seed_repo_dir, 'tests', 'requirements', 'py3.txt')
        if os.path.exists(req_file):
            subprocess.run([python, '-m', 'pip', 'install', '--quiet', '-r', req_file],
                            cwd=seed_repo_dir, check=False)
    return python, True, None


def run_baseline(repo_dir, venv_python, pass_to_pass_ids, runner=None, test_file=None, timeout=300):
    """Run the PASS_TO_PASS tests against repo_dir with the Django runner or pytest; returns a
    result dict."""
    repo_dir = os.path.abspath(repo_dir)
    runner = runner or detect_runner(repo_dir)
    env = os.environ.copy()
    env['PYTHONPATH'] = repo_dir

    if runner == 'django':
        labels, skipped = convert_django_labels(pass_to_pass_ids)
        cmd = [venv_python, os.path.join(repo_dir, 'tests', 'runtests.py')] + labels + ['-v0']
        r = subprocess.run(cmd, cwd=repo_dir, env=env, capture_output=True, text=True, timeout=timeout)
        ok = r.returncode == 0
        m = re.search(r'Ran (\d+) test', r.stderr)
        total = int(m.group(1)) if m else None
        return {'runner': 'django', 'total': total, 'skipped_unresolved': len(skipped),
                'ok': ok, 'tail': r.stderr[-2000:]}

    has_path_style = any('::' in t for t in pass_to_pass_ids)
    if has_path_style:
        cmd = [venv_python, '-m', 'pytest', '-q'] + [t.strip() for t in pass_to_pass_ids]
    elif test_file:
        kexpr = ' or '.join(t.strip() for t in pass_to_pass_ids)
        cmd = [venv_python, '-m', 'pytest', '-q', test_file, '-k', kexpr]
    else:
        return {'runner': 'pytest', 'ok': None, 'tail':
                'SKIPPED: bare test names given without --test-file (see module docstring - '
                'automatic test-file discovery not implemented, documented simplification)'}
    r = subprocess.run(cmd, cwd=repo_dir, env=env, capture_output=True, text=True, timeout=timeout)
    ok = r.returncode == 0
    m = re.search(r'(\d+) passed', r.stdout)
    passed = int(m.group(1)) if m else None
    m2 = re.search(r'(\d+) failed', r.stdout)
    failed = int(m2.group(1)) if m2 else 0
    return {'runner': 'pytest', 'passed': passed, 'failed': failed, 'ok': ok, 'tail': r.stdout[-2000:]}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-dir', required=True)
    ap.add_argument('--venv-dir', required=True)
    ap.add_argument('--pass-to-pass-file', required=True, help='JSON file: list of PASS_TO_PASS test IDs')
    ap.add_argument('--test-file', default=None)
    args = ap.parse_args()

    args.repo_dir = os.path.abspath(args.repo_dir)
    ids = json.load(open(args.pass_to_pass_file))
    python, ok, err = setup_venv(args.venv_dir, args.repo_dir)
    if not ok:
        print(f"venv setup FAILED: {err}")
        sys.exit(1)
    result = run_baseline(args.repo_dir, python, ids, test_file=args.test_file)
    print(json.dumps(result, indent=1))
