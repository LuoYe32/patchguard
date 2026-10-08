import argparse
import json
import os
import subprocess
import sys
import tempfile

from .history import classify, state
from .hygiene import hygiene_findings
from .severity import TIER_NAMES, record_of, severity

IGNORED_DIRS = {'tests', 'test', 'docs', 'doc', 'examples', 'scripts', 'build', 'dist', 'node_modules', 'venv', '.venv'}


def run_git(repo, *args, check=True):
    return subprocess.run(['git', *args], cwd=repo, capture_output=True, text=True, encoding='utf-8',
                          errors='replace', check=check)


def discover_packages(repo):
    """(root, package) pairs for directories with __init__.py at the repository root or in src/."""
    found = []
    for root_rel in ('', 'src'):
        base = os.path.join(repo, root_rel) if root_rel else repo
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if name in IGNORED_DIRS or name.startswith('.'):
                continue
            if os.path.isfile(os.path.join(base, name, '__init__.py')):
                found.append((root_rel, name))
    return found


def changed_python_files(repo, base, head):
    out = run_git(repo, 'diff', '--name-only', base, *( [head] if head else [] )).stdout.split()
    untracked = run_git(repo, 'ls-files', '--others', '--exclude-standard').stdout.split() if not head else []
    return sorted({f for f in out + untracked if f.endswith('.py')})


def untracked_diff(repo):
    """Diff text that shows new untracked files as added, so that hygiene checks can see them."""
    parts = []
    for rel in run_git(repo, 'ls-files', '--others', '--exclude-standard').stdout.split('\n'):
        path = os.path.join(repo, rel)
        if not rel or not os.path.isfile(path):
            continue
        with open(path, 'rb') as f:
            raw = f.read(1_000_000)
        if b'\0' in raw:
            parts.append(f"diff --git a/{rel} b/{rel}\nnew file mode 100644\nBinary files /dev/null and b/{rel} differ\n")
            continue
        lines = raw.decode('utf-8', errors='replace').splitlines()
        parts.append(f"diff --git a/{rel} b/{rel}\nnew file mode 100644\n--- /dev/null\n+++ b/{rel}\n@@ -0,0 +1,{len(lines)} @@\n"
                     + ''.join(f"+{line}\n" for line in lines))
    return ''.join(parts)


def kind_of(finding):
    if 'pair' in finding:
        return 'E'
    if 'added' in finding:
        return 'read-set'
    if 'method' in finding:
        return 'protocol'
    if 'changes' in finding:
        return 'D'
    return 'syntax'


def analyze(repo, base='HEAD', head=None, intent='', packages=None, callers=True):
    """List of findings sorted by severity (each: tier, class, id, reason, details)."""
    repo = os.path.abspath(repo)
    packages = packages or discover_packages(repo)
    if not packages:
        raise SystemExit('no Python package found (a directory with __init__.py at the repository root or in src/); use --package')
    if not intent:
        intent = run_git(repo, 'log', '--format=%B', f'{base}..{head or "HEAD"}', check=False).stdout.strip()
    files = changed_python_files(repo, base, head)
    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        pre_tree = os.path.join(tmp, 'base')
        run_git(repo, 'worktree', 'add', '--detach', pre_tree, base)
        post_tree = repo
        if head:
            post_tree = os.path.join(tmp, 'head')
            run_git(repo, 'worktree', 'add', '--detach', post_tree, head)
        try:
            for root_rel, package in packages:
                prefix = (root_rel + '/' if root_rel else '') + package + '/'
                touched = [f[len(root_rel) + 1:] if root_rel else f for f in files if f.startswith(prefix)]
                if not touched:
                    continue
                pre_root = os.path.join(pre_tree, root_rel) if root_rel else pre_tree
                post_root = os.path.join(post_tree, root_rel) if root_rel else post_tree
                pre, post = state(pre_root, package), state(post_root, package)
                frame, _ = classify(pre, post, touched, intent, post_root, package, callers=callers)
                for f in frame:
                    cls = kind_of(f)
                    record = record_of(cls, f)
                    findings.append({'tier': severity(record), 'class': cls, 'id': record['id'], 'reason': f.get('reason', ''),
                                     'detail': {k: v for k, v in record.items() if k not in ('class', 'id')}})
        finally:
            run_git(repo, 'worktree', 'remove', '--force', pre_tree, check=False)
            if head:
                run_git(repo, 'worktree', 'remove', '--force', post_tree, check=False)
    diff = run_git(repo, 'diff', base, *([head] if head else [])).stdout + (untracked_diff(repo) if not head else '')
    for f in hygiene_findings(diff):
        record = record_of('hygiene', f)
        findings.append({'tier': severity(record), 'class': 'hygiene', 'id': f['file'], 'reason': f['reason'],
                         'detail': {'kind': f['kind']}})
    findings.sort(key=lambda x: (-x['tier'], x['class'], x['id']))
    return findings


def render(findings):
    if not findings:
        return 'No out-of-scope changes found.'
    lines = [f"{len(findings)} change(s) outside the intended scope:"]
    for f in findings:
        lines.append(f"  [{TIER_NAMES[f['tier']].upper():6s}] {f['class']:8s} {f['id']}")
        if f['reason']:
            lines.append(f"           {f['reason']}")
    return '\n'.join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='patchguard check', description=__doc__)
    ap.add_argument('--repo', default='.', help='path of the git repository (default: current directory)')
    ap.add_argument('--base', default='HEAD', help='revision to compare against (default: HEAD, i.e. uncommitted changes)')
    ap.add_argument('--head', default=None, help='revision to analyze instead of the working tree')
    ap.add_argument('--intent', default='', help='what the change is meant to do (issue or PR text); default: commit messages in base..head')
    ap.add_argument('--intent-file', default=None)
    ap.add_argument('--package', action='append', default=None,
                    help="top-level package to analyze, as 'name' or 'src/name'; default: discovered automatically")
    ap.add_argument('--no-callers', action='store_true', help='skip the repository-wide caller check of signature changes')
    ap.add_argument('--format', choices=('text', 'json'), default='text')
    ap.add_argument('--fail-on', choices=('low', 'medium', 'high'), default=None,
                    help='exit with status 1 when a finding of at least this severity exists')
    args = ap.parse_args(argv)
    intent = open(args.intent_file, encoding='utf-8').read() if args.intent_file else args.intent
    packages = None
    if args.package:
        packages = [(os.path.dirname(p), os.path.basename(p)) for p in args.package]
    findings = analyze(args.repo, args.base, args.head, intent, packages, callers=not args.no_callers)
    print(json.dumps(findings, indent=1) if args.format == 'json' else render(findings))
    if args.fail_on:
        threshold = {'low': 1, 'medium': 2, 'high': 3}[args.fail_on]
        sys.exit(1 if any(f['tier'] >= threshold for f in findings) else 0)


if __name__ == '__main__':
    main()
