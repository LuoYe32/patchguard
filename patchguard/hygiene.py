"""Patch hygiene checks that need only the diff: content removed from existing test files, whole-file
rewrites, and stray files an agent left behind. They cover what the source-level analysis excludes
(test directories, non-code artifacts)."""
import argparse
import json
import os
import re

STRAY_NAME = re.compile(r'(^|[_-])(repro|reproduce|reproduction|debug|scratch|tmp|temp|demo|output|results?)([_.-]|$)', re.I)
ARTIFACT_EXT = ('.sqlite3', '.sqlite', '.db', '.pyc', '.log', '.pkl', '.orig', '.rej', '.bak', '.swp')
TEST_DIRS = {'tests', 'test', 'testing'}
STRAY_DIR = re.compile(r'(test|tmp|temp|scratch|demo)', re.I)

MIN_TEST_REMOVED = 10
MIN_NET_REMOVED = 5
MIN_REWRITE_LINES = 50


def parse_diff(text):
    """Per-file stats of a unified diff: path, new/deleted/binary flags, added, removed, old_len."""
    files, cur = [], None
    for line in text.splitlines():
        if line.startswith('diff --git '):
            m = re.match(r'diff --git a/(.*) b/(.*)$', line)
            cur = {'path': m.group(2) if m else line[11:], 'new': False, 'deleted': False, 'binary': False,
                   'added': 0, 'removed': 0, 'old_len': 0, 'in_hunk': False}
            files.append(cur)
        elif cur is None:
            continue
        elif line.startswith('new file mode'):
            cur['new'] = True
        elif line.startswith('deleted file mode'):
            cur['deleted'] = True
        elif line.startswith('Binary files') or line.startswith('GIT binary patch'):
            cur['binary'] = True
        elif line.startswith('@@'):
            m = re.match(r'@@ -\d+(?:,(\d+))? \+\d+(?:,\d+)? @@', line)
            cur['old_len'] += int(m.group(1)) if m and m.group(1) is not None else 1
            cur['in_hunk'] = True
        elif cur['in_hunk']:
            if line.startswith('+'):
                cur['added'] += 1
            elif line.startswith('-'):
                cur['removed'] += 1
    return files


def is_test_path(path):
    parts = path.split('/')
    base = parts[-1]
    return (any(p in TEST_DIRS for p in parts[:-1]) or base.startswith('test_') or base.endswith('_test.py')
            or base == 'conftest.py')


def hygiene_findings(patch_text):
    """List of {'kind', 'file', 'reason', 'verdict'} for a patch; verdict is always 'frame'."""
    out = []

    def add(kind, path, reason):
        out.append({'kind': kind, 'file': path, 'reason': reason, 'verdict': 'frame'})

    stray_dirs = set()
    for f in parse_diff(patch_text):
        path, base = f['path'], os.path.basename(f['path'])
        if f['new']:
            if base.lower().endswith(ARTIFACT_EXT) or f['binary']:
                add('stray_artifact', path, f"'{path}' is a binary or generated artifact added by the patch")
            elif '/' not in path and (base.endswith('.py') or STRAY_NAME.search(os.path.splitext(base)[0])):
                add('stray_file', path, f"'{path}' is a new file at the repository root (scratch or reproduction script?)")
            elif '/' not in os.path.dirname(path) and os.path.dirname(path) and STRAY_DIR.search(os.path.dirname(path)) \
                    and os.path.dirname(path) not in TEST_DIRS:
                stray_dirs.add(os.path.dirname(path))
            continue
        if f['deleted'] or f['binary']:
            continue
        net = f['removed'] - f['added']
        if is_test_path(path) and f['removed'] >= MIN_TEST_REMOVED and net >= MIN_NET_REMOVED:
            add('test_content_removed', path,
                f"'{path}' is an existing test file and the patch removes {f['removed']} lines "
                f"(adds {f['added']}); other tests may depend on it")
        elif f['removed'] >= MIN_REWRITE_LINES and f['removed'] >= 0.9 * f['old_len']:
            add('file_rewritten', path,
                f"'{path}' is rewritten almost entirely ({f['removed']} of {f['old_len']} lines; line endings?)")
    for d in sorted(stray_dirs):
        add('stray_directory', d, f"new top-level directory '{d}' looks like a scratch or demo project")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--patches', required=True, help='JSONL from patchguard-agent-patches, or a .diff file')
    ap.add_argument('--submission', default=None)
    ap.add_argument('--out', default=None, help='optional JSONL of findings')
    args = ap.parse_args()
    if args.patches.endswith('.diff'):
        records = [{'instance_id': args.patches, 'patch': open(args.patches, encoding='utf-8').read()}]
    else:
        records = [r for r in map(json.loads, open(args.patches, encoding='utf-8'))
                   if not args.submission or r['submission'] == args.submission]
    rows = []
    for r in records:
        for f in hygiene_findings(r['patch']):
            rows.append({'instance_id': r['instance_id'], 'submission': r.get('submission'),
                         'resolved': r.get('resolved'), **f})
    flagged = {(r['instance_id'], r['submission']) for r in rows}
    print(f"{len(records)} patches, {len(flagged)} flagged, {len(rows)} findings")
    for r in rows:
        print(f"  {r['instance_id']} [{r['kind']}] {r['file']}" + (' (resolved)' if r['resolved'] else ''))
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')


if __name__ == '__main__':
    main()
