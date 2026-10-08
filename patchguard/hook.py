import hashlib
import json
import os
import re
import subprocess
import sys
import time

CACHE_DIR_NAME = '.patchguard_hook_cache'


def get_cache_dir(cwd):
    d = os.path.join(cwd, CACHE_DIR_NAME)
    os.makedirs(d, exist_ok=True)
    return d


LOG_NAME = 'usage.jsonl'


def log_event(cwd, record):
    """Append one invocation record to <cwd>/.patchguard_hook_cache/usage.jsonl; never raises."""
    try:
        with open(os.path.join(get_cache_dir(cwd), LOG_NAME), 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
    except Exception:
        pass


def summarize_log(cwd):
    """Human-readable usage summary of the hook in cwd."""
    path = os.path.join(cwd, CACHE_DIR_NAME, LOG_NAME)
    if not os.path.exists(path):
        return 'no usage log yet'
    events = [json.loads(line) for line in open(path, encoding='utf-8') if line.strip()]
    py = [e for e in events if e['outcome'] != 'not_python']
    flagged = [e for e in events if e['outcome'] == 'flagged']
    repeats = sum(e['outcome'] == 'repeat' for e in events)
    latencies = sorted(e['latency_ms'] for e in py)
    out = [f"{len(events)} hook calls, {len(py)} on .py files, {len(flagged)} flagged ({repeats} repeats suppressed), "
           f"{sum(e['outcome'] == 'error' for e in events)} errors",
           f"median latency {latencies[len(latencies) // 2]} ms" if latencies else 'no latency data']
    for e in flagged:
        out.append(f"{e['ts']}  {e['file']}")
        for f in e['findings']:
            out.append(f"    - {f}")
    return '\n'.join(out)


def get_or_create_pre_snapshot(cwd, top_package):
    """Mined state of HEAD, cached per commit and per miner version."""
    from . import mine as mine_module
    from .mine import mine
    cache_dir = get_cache_dir(cwd)
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=cwd, capture_output=True, text=True).stdout.strip()
    miner = hashlib.sha1(open(mine_module.__file__, 'rb').read()).hexdigest()[:8]
    cache_file = os.path.join(cache_dir, f'pre_{top_package}_{head[:12]}_{miner}.json')
    if head and os.path.exists(cache_file):
        return json.load(open(cache_file))

    worktree = os.path.join(cache_dir, f'pre_worktree_{top_package}')
    if os.path.exists(worktree):
        subprocess.run(['git', 'checkout', '-q', '--detach', head or 'HEAD'], cwd=worktree, capture_output=True, text=True)
    else:
        subprocess.run(['git', 'worktree', 'add', '--detach', worktree, 'HEAD'],
                       cwd=cwd, capture_output=True, text=True)
    edges, reads = mine(worktree, top_package)
    data = {'edges': {f"{a}=>{b}": c for (a, b), c in edges.items()}, 'reads': reads}
    if head:
        json.dump(data, open(cache_file, 'w'))
    return data


def guess_top_package(cwd, file_path):
    """Top-level package of the edited file; PATCHGUARD_TOP_PACKAGE overrides."""
    override = os.environ.get('PATCHGUARD_TOP_PACKAGE')
    if override:
        return override
    rel = os.path.relpath(file_path, cwd)
    parts = rel.split(os.sep)
    for i in range(1, len(parts)):
        candidate = parts[0] if i == 1 else os.sep.join(parts[:i])
        if os.path.exists(os.path.join(cwd, candidate, '__init__.py')):
            return candidate.replace(os.sep, '.')
    return parts[0]


def finding_key(finding):
    return f"{finding.get('pair') or finding.get('function')}|{','.join(finding.get('added', []))}"


def select_new(cwd, session_id, findings):
    """Findings not yet reported in this session; a finding that disappears and returns is reported again."""
    cache_dir = get_cache_dir(cwd)
    path = os.path.join(cache_dir, f"session_{re.sub(r'[^A-Za-z0-9_-]', '', str(session_id or 'nosession'))}.json")
    try:
        seen = set(json.load(open(path)))
    except (OSError, ValueError):
        seen = set()
    keys = {finding_key(f) for f in findings}
    json.dump(sorted(keys), open(path, 'w'))
    return [f for f in findings if finding_key(f) not in seen]


def check(cwd, file_path):
    from .mine import mine, collect_known_packages
    from .partition import compute_t_module, partition_e_findings, partition_readset_findings

    top_package = guess_top_package(cwd, file_path)
    if not os.path.isdir(os.path.join(cwd, top_package.split('.')[0])):
        return None

    pre = get_or_create_pre_snapshot(cwd, top_package)
    post_edges, post_reads = mine(cwd, top_package)
    post_edges_json = {f"{a}=>{b}": c for (a, b), c in post_edges.items()}

    new_pairs = sorted(set(post_edges_json) - set(pre['edges']))
    read_changes = []
    for qn in set(pre['reads']) & set(post_reads):
        added = sorted(set(post_reads[qn]) - set(pre['reads'][qn]))
        if added:
            read_changes.append({'function': qn, 'added': added})

    if not new_pairs and not read_changes:
        return None

    known_pkgs = collect_known_packages(cwd, top_package)
    touched_files = [os.path.relpath(file_path, cwd)]
    t_module = compute_t_module(touched_files, '', known_pkgs, top_package)
    t_symbol = set(post_reads) - set(pre['reads'])

    e_findings = partition_e_findings(
        [{'pair': p, 'count': post_edges_json[p]} for p in new_pairs],
        t_module, set(), pre['edges'], k=1)
    rs_findings = partition_readset_findings(read_changes, t_symbol, {}, k=1)

    frame = [f for f in e_findings + rs_findings if f['verdict'] == 'frame']
    return frame or None


def main():
    if '--summary' in sys.argv:
        print(summarize_log(os.getcwd()))
        return
    t0 = time.time()
    cwd, rel, tool, frame, outcome, error, repeated = os.getcwd(), None, None, None, 'silent', None, 0
    try:
        hook_input = json.load(sys.stdin)
        tool = hook_input.get('tool_name')
        tool_input = hook_input.get('tool_input', {})
        cwd = hook_input.get('cwd', cwd)
        file_path = tool_input.get('file_path')
        if file_path:
            rel = os.path.relpath(file_path, cwd)
        if file_path and not file_path.endswith('.py'):
            file_path = None
            outcome = 'not_python'
        frame = check(cwd, file_path) if file_path else None
        if file_path:
            found = frame or []
            frame = select_new(cwd, hook_input.get('session_id'), found)
            repeated = len(found) - len(frame)
    except Exception as e:
        frame, outcome, error = None, 'error', f"{type(e).__name__}: {str(e)[:200]}"

    if frame:
        outcome = 'flagged'
    elif repeated:
        outcome = 'repeat'
    log_event(cwd, {'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'tool': tool, 'file': rel, 'outcome': outcome,
                    'n_frame': len(frame or []), 'n_repeat': repeated, 'latency_ms': round((time.time() - t0) * 1000), 'error': error,
                    'findings': [f"{f.get('pair') or f.get('function', '').split('::')[-1]}: {f['reason']}"
                                 for f in (frame or [])]})

    if frame:
        lines = ["⚠️ PatchGuard: этот edit мог затронуть инвариант вне заявленной области "
                 "задачи (не только что редактируемый файл — скрытая зависимость в коде):"]
        for f in frame[:5]:
            label = f.get('pair') or f.get('function', '').split('::')[-1]
            lines.append(f"  - {label}: {f['reason']}")
        if len(frame) > 5:
            lines.append(f"  ... и ещё {len(frame) - 5}")
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                   "additionalContext": '\n'.join(lines)}}))
    sys.exit(0)


if __name__ == '__main__':
    main()
