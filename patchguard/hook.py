import json
import os
import subprocess
import sys

CACHE_DIR_NAME = '.patchguard_hook_cache'


def get_cache_dir(cwd):
    d = os.path.join(cwd, CACHE_DIR_NAME)
    os.makedirs(d, exist_ok=True)
    return d


def get_or_create_pre_snapshot(cwd, top_package):
    from .mine import mine
    cache_dir = get_cache_dir(cwd)
    cache_file = os.path.join(cache_dir, f'pre_{top_package}.json')
    if os.path.exists(cache_file):
        return json.load(open(cache_file))

    worktree = os.path.join(cache_dir, f'pre_worktree_{top_package}')
    if not os.path.exists(worktree):
        subprocess.run(['git', 'worktree', 'add', '--detach', worktree, 'HEAD'],
                        cwd=cwd, capture_output=True, text=True)
    edges, reads = mine(worktree, top_package)
    data = {'edges': {f"{a}=>{b}": c for (a, b), c in edges.items()}, 'reads': reads}
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
    try:
        hook_input = json.load(sys.stdin)
        tool_input = hook_input.get('tool_input', {})
        cwd = hook_input.get('cwd', os.getcwd())
        file_path = tool_input.get('file_path')
        if file_path and not file_path.endswith('.py'):
            file_path = None
        frame = check(cwd, file_path) if file_path else None
    except Exception:
        frame = None

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
