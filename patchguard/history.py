import argparse
import json
import math
import os
import random
import re
import subprocess
from multiprocessing import Pool

from .cli import extend_call_graph, syntax_findings
from .callers import annotate_callers
from .hygiene import hygiene_findings
from .severity import record_of
from .mine import collect_known_packages, mine, mine_signatures, module_name
from .partition import (build_call_graph, classify_intent, compute_t_module, compute_t_symbol,
                        diff_signatures, partition_e_findings, partition_readset_findings,
                        partition_signature_findings, protocol_findings)

HASH_RE = re.compile(r'\b[0-9a-f]{7,40}\b')


def git(git_dir, *args, cwd=None):
    r = subprocess.run(['git', '--git-dir', git_dir, *args] if cwd is None else ['git', *args],
                       cwd=cwd, capture_output=True, text=True, encoding='utf-8', errors='replace')
    return r.stdout


def regression_links(git_dir):
    """{induced commit hash: [fix commit hashes]} from commit messages that name a regression and a hash."""
    log = git(git_dir, 'log', '--no-merges', '--format=%H%x1f%B%x1e', '-i', '--grep=regression')
    links = {}
    for entry in log.split('\x1e'):
        if '\x1f' not in entry:
            continue
        fix, message = entry.strip().split('\x1f', 1)
        for token in set(HASH_RE.findall(message)):
            if not re.search(r'[a-f]', token) or token == fix[:len(token)]:
                continue
            full = git(git_dir, 'rev-parse', '--verify', '--quiet', token + '^{commit}').strip()
            if full and full != fix:
                links.setdefault(full, []).append(fix)
    return links


PR_REF_RE = re.compile(r'(?:#|gh-|GH-|PR |pull request |pull/)(\d+)', re.I)
PR_SUFFIX_RE = re.compile(r'\(#(\d+)\)\s*$')


def regression_links_by_pr(git_dir):
    """{induced commit: [fix commits]} from regression messages that cite a merged pull request number."""
    log = git(git_dir, 'log', '--no-merges', '--format=%H%x1f%s%x1f%b%x1e')
    pr_commit, candidates = {}, []
    for entry in log.split('\x1e'):
        parts = entry.strip().split('\x1f', 2)
        if len(parts) < 3:
            continue
        commit, subject, body = parts
        m = PR_SUFFIX_RE.search(subject)
        own = m.group(1) if m else None
        if own:
            pr_commit.setdefault(own, commit)
        if re.search(r'regress', subject + ' ' + body, re.I):
            candidates.append((commit, own, subject + '\n' + body))
    links = {}
    for fix, own, text in candidates:
        for n in set(PR_REF_RE.findall(text)):
            induced = pr_commit.get(n)
            if induced and induced != fix and n != own:
                links.setdefault(induced, []).append(fix)
    return links


def commit_meta(git_dir, rev):
    out = git(git_dir, 'show', '-s', '--format=%P%x1f%ct%x1f%B', rev).split('\x1f', 2)
    return {'parents': out[0].split(), 'time': int(out[1]), 'message': out[2].strip()}


def touched_py(git_dir, parent, commit, prefix):
    out = git(git_dir, 'diff', '--name-only', parent, commit)
    return [f for f in out.splitlines() if f.endswith('.py') and f.startswith(prefix + '/')]


def state(worktree, top_package):
    edges, reads = mine(worktree, top_package)
    return {'edges': {f"{a}=>{b}": c for (a, b), c in edges.items()}, 'reads': reads,
            'sigs': mine_signatures(worktree, top_package), 'graph': build_call_graph(worktree, top_package),
            'pkgs': collect_known_packages(worktree, top_package)}


def read_changes(pre_reads, post_reads):
    moved = {r for qn in set(post_reads) - set(pre_reads) for r in post_reads[qn]}
    out = []
    for qn in sorted(set(pre_reads) & set(post_reads)):
        added = sorted(set(post_reads[qn]) - set(pre_reads[qn]))
        removed = sorted(set(pre_reads[qn]) - set(post_reads[qn]) - moved)
        if added or removed:
            out.append({'function': qn, 'added': added, 'removed': removed})
    return out


def classify(pre, post, touched, message, worktree, top_package, callers=True):
    """Out-of-scope findings of a commit, partitioned like the offline pipeline."""
    t_module = compute_t_module(touched, message, pre['pkgs'], top_package)
    intent, boundary, k = classify_intent(message)
    b_pkgs = {p for p in pre['pkgs'] if boundary and boundary in p} if boundary else set()
    touched_modules = {module_name('', f, '') for f in touched}
    t_symbol = compute_t_symbol(pre['reads'], post['reads'], message, touched_modules)
    graph = extend_call_graph(pre['graph'], post['graph'], set(post['reads']) - set(pre['reads']))
    new_pairs = [{'pair': p, 'count': post['edges'][p]} for p in sorted(set(post['edges']) - set(pre['edges']))]
    broken = syntax_findings(worktree, touched)
    sig_changes = diff_signatures(pre['sigs'], post['sigs'], {module_name('', x['file'], '') for x in broken})
    if sig_changes and callers:
        try:
            sig_changes = annotate_callers(sig_changes, pre['sigs'], post['sigs'], worktree)
        except Exception:
            pass
    findings = (partition_e_findings(new_pairs, t_module, b_pkgs, pre['edges'], k)
                + partition_readset_findings(read_changes(pre['reads'], post['reads']), t_symbol, graph, k)
                + partition_signature_findings(sig_changes, t_symbol, graph, k) + broken
                + protocol_findings(pre['sigs'], post['sigs'], message))
    return [f for f in findings if f['verdict'] == 'frame'], intent


def analyze_commit(job):
    git_dir, worktree, commit, top_package = job['git_dir'], job['worktree'], job['commit'], job['top']
    meta = job['meta']
    parent = meta['parents'][0]
    touched = touched_py(git_dir, parent, commit, top_package)
    patch = git(git_dir, 'diff', parent, commit)
    numstat = [line.split('\t') for line in git(git_dir, 'diff', '--numstat', parent, commit).splitlines()]
    row = {'commit': commit, 'time': meta['time'], 'subject': meta['message'].splitlines()[0][:120],
           'files': len(numstat), 'lines': sum(int(a) + int(b) for a, b, _ in numstat if a.isdigit() and b.isdigit()),
           'induced': job['induced'], 'hygiene': [x['kind'] for x in hygiene_findings(patch)]}
    try:
        subprocess.run(['git', 'checkout', '-q', '--detach', parent], cwd=worktree, check=True, capture_output=True)
        pre = state(worktree, top_package)
        subprocess.run(['git', 'checkout', '-q', '--detach', commit], cwd=worktree, check=True, capture_output=True)
        post = state(worktree, top_package)
        frame, intent = classify(pre, post, touched, meta['message'], worktree, top_package)
        row.update({'intent': intent, 'frame': [record_of('E' if 'pair' in f else 'protocol' if 'method' in f else 'syntax' if 'file' in f else
                                                            'read-set' if 'added' in f else 'D', f) for f in frame]})
    except Exception as e:
        row['error'] = f"{type(e).__name__}: {str(e)[:160]}"
    return row


def init_worker(queue):
    global WORKTREE
    WORKTREE = queue.get()


def run_job(job):
    return analyze_commit({**job, 'worktree': WORKTREE})


def sample_commits(git_dir, links, since, until, prefix, n_other, seed, n_induced=None):
    revs = git(git_dir, 'rev-list', '--first-parent', '--no-merges', f'--since={since}', f'--until={until}', 'HEAD', '--', prefix).split()
    induced = [r for r in revs if r in links][:n_induced]
    others = [r for r in revs if r not in links]
    random.Random(seed).shuffle(others)
    return induced, others[:n_other]


def cmd_run(args):
    git_dir = os.path.abspath(args.git_dir)
    if args.commits_from:
        previous = [json.loads(l) for l in open(args.commits_from, encoding='utf-8')]
        links = {r['commit']: [] for r in previous if r['induced']}
        induced = [r['commit'] for r in previous if r['induced']]
        others = [r['commit'] for r in previous if not r['induced']]
    else:
        links = regression_links(git_dir)
        induced, others = sample_commits(git_dir, links, args.since, args.until, args.top, args.others, args.seed, args.induced_limit)
    print(f"[history] {len(links)} induced commits in history, {len(induced)} in window, {len(others)} sampled others", flush=True)
    worktrees = []
    for i in range(args.workers):
        wt = os.path.join(os.path.abspath(args.work), f'wt{i}')
        if not os.path.exists(wt):
            subprocess.run(['git', '--git-dir', git_dir, 'worktree', 'add', '--detach', wt, 'HEAD'], check=True, capture_output=True)
        worktrees.append(wt)
    from multiprocessing import Manager
    manager = Manager()
    queue = manager.Queue()
    for wt in worktrees:
        queue.put(wt)
    jobs = []
    for rev in induced + others:
        meta = commit_meta(git_dir, rev)
        if meta['parents']:
            jobs.append({'git_dir': git_dir, 'commit': rev, 'top': args.top, 'meta': meta, 'induced': rev in links,
                         'fixes': links.get(rev, [])})
    done = set()
    if os.path.exists(args.out):
        done = {json.loads(l)['commit'] for l in open(args.out)}
    jobs = [j for j in jobs if j['commit'] not in done]
    with Pool(args.workers, initializer=init_worker, initargs=(queue,)) as pool, open(args.out, 'a') as out:
        for i, row in enumerate(pool.imap_unordered(run_job, jobs), 1):
            out.write(json.dumps(row, ensure_ascii=False) + '\n')
            out.flush()
            if i % 25 == 0:
                print(f"[history] {i}/{len(jobs)}", flush=True)
    print('[history] DONE', flush=True)


def woolf(a, b, c, d):
    """Odds ratio with 95% CI (Haldane-corrected) for exposed a/b and unexposed c/d (events/non-events)."""
    a, b, c, d = a + .5, b + .5, c + .5, d + .5
    or_ = (a * d) / (b * c)
    se = math.sqrt(1 / a + 1 / b + 1 / c + 1 / d)
    return round(or_, 2), (round(math.exp(math.log(or_) - 1.96 * se), 2), round(math.exp(math.log(or_) + 1.96 * se), 2))


def mantel_haenszel(strata):
    """Pooled odds ratio over strata of (flagged&induced, flagged&clean, unflagged&induced, unflagged&clean)."""
    num = sum(a * d / (a + b + c + d) for a, b, c, d in strata if a + b + c + d)
    den = sum(b * c / (a + b + c + d) for a, b, c, d in strata if a + b + c + d)
    return round(num / den, 2) if den else None


def summarize(rows):
    rows = [r for r in rows if 'error' not in r]
    def table(flag):
        a = sum(1 for r in rows if r['induced'] and flag(r)); b = sum(1 for r in rows if not r['induced'] and flag(r))
        c = sum(1 for r in rows if r['induced'] and not flag(r)); d = sum(1 for r in rows if not r['induced'] and not flag(r))
        or_, ci = woolf(a, b, c, d)
        return {'induced_flagged': a, 'induced_total': a + c, 'other_flagged': b, 'other_total': b + d,
                'odds_ratio': or_, 'ci95': ci}
    sizes = sorted(r['lines'] for r in rows)
    cuts = (sizes[len(sizes) // 3], sizes[2 * len(sizes) // 3]) if sizes else (0, 0)
    stratum = lambda r: 0 if r['lines'] <= cuts[0] else 1 if r['lines'] <= cuts[1] else 2
    def adjusted(flag):
        strata = []
        for s in range(3):
            sub = [r for r in rows if stratum(r) == s]
            strata.append((sum(1 for r in sub if r['induced'] and flag(r)), sum(1 for r in sub if not r['induced'] and flag(r)),
                           sum(1 for r in sub if r['induced'] and not flag(r)), sum(1 for r in sub if not r['induced'] and not flag(r))))
        return mantel_haenszel(strata)
    out = {'commits': len(rows), 'induced': sum(r['induced'] for r in rows), 'size_cuts_lines': cuts, 'by_signal': {}}
    signals = {'any_frame': lambda r: bool(r['frame']), 'hygiene': lambda r: bool(r['hygiene']),
               'any_frame_or_hygiene': lambda r: bool(r['frame'] or r['hygiene'])}
    for cls in ('E', 'read-set', 'D', 'syntax'):
        signals[cls] = (lambda c: lambda r: any(f['class'] == c for f in r['frame']))(cls)
    signals['large_change_baseline'] = lambda r: r['lines'] > cuts[1]
    for name, flag in signals.items():
        out['by_signal'][name] = {**table(flag), 'size_adjusted_or': adjusted(flag)}
    return out


def cmd_report(args):
    rows = [json.loads(l) for l in open(args.data)]
    print(json.dumps(summarize(rows), indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--git-dir', required=True, help='bare clone of the project')
    r.add_argument('--work', required=True)
    r.add_argument('--out', required=True)
    r.add_argument('--top', default='django')
    r.add_argument('--since', default='2018-01-01')
    r.add_argument('--until', default='2022-12-31')
    r.add_argument('--others', type=int, default=1500)
    r.add_argument('--seed', type=int, default=0)
    r.add_argument('--induced-limit', type=int, default=None)
    r.add_argument('--commits-from', default=None, help='re-analyze exactly the commits (and labels) of an earlier output file')
    r.add_argument('--workers', type=int, default=3)
    r.set_defaults(func=cmd_run)
    p = sub.add_parser('report')
    p.add_argument('--data', required=True)
    p.set_defaults(func=cmd_report)
    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
