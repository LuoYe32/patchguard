import argparse
import json
import time

TIER_NAMES = {0: 'none', 1: 'low', 2: 'medium', 3: 'high'}


def is_private(qualified):
    name = str(qualified).split('::')[-1].split('.')[-1]
    return name.startswith('_') and not (name.startswith('__') and name.endswith('__'))


def record_of(cls, finding):
    """Compact, serializable description of a classified finding used for ranking."""
    if cls == 'D':
        return {'class': 'D', 'id': finding['function'], 'private': is_private(finding['function']),
                'kinds': sorted({c['kind'] for c in finding['changes']}), 'broken': finding.get('broken_total'),
                'checked': finding.get('callers_checked')}
    if cls == 'read-set':
        added = finding.get('added', [])
        return {'class': 'read-set', 'id': finding['function'], 'n_added': len(added), 'added': added[:5]}
    if cls == 'E':
        return {'class': 'E', 'id': finding['pair']}
    if cls == 'protocol':
        return {'class': 'protocol', 'id': finding['function'], 'method': finding['method']}
    if cls == 'syntax':
        return {'class': 'syntax', 'id': finding['file']}
    return {'class': 'hygiene', 'id': finding['file'], 'kind': finding['kind']}


def severity(record):
    """3 high, 2 medium, 1 low."""
    cls = record['class']
    if cls == 'syntax':
        return 3
    if cls == 'D':
        if record.get('broken'):
            return 3
        if record.get('private'):
            return 1
        return 1 if record.get('checked') and record.get('broken') == 0 else 2
    if cls == 'read-set':
        added = record.get('added') or []
        if added and all(a.split('.')[-1].startswith('__') for a in added):
            return 1
        return 3 if record.get('n_added', 0) >= 3 else 2
    if cls in ('E', 'protocol'):
        return 2
    if cls == 'hygiene':
        return {'test_content_removed': 3, 'file_rewritten': 2}.get(record.get('kind'), 1)
    return 2


def commit_tier(records):
    return max((severity(r) for r in records), default=0)


def tier_table(rows, flag_of):
    """Counts and induced share of commits by highest severity tier."""
    out = {}
    base = sum(r['induced'] for r in rows) / len(rows) if rows else 0
    for tier in (0, 1, 2, 3):
        sub = [r for r in rows if flag_of(r) == tier]
        induced = sum(r['induced'] for r in sub)
        out[TIER_NAMES[tier]] = {'commits': len(sub), 'induced': induced,
                                 'induced_share': round(induced / len(sub), 3) if sub else None,
                                 'lift_vs_base': round(induced / len(sub) / base, 2) if sub and base else None}
    return out


def history_records(row):
    return [r for r in row.get('frame', []) if 'class' in r] + \
           [{'class': 'hygiene', 'id': '', 'kind': k} for k in row.get('hygiene', [])]


def main():
    from .history import mantel_haenszel, summarize, woolf
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--data', required=True, help='JSONL from patchguard-history run (with severity records)')
    ap.add_argument('--min-year', type=int, default=None)
    ap.add_argument('--max-year', type=int, default=None)
    args = ap.parse_args()
    rows = [r for r in map(json.loads, open(args.data, encoding='utf-8')) if 'error' not in r]
    year = lambda r: time.gmtime(r['time']).tm_year
    rows = [r for r in rows if (args.min_year is None or year(r) >= args.min_year) and (args.max_year is None or year(r) <= args.max_year)]
    rows = [r for r in rows if r.get('frame') is not None and (not r['frame'] or 'broken' in r['frame'][0] or 'n_added' in r['frame'][0]
                                                               or r['frame'][0]['class'] in ('E', 'syntax', 'D', 'read-set'))]
    for r in rows:
        r['tier'] = commit_tier([x for x in history_records(r) if x['class'] != 'hygiene'])
    print(json.dumps({'commits': len(rows), 'induced': sum(r['induced'] for r in rows),
                      'by_tier': tier_table(rows, lambda r: r['tier'])}, indent=1))
    sizes = sorted(r['lines'] for r in rows)
    cuts = (sizes[len(sizes) // 3], sizes[2 * len(sizes) // 3])
    stratum = lambda r: 0 if r['lines'] <= cuts[0] else 1 if r['lines'] <= cuts[1] else 2
    for name, flag in (('any finding', lambda r: r['tier'] >= 1), ('medium or high', lambda r: r['tier'] >= 2), ('high only', lambda r: r['tier'] >= 3)):
        a = sum(1 for r in rows if r['induced'] and flag(r)); b = sum(1 for r in rows if not r['induced'] and flag(r))
        c = sum(1 for r in rows if r['induced'] and not flag(r)); d = sum(1 for r in rows if not r['induced'] and not flag(r))
        strata = [tuple(sum(1 for r in rows if stratum(r) == s and r['induced'] == i and flag(r) == f) for i, f in ((1, True), (0, True), (1, False), (0, False)))
                  for s in range(3)]
        print(f"{name:16s} flagged commits {a + b:5d} ({(a + b) / len(rows):.0%})  precision {a / max(1, a + b):.1%}  recall {a / max(1, a + c):.1%}  "
              f"OR {woolf(a, b, c, d)[0]} {woolf(a, b, c, d)[1]}  size-adjusted OR {mantel_haenszel(strata)}")


if __name__ == '__main__':
    main()
