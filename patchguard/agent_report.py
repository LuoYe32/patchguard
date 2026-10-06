import argparse
import glob
import json
import os
from collections import defaultdict

CLASSES = (('e_findings', 'E'), ('readset_findings', 'read-set'), ('d_findings', 'D'), ('syntax_findings', 'syntax'), ('hygiene_findings', 'hygiene'))


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def frame_items(classified):
    """Out-of-scope findings as {'class', 'id', 'detail', 'private'} dicts."""
    items = []
    for key, cls in CLASSES:
        for it in (classified or {}).get(key, []):
            if it['verdict'] != 'frame':
                continue
            if cls == 'E':
                detail = {'count': it.get('count')}
            elif cls == 'syntax':
                detail = {'error': it['error']}
            elif cls == 'hygiene':
                detail = {'kind': it['kind']}
            elif cls == 'read-set':
                detail = {'added': it['added'], 'removed': it['removed']}
            else:
                detail = {'changes': it['changes']}
            items.append({'class': cls, 'id': it.get('pair') or it.get('function') or it['file'], 'detail': detail,
                          'private': it.get('private', False)})
    return items


def load_run(run_dir):
    """{instance_id: record} for one submission directory."""
    runs = {}
    for inst_dir in sorted(glob.glob(os.path.join(run_dir, '*', ''))):
        iid = os.path.basename(os.path.dirname(inst_dir))
        classified = load_json(os.path.join(inst_dir, 'negative', 'classified_report.json'))
        agent = load_json(os.path.join(inst_dir, 'agent.json')) or {}
        if classified is None:
            continue
        baseline = load_json(os.path.join(inst_dir, 'negative', 'baseline_report.json'))
        runs[iid] = {'instance_id': iid, 'resolved': agent.get('resolved'),
                     'findings': frame_items(classified),
                     'p2p_ok': baseline.get('ok') if baseline else None}
    return runs


def summarize(runs):
    n = len(runs)
    with_findings = [r for r in runs.values() if r['findings']]
    by_class = defaultdict(int)
    for r in runs.values():
        for cls in {f['class'] for f in r['findings']}:
            by_class[cls] += 1
    out = {'instances': n, 'with_findings': len(with_findings),
           'rate': round(len(with_findings) / n, 3) if n else None,
           'findings_total': sum(len(r['findings']) for r in runs.values()),
           'instances_by_class': dict(by_class)}
    for flag, name in ((True, 'resolved'), (False, 'unresolved')):
        grp = [r for r in runs.values() if r['resolved'] is flag]
        hit = sum(1 for r in grp if r['findings'])
        out[name] = {'n': len(grp), 'with_findings': hit, 'rate': round(hit / len(grp), 3) if grp else None}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runs', nargs='+', required=True, help='submission output directories')
    ap.add_argument('--reference', required=True, help='batch directory of reference-patch runs')
    ap.add_argument('--out', required=True, help='directory for summary.json and findings.jsonl')
    args = ap.parse_args()

    reference = load_run(args.reference)
    summary, rows = {}, []
    for run_dir in args.runs:
        name = os.path.basename(os.path.normpath(run_dir))
        runs = load_run(run_dir)
        common = {i: r for i, r in reference.items() if i in runs}
        summary[name] = {**summarize(runs),
                         'reference_same_instances': summarize(common) if common else None}
        for iid, rec in runs.items():
            ref_ids = {(f['class'], f['id']) for f in reference.get(iid, {}).get('findings', [])}
            for f in rec['findings']:
                rows.append({'submission': name, 'instance_id': iid, 'resolved': rec['resolved'], **f,
                             'also_in_reference_patch': (f['class'], f['id']) in ref_ids, 'label': None})
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=1)
    with open(os.path.join(args.out, 'findings.jsonl'), 'w', encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
