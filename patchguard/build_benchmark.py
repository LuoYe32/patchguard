import argparse
import glob
import json
import os
from collections import defaultdict

from .batch_invarbench import fetch_swebench_verified

VARIANTS = {'negative': 'negative', 'positive_e': 'E', 'positive_readset': 'read-set', 'positive_d': 'D',
            'twin_readset': 'twin-read-set', 'twin_d': 'twin-D',
            'decoy_optional_param': 'decoy-optional-param', 'decoy_reread': 'decoy-reread',
            'decoy_noop': 'decoy-noop', 'decoy_existing_edge': 'decoy-existing-edge'}
POSITIVE = ('E', 'read-set', 'D')
TWIN = {'twin-read-set': 'read-set', 'twin-D': 'D'}
CLASS_OF = {'e_findings': 'E', 'readset_findings': 'read-set', 'd_findings': 'D', 'syntax_findings': 'syntax', 'hygiene_findings': 'hygiene'}


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def frame_findings(classified):
    out = []
    for key, cls in CLASS_OF.items():
        for item in classified.get(key, []):
            if item['verdict'] != 'frame':
                continue
            ident = item['pair'] if cls == 'E' else item['file'] if cls in ('syntax', 'hygiene') else item['function'].split('::')[-1]
            entry = {'class': cls, 'id': ident}
            if 'private' in item:
                entry['private'] = item['private']
            out.append(entry)
    return out


def is_detected(variant, injection, classified):
    if variant == 'E':
        want = f"{injection['source_pkg']}=>{injection['target_pkg']}"
        return any(i['verdict'] == 'frame' and i['pair'] == want for i in classified.get('e_findings', []))
    if variant == 'read-set':
        qual, attr = injection.get('qualname', injection['function']), f"{injection['param']}.{injection['attr']}"
        return any(i['verdict'] == 'frame' and i['function'].endswith('::' + qual) and attr in i['added']
                   for i in classified.get('readset_findings', []))
    qual = injection['function']
    return any(i['verdict'] == 'frame' and i['function'].endswith('::' + qual)
               and any(c['kind'] == injection['change'] for c in i['changes'])
               for i in classified.get('d_findings', []))


def injected_verdict(variant, injection, classified):
    """Verdict ('frame' or 'scope') the detector gave the injected change, or None if unreported."""
    if variant == 'read-set':
        qual, attr = injection.get('qualname', injection['function']), f"{injection['param']}.{injection['attr']}"
        items = [i for i in classified.get('readset_findings', [])
                 if i['function'].endswith('::' + qual) and attr in i['added']]
    else:
        qual = injection['function']
        items = [i for i in classified.get('d_findings', [])
                 if i['function'].endswith('::' + qual) and any(c['kind'] == injection['change'] for c in i['changes'])]
    return items[0]['verdict'] if items else None


def decoy_flagged(injection, classified, negative_classified):
    """True if the detector reports a new out-of-scope finding on the decoyed function or edge."""
    def frame_ids(report):
        ids = set()
        for key in ('e_findings', 'readset_findings', 'd_findings'):
            for i in (report or {}).get(key, []):
                if i['verdict'] == 'frame':
                    ids.add(i.get('pair') or i['function'])
        return ids
    new = frame_ids(classified) - frame_ids(negative_classified)
    if injection.get('pair'):
        return injection['pair'] in new
    return any(i.endswith('::' + injection['qualname']) for i in new)


def build_records(runs_dir, rows_by_id):
    records = []
    for inst_dir in sorted(glob.glob(os.path.join(runs_dir, '*', ''))):
        iid = os.path.basename(os.path.dirname(inst_dir))
        meta = rows_by_id.get(iid)
        if meta is None:
            continue
        base = {'instance_id': iid, 'repo': meta['repo'], 'base_commit': meta['base_commit']}
        neg_cls = load_json(os.path.join(inst_dir, 'negative', 'classified_report.json'))
        neg_base = load_json(os.path.join(inst_dir, 'negative', 'baseline_report.json'))
        reference_clean = bool(neg_cls is not None and neg_base and neg_base.get('ok') is True)
        for dirname, variant in VARIANTS.items():
            vdir = os.path.join(inst_dir, dirname)
            classified = load_json(os.path.join(vdir, 'classified_report.json'))
            baseline = load_json(os.path.join(vdir, 'baseline_report.json'))
            injection = load_json(os.path.join(vdir, 'injection.json'))
            if variant != 'negative' and injection is None:
                continue
            controlled = variant in TWIN or variant.startswith('decoy')
            complete = classified is not None and (baseline is not None or controlled)
            rec = {**base, 'variant': variant, 'injection': injection, 'complete': complete,
                   'reference_clean': reference_clean,
                   'frame_findings': frame_findings(classified) if classified else None,
                   'baseline_ok': baseline.get('ok') if baseline else None}
            if variant in POSITIVE:
                rec['oracle_verified'] = injection.get('oracle', {}).get('verified', True)
                rec['detected'] = is_detected(variant, injection, classified) if classified else None
                rec['tests_catch_it'] = (baseline.get('ok') is False) if (baseline and reference_clean) else None
            elif variant in TWIN and classified:
                rec['oracle_verified'] = injection.get('oracle', {}).get('verified', True)
                rec['verdict'] = injected_verdict(TWIN[variant], injection, classified)
            elif variant.startswith('decoy') and classified:
                rec['flagged'] = decoy_flagged(injection, classified, neg_cls)
            records.append(rec)
    return records


def summarize(records):
    usable = [r for r in records if r['complete'] and r['reference_clean']]
    summary = {'records': len(records), 'usable': len(usable),
               'instances': len({r['instance_id'] for r in usable}),
               'natural_frame_findings': sum(len(r['frame_findings']) for r in usable if r['variant'] == 'negative')}
    per = defaultdict(lambda: [0, 0, 0, 0])
    for r in usable:
        if r['variant'] not in POSITIVE:
            continue
        per[r['variant']][0] += 1
        verified = r.get('oracle_verified', True)
        per[r['variant']][1] += verified
        per[r['variant']][2] += bool(verified and r['detected'])
        per[r['variant']][3] += bool(verified and r['tests_catch_it'])
    summary['by_class'] = {v: {'n': n, 'oracle_verified': ov, 'detected': d, 'caught_by_tests': t}
                           for v, (n, ov, d, t) in per.items()}
    twins = defaultdict(lambda: {'n': 0, 'scope': 0, 'frame': 0, 'unreported': 0})
    for r in records:
        if r['variant'] in TWIN and r.get('oracle_verified') and 'verdict' in r:
            t = twins[TWIN[r['variant']]]
            t['n'] += 1
            t[r['verdict'] or 'unreported'] += 1
    summary['twins_expected_scope'] = dict(twins)
    decoys = defaultdict(lambda: {'n': 0, 'flagged': 0})
    for r in records:
        if r['variant'].startswith('decoy') and 'flagged' in r:
            decoys[r['variant']]['n'] += 1
            decoys[r['variant']]['flagged'] += bool(r['flagged'])
    summary['decoys_expected_unflagged'] = dict(decoys)
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', required=True, nargs='+', help='batch output directories (later ones win on duplicate instances)')
    ap.add_argument('--out', required=True, help='manifest JSONL path')
    ap.add_argument('--data-file', default=None, help='local SWE-bench Verified JSON; default: download and cache')
    args = ap.parse_args()

    rows = json.load(open(args.data_file)) if args.data_file else fetch_swebench_verified()
    rows_by_id = {r['instance_id']: r for r in rows}
    by_key = {}
    for runs_dir in args.runs:
        for rec in build_records(runs_dir, rows_by_id):
            by_key[(rec['instance_id'], rec['variant'])] = rec
    records = list(by_key.values())
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    summary = summarize(records)
    with open(os.path.splitext(args.out)[0] + '_summary.json', 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
