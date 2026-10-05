import argparse
import glob
import json
import math
import os
from collections import defaultdict

from .agent_report import frame_items, load_json


def wilson(k, n, z=1.96):
    """95% Wilson score interval for k successes out of n, as (low, high) or None."""
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)


def rate(k, n):
    return {'k': k, 'n': n, 'rate': round(k / n, 3) if n else None, 'ci95': wilson(k, n)}


def findings_dir(variant, reference_dir, agents_dir):
    return reference_dir if variant == 'gold' else os.path.join(agents_dir, variant)


def build_cases(fulltest_dir, reference_dir, agents_dir):
    cases = []
    for path in sorted(glob.glob(os.path.join(fulltest_dir, '*', '*.json'))):
        variant = os.path.splitext(os.path.basename(path))[0]
        if variant == 'base':
            continue
        iid = os.path.basename(os.path.dirname(path))
        run = load_json(path)
        classified = load_json(os.path.join(findings_dir(variant, reference_dir, agents_dir), iid,
                                            'negative', 'classified_report.json'))
        if run.get('status') not in ('ok', 'crashed') or classified is None:
            continue
        findings = frame_items(classified)
        confirmed = run.get('confirmed_regressions', [])
        cases.append({'instance_id': iid, 'variant': variant,
                      'crashed': run['status'] == 'crashed',
                      'regressed': run['status'] == 'crashed' or bool(confirmed),
                      'confirmed_regressions': confirmed,
                      'flagged': bool(findings),
                      'finding_classes': sorted({f['class'] for f in findings}),
                      'findings': [{'class': f['class'], 'id': f['id']} for f in findings]})
    return cases


def summarize(cases):
    def table(rows):
        reg, clean = [c for c in rows if c['regressed']], [c for c in rows if not c['regressed']]
        return {'patches': len(rows),
                'regressed': len(reg),
                'flagged_given_regressed': rate(sum(c['flagged'] for c in reg), len(reg)),
                'flagged_given_clean': rate(sum(c['flagged'] for c in clean), len(clean)),
                'regressed_given_flagged': rate(sum(c['regressed'] for c in rows if c['flagged']),
                                                sum(c['flagged'] for c in rows)),
                'counts': {'regressed_flagged': sum(c['flagged'] for c in reg),
                           'regressed_unflagged': sum(not c['flagged'] for c in reg),
                           'clean_flagged': sum(c['flagged'] for c in clean),
                           'clean_unflagged': sum(not c['flagged'] for c in clean)}}
    by_variant = defaultdict(list)
    for c in cases:
        by_variant[c['variant']].append(c)
    return {'overall': table(cases), 'by_variant': {v: table(rows) for v, rows in sorted(by_variant.items())}}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fulltest', required=True, help='patchguard-fulltest output directory')
    ap.add_argument('--reference', required=True, help='batch directory of reference-patch runs (negative branch)')
    ap.add_argument('--agents', required=True, help='directory holding one batch directory per submission')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    cases = build_cases(args.fulltest, args.reference, args.agents)
    summary = summarize(cases)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, 'regressions_vs_findings.json'), 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=1)
    with open(os.path.join(args.out, 'cases.jsonl'), 'w', encoding='utf-8') as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + '\n')
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
