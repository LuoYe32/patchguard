import argparse
import json
import os
from collections import defaultdict


def load_jsonl(path):
    with open(path, encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def id_matches(predicted, expected):
    predicted, expected = str(predicted), str(expected)
    return predicted == expected or predicted.endswith('::' + expected) or predicted.endswith('.' + expected)


def finding_matches(finding, target):
    """Whether a predicted finding refers to the expected change."""
    if finding.get('class') != target['class'] or not id_matches(finding.get('id', ''), target['id']):
        return False
    if target['class'] == 'read-set' and target.get('attr'):
        attrs = finding.get('detail') or ''
        attrs = ','.join(attrs) if isinstance(attrs, list) else str(attrs)
        return target['attr'] in attrs
    return True


def score(examples, predictions):
    by_id = {p['example_id']: p.get('findings', []) for p in predictions}
    reference_frame = defaultdict(set)
    for ex in examples:
        if ex['family'] == 'reference' and ex['example_id'] in by_id:
            reference_frame[ex.get('instance_id')] |= {(f.get('class'), f.get('id')) for f in by_id[ex['example_id']]
                                                    if f.get('verdict') == 'frame'}
    buckets = defaultdict(lambda: {'n': 0, 'hit': 0})

    def record(key, hit):
        buckets[key]['n'] += 1
        buckets[key]['hit'] += bool(hit)

    for ex in examples:
        if ex['example_id'] not in by_id:
            continue
        findings = by_id[ex['example_id']]
        family, kind = ex['family'], ex['kind']
        frame = [f for f in findings if f.get('verdict') == 'frame']
        if family in ('twin', 'decoy'):
            frame = [f for f in frame if (f.get('class'), f.get('id')) not in reference_frame[ex.get('instance_id')]]
        target = ex.get('target')
        if family == 'positive':
            record(f'positive/{kind}', any(finding_matches(f, target) for f in frame))
        elif family == 'twin':
            record(f'twin/{kind}', any(finding_matches(f, target) for f in frame))
        elif family == 'decoy':
            site = ex['target']
            record(f'decoy/{kind}', any(id_matches(f.get('id', ''), site['id']) for f in frame))
        elif family == 'reference':
            record('reference', bool(frame))
    out = {}
    for key, b in sorted(buckets.items()):
        out[key] = {'n': b['n'], 'count': b['hit'], 'rate': round(b['hit'] / b['n'], 3) if b['n'] else None}
    fam = defaultdict(lambda: [0, 0])
    for key, b in buckets.items():
        f = key.split('/')[0]
        fam[f][0] += b['n']
        fam[f][1] += b['hit']
    out['summary'] = {f: {'n': n, 'count': c, 'rate': round(c / n, 3) if n else None} for f, (n, c) in sorted(fam.items())}
    out['summary_meaning'] = {'positive': 'recall (higher is better)', 'twin': 'false alarm rate (lower is better)',
                              'decoy': 'false alarm rate (lower is better)', 'reference': 'noise rate (lower is better)'}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--benchmark', required=True, help='directory with examples.jsonl')
    ap.add_argument('--predictions', required=True)
    ap.add_argument('--out', default=None)
    args = ap.parse_args()
    result = score(load_jsonl(os.path.join(args.benchmark, 'examples.jsonl')), load_jsonl(args.predictions))
    text = json.dumps(result, indent=1)
    if args.out:
        open(args.out, 'w').write(text)
    print(text)


if __name__ == '__main__':
    main()
