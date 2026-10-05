import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .batch_invarbench import load_instances

BUCKET = 'https://swe-bench-submissions.s3.amazonaws.com'
METADATA_URL = 'https://raw.githubusercontent.com/SWE-bench/experiments/main/evaluation/verified/{name}/metadata.yaml'
CACHE_DIR = os.path.join(os.path.expanduser('~'), '.cache', 'patchguard', 'agent_patches')
COLLECTION = 'bash-only'


def http_get(url, retries=3):
    """Response body, or None on 404."""
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise


def list_submissions(collection=COLLECTION):
    """Submission directory names in a bucket collection."""
    names, marker = [], ''
    while True:
        query = urllib.parse.urlencode({'prefix': f'{collection}/', 'delimiter': '/', 'marker': marker})
        body = http_get(f'{BUCKET}/?{query}').decode('utf-8')
        found = re.findall(r'<Prefix>' + re.escape(collection) + r'/([^<]+)/</Prefix>', body)
        names.extend(found)
        if '<IsTruncated>true</IsTruncated>' not in body or not found:
            return names
        marker = f'{collection}/{found[-1]}/'


def submission_info(name):
    """Display name and headline resolve rate from the submission's metadata, when available."""
    body = http_get(METADATA_URL.format(name=name))
    if body is None:
        return {}
    text = body.decode('utf-8')
    info = {}
    for key in ('name', 'resolved', 'agent', 'model_display'):
        m = re.search(rf'^\s*{key}:\s*(.+)$', text, re.M)
        if m:
            info[key] = m.group(1).strip()
    return info


def fetch_instance(submission, instance_id, collection=COLLECTION, cache_dir=CACHE_DIR):
    """{'patch', 'resolved', 'applied'} for one submission/instance, or None if the submission has no entry."""
    local = os.path.join(cache_dir, submission, instance_id)
    cached = os.path.join(local, 'record.json')
    if os.path.exists(cached):
        return json.load(open(cached))
    base = f'{BUCKET}/{collection}/{submission}/logs/{instance_id}'
    patch, report = http_get(f'{base}/patch.diff'), http_get(f'{base}/report.json')
    if patch is None or report is None:
        return None
    report = json.loads(report)
    report = report.get(instance_id, report) if isinstance(report.get(instance_id), dict) else report
    record = {'patch': patch.decode('utf-8', errors='replace'),
              'resolved': bool(report.get('resolved')),
              'applied': bool(report.get('patch_successfully_applied'))}
    os.makedirs(local, exist_ok=True)
    json.dump(record, open(cached, 'w'))
    return record


def collect(submission, instances, workers=8, collection=COLLECTION):
    """One record per instance that the submission attempted with a non-empty patch."""
    def one(inst):
        rec = fetch_instance(submission, inst['instance_id'], collection)
        if rec is None or not rec['patch'].strip():
            return None
        return {'submission': submission, 'instance_id': inst['instance_id'], 'repo': inst['repo'], **rec}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [r for r in pool.map(one, instances) if r]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--list', action='store_true', help='list submissions with their headline resolve rate and exit')
    ap.add_argument('--submission', action='append', help='submission directory name (repeatable)')
    ap.add_argument('--collection', default=COLLECTION)
    ap.add_argument('--repos', default=None, help='comma-separated repo filter')
    ap.add_argument('--limit', type=int, default=None, help='first N instances of the selection')
    ap.add_argument('--ids', default=None, help='comma-separated instance ids')
    ap.add_argument('--data-file', default=None)
    ap.add_argument('--workers', type=int, default=8)
    ap.add_argument('--out', help='JSONL with one patch per line')
    args = ap.parse_args()

    if args.list:
        for name in list_submissions(args.collection):
            info = submission_info(name)
            print(f"{name}\t{info.get('resolved', '?')}%\t{info.get('model_display') or info.get('name', '')}")
        return
    if not args.submission or not args.out:
        ap.error('--submission and --out are required unless --list is given')

    repos = set(args.repos.split(',')) if args.repos else None
    ids = set(args.ids.split(',')) if args.ids else None
    instances = load_instances(limit=None if ids else args.limit, repos=repos, data_file=args.data_file, ids=ids)
    records = []
    for submission in args.submission:
        got = collect(submission, instances, args.workers, args.collection)
        print(f"{submission}: {len(got)}/{len(instances)} patches, "
              f"{sum(r['resolved'] for r in got)} resolved, {sum(not r['applied'] for r in got)} not applied")
        records.extend(got)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')


if __name__ == '__main__':
    main()
