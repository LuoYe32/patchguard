"""Merge exported InvarBench directories (one per project) into a single benchmark directory."""
import argparse
import json
import os
import shutil


def merge(sources, out):
    os.makedirs(os.path.join(out, 'predictions'), exist_ok=True)
    files = ['examples.jsonl', 'issues.jsonl'] + [os.path.join('predictions', n) for n in
                                                   sorted({n for s in sources for n in os.listdir(os.path.join(s, 'predictions'))})]
    for rel in files:
        with open(os.path.join(out, rel), 'w', encoding='utf-8') as dst:
            for src in sources:
                path = os.path.join(src, rel)
                if os.path.exists(path):
                    with open(path, encoding='utf-8') as f:
                        dst.write(f.read())
    for src in sources:
        shutil.copytree(os.path.join(src, 'patches'), os.path.join(out, 'patches'), dirs_exist_ok=True)
    with open(os.path.join(out, 'examples.jsonl'), encoding='utf-8') as f:
        return sum(1 for _ in f)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--sources', nargs='+', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    print(f"{merge(args.sources, args.out)} examples written to {args.out}")


if __name__ == '__main__':
    main()
