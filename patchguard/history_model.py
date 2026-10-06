"""Does a PatchGuard flag add predictive information about later regressions beyond the size of the
change? Logistic regression (no external dependencies) with repeated cross-validated AUC and
likelihood-ratio tests on the output of patchguard-history."""
import argparse
import json
import math
import random


def solve(matrix, vector):
    """Solve matrix x = vector by Gaussian elimination with partial pivoting."""
    n = len(vector)
    a = [row[:] + [vector[i]] for i, row in enumerate(matrix)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(a[r][col]))
        a[col], a[pivot] = a[pivot], a[col]
        if abs(a[col][col]) < 1e-12:
            a[col][col] = 1e-12
        for r in range(col + 1, n):
            f = a[r][col] / a[col][col]
            for c in range(col, n + 1):
                a[r][c] -= f * a[col][c]
    x = [0.0] * n
    for r in range(n - 1, -1, -1):
        x[r] = (a[r][n] - sum(a[r][c] * x[c] for c in range(r + 1, n))) / a[r][r]
    return x


def sigmoid(z):
    return 1 / (1 + math.exp(-max(-35.0, min(35.0, z))))


def fit(X, y, ridge=1e-3, iterations=50):
    """Logistic regression by Newton's method; X rows include the intercept column."""
    k = len(X[0])
    beta = [0.0] * k
    for _ in range(iterations):
        grad = [0.0] * k
        hess = [[0.0] * k for _ in range(k)]
        for row, yi in zip(X, y):
            p = sigmoid(sum(b * v for b, v in zip(beta, row)))
            w = p * (1 - p)
            for i in range(k):
                grad[i] += (yi - p) * row[i]
                for j in range(k):
                    hess[i][j] += w * row[i] * row[j]
        for i in range(k):
            grad[i] -= ridge * beta[i]
            hess[i][i] += ridge
        step = solve(hess, grad)
        beta = [b + s for b, s in zip(beta, step)]
        if max(abs(s) for s in step) < 1e-8:
            break
    return beta


def log_likelihood(beta, X, y):
    total = 0.0
    for row, yi in zip(X, y):
        p = min(max(sigmoid(sum(b * v for b, v in zip(beta, row))), 1e-12), 1 - 1e-12)
        total += yi * math.log(p) + (1 - yi) * math.log(1 - p)
    return total


def auc(scores, y):
    pos = [s for s, yi in zip(scores, y) if yi]
    neg = [s for s, yi in zip(scores, y) if not yi]
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def chi2_sf(x, df):
    """Survival function of the chi-square distribution (regularized upper incomplete gamma)."""
    a, x = df / 2, x / 2
    if x <= 0:
        return 1.0
    term = total = 1 / a
    for n in range(1, 500):
        term *= x / (a + n)
        total += term
        if term < 1e-14 * total:
            break
    lower = total * math.exp(-x + a * math.log(x) - math.lgamma(a))
    return max(0.0, 1 - lower)


def features(row):
    frame = row.get('frame', [])
    count = lambda c: sum(1 for f in frame if f['class'] == c)
    return {'log_lines': math.log1p(row['lines']), 'log_files': math.log1p(row['files']),
            'any_frame': float(bool(frame)), 'read_set': float(count('read-set') > 0), 'd': float(count('D') > 0),
            'e': float(count('E') > 0), 'n_frame': math.log1p(len(frame)), 'hygiene': float(bool(row.get('hygiene')))}


MODELS = {
    'size only': ['log_lines', 'log_files'],
    'size + any flag': ['log_lines', 'log_files', 'any_frame'],
    'size + classes': ['log_lines', 'log_files', 'read_set', 'd', 'e'],
    'size + classes + count': ['log_lines', 'log_files', 'read_set', 'd', 'e', 'n_frame'],
    'flags only (no size)': ['any_frame'],
}


def design(rows, names):
    return [[1.0] + [features(r)[n] for n in names] for r in rows]


def cross_validated_auc(rows, names, repeats=5, folds=5, seed=0):
    rnd = random.Random(seed)
    scores = []
    for _ in range(repeats):
        idx = list(range(len(rows)))
        rnd.shuffle(idx)
        parts = [idx[i::folds] for i in range(folds)]
        predicted = [0.0] * len(rows)
        for fold in parts:
            held = set(fold)
            train = [rows[i] for i in idx if i not in held]
            beta = fit(design(train, names), [int(r['induced']) for r in train])
            for i in fold:
                predicted[i] = sum(b * v for b, v in zip(beta, design([rows[i]], names)[0]))
        scores.append(auc(predicted, [int(r['induced']) for r in rows]))
    mean = sum(scores) / len(scores)
    return round(mean, 3), round(math.sqrt(sum((s - mean) ** 2 for s in scores) / len(scores)), 3)


def run(rows):
    y = [int(r['induced']) for r in rows]
    out = {'commits': len(rows), 'induced': sum(y), 'models': {}}
    fits = {}
    for name, names in MODELS.items():
        X = design(rows, names)
        beta = fit(X, y)
        fits[name] = (log_likelihood(beta, X, y), len(names))
        out['models'][name] = {
            'cv_auc': cross_validated_auc(rows, names), 'features': names,
            'odds_ratios': {n: round(math.exp(b), 2) for n, b in zip(['intercept'] + names, beta) if n != 'intercept'}}
    base_ll, base_k = fits['size only']
    out['likelihood_ratio_vs_size_only'] = {}
    for name in ('size + any flag', 'size + classes', 'size + classes + count'):
        ll, k = fits[name]
        stat = 2 * (ll - base_ll)
        out['likelihood_ratio_vs_size_only'][name] = {'chi2': round(stat, 2), 'df': k - base_k,
                                                      'p': float(f"{chi2_sf(stat, k - base_k):.3g}")}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--data', required=True, help='JSONL from patchguard-history run')
    ap.add_argument('--out', default=None)
    args = ap.parse_args()
    rows = [r for r in map(json.loads, open(args.data, encoding='utf-8')) if 'error' not in r]
    result = run(rows)
    text = json.dumps(result, indent=1)
    if args.out:
        open(args.out, 'w').write(text)
    print(text)


if __name__ == '__main__':
    main()
