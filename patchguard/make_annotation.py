import argparse
import html
import json
import os
import random
import re

from .batch_invarbench import fetch_swebench_verified

MAX_FINDINGS = 8
MAX_DIFF_LINES = 140


def module_path(module):
    return module.replace('.', '/') + '.py'


def file_diff(patch, wanted):
    """Diff of one file from a multi-file patch."""
    chunks = re.split(r'(?m)^(?=diff --git )', patch)
    return next((c for c in chunks if c.startswith('diff --git') and (f' b/{wanted}' in c.splitlines()[0])), '')


def describe(f):
    cls, ident = f['class'], f['id']
    detail = f.get('detail')
    if cls == 'E':
        return {'class': 'new package dependency', 'where': ident, 'what': 'the patch adds an import from one package to another'}
    if cls == 'read-set':
        added = detail if isinstance(detail, list) else (detail or {}).get('added', [])
        return {'class': 'new attribute read', 'where': ident.split('::')[-1], 'what': 'now reads: ' + ', '.join(added[:6])}
    if cls == 'D':
        kinds = detail if isinstance(detail, list) else [c['kind'] for c in (detail or {}).get('changes', [])]
        return {'class': 'signature change', 'where': ident.split('::')[-1], 'what': ', '.join(kinds)}
    return {'class': cls, 'where': ident, 'what': str(detail)[:120]}


def case_diff(patch, findings):
    """Diff shown for a case: the files the findings point to, or the first files of the patch."""
    files = []
    for f in findings:
        if f['class'] in ('read-set', 'D') and '::' in f['id']:
            files.append(module_path(f['id'].split('::')[0]))
        elif f['class'] == 'E':
            files.extend(re.findall(r'(?m)^diff --git a/(\S+\.py) ', patch)[:2])
    parts = [file_diff(patch, p) for p in dict.fromkeys(files)]
    text = ''.join(p for p in parts if p) or '\n'.join(patch.splitlines()[:MAX_DIFF_LINES])
    lines = text.splitlines()
    names = re.findall(r'(?m)^diff --git a/(\S+) ', patch)
    shown = '\n'.join(lines[:MAX_DIFF_LINES]) + (f'\n... ({len(lines) - MAX_DIFF_LINES} more lines)' if len(lines) > MAX_DIFF_LINES else '')
    return shown, names


def build(args):
    rows = {r['instance_id']: r for r in fetch_swebench_verified()}
    rng = random.Random(args.seed)
    cases, key = [], {}
    benchmark = os.path.join(args.benchmark)
    examples = {e['example_id']: e for e in map(json.loads, open(os.path.join(benchmark, 'examples.jsonl')))}
    predictions = {p['example_id']: p['findings'] for p in map(json.loads, open(os.path.join(benchmark, 'predictions', 'patchguard.jsonl')))}
    agent_patches = {}
    for line in open(args.agent_patches, encoding='utf-8'):
        r = json.loads(line)
        agent_patches[(r['submission'], r['instance_id'])] = r['patch']

    def add(kind, origin, iid, patch, findings):
        shown, names = case_diff(patch, findings)
        cid = f'c{len(cases) + 1:03d}'
        cases.append({'id': cid, 'kind': kind, 'issue': rows[iid]['problem_statement'][:1400], 'files': names[:12],
                      'diff': shown, 'findings': [describe(f) for f in findings[:MAX_FINDINGS]],
                      'more': max(0, len(findings) - MAX_FINDINGS)})
        key[cid] = {'origin': origin, 'instance_id': iid, 'findings': findings[:MAX_FINDINGS]}

    for eid, ex in sorted(examples.items()):
        if ex['family'] == 'reference':
            fs = [f for f in predictions.get(eid, []) if f['verdict'] == 'frame' and f['class'] in ('E', 'read-set', 'D')]
            if fs:
                add('flagged', 'reference', ex['instance_id'], rows[ex['instance_id']]['patch'], fs)
    findings = [json.loads(l) for l in open(args.agent_findings)]
    by_patch = {}
    for r in findings:
        if r['class'] in ('E', 'read-set', 'D'):
            by_patch.setdefault((r['submission'], r['instance_id']), []).append(r)
    chosen = [k for k in by_patch if 'gpt-4o' not in k[0]] + rng.sample([k for k in by_patch if 'gpt-4o' in k[0]], min(8, sum('gpt-4o' in k[0] for k in by_patch)))
    for sub, iid in chosen:
        add('flagged', f'agent:{sub}', iid, agent_patches[(sub, iid)], by_patch[(sub, iid)])
    flagged_keys = {('gold', e['instance_id']) for e in examples.values() if e['family'] == 'reference'
                    and any(f['verdict'] == 'frame' for f in predictions.get(e['example_id'], []))} | set(by_patch)
    controls = [('gold', e['instance_id']) for e in examples.values() if e['family'] == 'reference'
                and ('gold', e['instance_id']) not in flagged_keys and e['repo'] == 'django/django']
    for sub, iid in rng.sample(controls, min(8, len(controls))):
        add('control', 'reference', iid, rows[iid]['patch'], [])
    agent_controls = [k for k in agent_patches if k not in by_patch and 'gpt-4o' not in k[0] and k[1].startswith('django')]
    for sub, iid in rng.sample(agent_controls, min(8, len(agent_controls))):
        add('control', f'agent:{sub}', iid, agent_patches[(sub, iid)], [])
    order = list(range(len(cases)))
    rng.shuffle(order)
    cases = [cases[i] for i in order]
    return cases, key


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Patch review</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#fff;--fg:#1d2430;--mut:#667085;--line:#e4e7ec;--card:#f8f9fb;--add:#e6f6ea;--del:#fdecec;--acc:#2f5bea}
@media (prefers-color-scheme:dark){:root{--bg:#14171d;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2a303b;--card:#1b1f27;--add:#173424;--del:#3a1d1d;--acc:#7da2ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:8px 0}.mut{color:var(--mut)}
.bar{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 16px;z-index:5;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.card{border:1px solid var(--line);background:var(--card);border-radius:10px;padding:14px;margin:16px 0}
.issue{white-space:pre-wrap;max-height:160px;overflow:auto;border-left:3px solid var(--line);padding-left:10px}
pre.diff{overflow:auto;max-height:420px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px;font:12.5px/1.45 ui-monospace,monospace}
.a{background:var(--add)}.d{background:var(--del)}.h{color:var(--acc)}
.f{border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:8px 0;background:var(--bg)}
label{margin-right:12px;white-space:nowrap}
textarea{width:100%;box-sizing:border-box;min-height:44px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:14px;cursor:pointer}
.done{outline:2px solid #2a9d5c}
</style></head><body>
<div class="bar"><b>Patch review</b><span id="prog" class="mut"></span><button onclick="exportAnswers()">Download my answers</button>
<span class="mut">Answers are saved in this browser automatically.</span></div>
<main>
<h1>How to answer</h1>
<p class="mut">For every case you see an issue, the patch written for it, and (for most cases) a list of changes a tool pointed at.
Judge each change on its own, as a maintainer reviewing a pull request. You do not need to run anything. If you cannot tell, say so.</p>
<ul class="mut"><li><b>Needed for the fix</b>: the issue cannot be resolved properly without this change.</li>
<li><b>Unneeded but harmless</b>: not required, but you would accept it.</li>
<li><b>Unneeded and risky</b>: unrelated to the issue, or it could break other code, or you would ask for it to be removed or discussed.</li>
<li><b>Cannot tell</b>: not enough information.</li></ul>
<div id="cases"></div></main>
<script>
const CASES = __DATA__;
const KEY = 'invarbench-annotation-v1';
let answers = {}; try { answers = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch (e) {}
const esc = s => s.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const colorize = d => d.split('\\n').map(l => '<div class="' + (l.startsWith('+') && !l.startsWith('+++') ? 'a' : l.startsWith('-') && !l.startsWith('---') ? 'd' : l.startsWith('@@') ? 'h' : '') + '">' + esc(l || ' ') + '</div>').join('');
const OPTS = [['needed','Needed for the fix'],['harmless','Unneeded but harmless'],['risky','Unneeded and risky'],['unsure','Cannot tell']];
function save() { try { localStorage.setItem(KEY, JSON.stringify(answers)); } catch (e) {} progress(); }
function set(cid, part, val) { (answers[cid] = answers[cid] || {})[part] = val; save(); mark(cid); }
function mark(cid) { const c = CASES.find(x => x.id === cid); const a = answers[cid] || {};
  const need = c.findings.length ? c.findings.map((_, i) => 'f' + i) : ['control'];
  document.getElementById(cid).classList.toggle('done', need.every(k => a[k])); }
function progress() { const done = CASES.filter(c => { const a = answers[c.id] || {}; const need = c.findings.length ? c.findings.map((_, i) => 'f' + i) : ['control']; return need.every(k => a[k]); }).length;
  document.getElementById('prog').textContent = done + ' / ' + CASES.length + ' cases answered'; }
function render() {
  document.getElementById('cases').innerHTML = CASES.map((c, n) => {
    const a = answers[c.id] || {};
    const fs = c.findings.map((f, i) => '<div class="f"><div><b>' + esc(f.class) + '</b> in <code>' + esc(f.where) + '</code> <span class="mut">(' + esc(f.what) + ')</span></div><div>' +
      OPTS.map(o => '<label><input type="radio" name="' + c.id + 'f' + i + '" ' + (a['f' + i] === o[0] ? 'checked' : '') + ' onchange="set(\\'' + c.id + '\\',\\'f' + i + '\\',\\'' + o[0] + '\\')"> ' + o[1] + '</label>').join('') + '</div></div>').join('');
    const ctl = c.findings.length ? '' : '<div class="f"><div>Does this patch contain changes that are not needed for the issue?</div><div>' +
      [['none','No'],['minor','Minor ones'],['major','Yes, significant'],['unsure','Cannot tell']].map(o => '<label><input type="radio" name="' + c.id + 'ctl" ' + (a.control === o[0] ? 'checked' : '') + ' onchange="set(\\'' + c.id + '\\',\\'control\\',\\'' + o[0] + '\\')"> ' + o[1] + '</label>').join('') + '</div></div>';
    return '<section class="card" id="' + c.id + '"><div class="mut">Case ' + (n + 1) + ' of ' + CASES.length + '</div><h3>Issue</h3><div class="issue">' + esc(c.issue) + '</div>' +
      '<h3>Patch</h3><div class="mut">Files: ' + esc(c.files.join(', ')) + '</div><pre class="diff">' + colorize(c.diff) + '</pre>' +
      (c.findings.length ? '<h3>Changes to judge</h3>' + fs + (c.more ? '<div class="mut">' + c.more + ' more similar changes not listed.</div>' : '') : '<h3>Your judgement</h3>' + ctl) +
      '<textarea placeholder="Optional comment" oninput="set(\\'' + c.id + '\\',\\'comment\\',this.value)">' + esc(a.comment || '') + '</textarea></section>'; }).join('');
  CASES.forEach(c => mark(c.id)); progress(); }
function exportAnswers() { const blob = new Blob([JSON.stringify({version: 1, answers}, null, 1)], {type: 'application/json'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'annotation_answers.json'; a.click(); }
render();
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--benchmark', required=True)
    ap.add_argument('--agent-patches', required=True)
    ap.add_argument('--agent-findings', required=True)
    ap.add_argument('--out', required=True, help='output directory')
    ap.add_argument('--seed', type=int, default=0)
    args = ap.parse_args()
    cases, key = build(args)
    os.makedirs(args.out, exist_ok=True)
    data = json.dumps(cases, ensure_ascii=False).replace('</', '<\\/')
    open(os.path.join(args.out, 'annotate.html'), 'w', encoding='utf-8').write(PAGE.replace('__DATA__', data))
    json.dump(key, open(os.path.join(args.out, 'key.json'), 'w'), indent=1)
    print(f"{len(cases)} cases ({sum(c['kind'] == 'flagged' for c in cases)} flagged, "
          f"{sum(c['kind'] == 'control' for c in cases)} controls); findings to judge: {sum(len(c['findings']) for c in cases)}")


if __name__ == '__main__':
    main()
