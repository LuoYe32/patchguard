import argparse
import json
import os


CLASS_LABELS = {'e_findings': 'E — архитектурная зависимость', 'readset_findings':
                'read-set — новое чтение атрибута', 'd_findings': 'D — сигнатура функции',
                'syntax_findings': 'syntax — файл больше не разбирается',
                'hygiene_findings': 'hygiene — состав патча',
                'protocol_findings': 'protocol — новый протокольный метод класса'}


def _finding_title(cls_key, item):
    if cls_key == 'e_findings':
        return f"`{item['pair']}`"
    if cls_key == 'readset_findings':
        return f"`{item['function'].split('::')[-1]}` читает новое: `{', '.join(item['added'])}`"
    if cls_key == 'd_findings':
        kinds = ', '.join(c['kind'] for c in item['changes'])
        broken = item.get('broken_total')
        suffix = f"; {broken} вызов(ов) в коде больше не подходят к новой сигнатуре" if broken else ''
        return f"`{item['function'].split('::')[-1]}` — {kinds}{suffix}"
    if cls_key == 'protocol_findings':
        return f"`{item['owner']}.{item['method']}`"
    if cls_key == 'hygiene_findings':
        return f"`{item['file']}` — {item['kind']}"
    if cls_key == 'syntax_findings':
        return f"`{item['file']}` — {item['error']}"
    return str(item)


def generate_report(classified_report, baseline_report=None, instance_label=None):
    frame, scope = [], []
    for cls_key in ('e_findings', 'readset_findings', 'd_findings', 'syntax_findings', 'hygiene_findings', 'protocol_findings'):
        for item in classified_report.get(cls_key, []):
            bucket = frame if item['verdict'] == 'frame' else scope
            bucket.append((cls_key, item))

    lines = []
    lines.append(f"# PatchGuard — отчёт{f' ({instance_label})' if instance_label else ''}")
    lines.append("")
    lines.append("## Сводка")
    lines.append("")
    lines.append(f"- **{len(frame)}** находок вне заявленного scope (`frame`) — требуют проверки")
    lines.append(f"- **{len(scope)}** изменений в рамках заявленного scope (`scope`) — информационно, ожидаемый эффект патча")
    if baseline_report is not None:
        r = baseline_report
        if r.get('ok') is True:
            status = f"✅ пройден ({r.get('total') or r.get('passed')} тестов)"
        elif r.get('ok') is False:
            status = f"❌ НЕ пройден ({r.get('runner')})"
        else:
            status = "⊘ не запускался"
        lines.append(f"- Существующий test suite (class C baseline): {status}")
        if frame and r.get('ok') is True:
            lines.append("  — **существующие тесты не ловят эти находки — это сигнал сверх теста**")
        elif frame and r.get('ok') is False:
            lines.append("  — часть находок, возможно, уже поймана и существующими тестами")
    lines.append("")

    if frame:
        lines.append("## ⚠️ Находки вне scope (frame) — требуют проверки")
        lines.append("")
        for i, (cls_key, item) in enumerate(frame, 1):
            lines.append(f"{i}. **[{CLASS_LABELS[cls_key]}]** {_finding_title(cls_key, item)}")
            lines.append(f"   {item['reason']}")
            lines.append("")

    if scope:
        lines.append("## Изменения в рамках заявленного scope (информационно)")
        lines.append("")
        for i, (cls_key, item) in enumerate(scope, 1):
            lines.append(f"{i}. **[{CLASS_LABELS[cls_key]}]** {_finding_title(cls_key, item)}")
            lines.append(f"   {item['reason']}")
            lines.append("")

    if not frame and not scope:
        lines.append("Находок нет — ни одна из проверенных инвариантных классов (E/read-set/D) не зафиксировала изменений.")
        lines.append("")

    return '\n'.join(lines)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--classified-report', required=True)
    ap.add_argument('--baseline-report', default=None)
    ap.add_argument('--instance-label', default=None)
    ap.add_argument('--out', default=None)
    args = ap.parse_args()

    classified = json.load(open(args.classified_report))
    baseline = json.load(open(args.baseline_report)) if args.baseline_report and os.path.exists(args.baseline_report) else None
    report = generate_report(classified, baseline, args.instance_label)
    if args.out:
        open(args.out, 'w').write(report)
        print(f"written to {args.out}")
    else:
        print(report)
